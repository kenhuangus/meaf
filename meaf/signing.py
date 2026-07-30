"""Ed25519 evidence signing and level 4 evidence validity.

Level 4 asks whether an observation may be believed at all: is it attributable,
is it about the artifact that is actually deployed, was it collected by a method
the organisation approved, is it still inside its validity window, and is it
honestly classified as a deterministic observation or a probabilistic inference.

The signature check binds a key to a *collector*, not merely to a package. A
keyring holder signing as some other collector would let one compromised tool
manufacture evidence attributed to every other tool, so ``key-id`` must equal
the ``collector`` field it signs for.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from meaf.attest import (
    STATUS_DRIFT,
    STATUS_MISSING_FILE,
    STATUS_OUTSIDE_ROOT,
    check_attestation,
)
from meaf.model import (
    SEVERITY_ERROR,
    SEVERITY_WARNING,
    Finding,
    TimestampError,
    component_digests,
    evidence_is_fresh,
    objects,
)
from meaf.policy import Policy, default_policy


def canonical_payload(evidence: dict[str, Any]) -> bytes:
    """UTF-8 bytes of the evidence JSON with the signature field removed.

    Sorted keys and no whitespace, so two producers serialising the same
    evidence object produce the same bytes to sign.
    """
    unsigned = {key: value for key, value in evidence.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_keyring(path: Path) -> dict[str, bytes]:
    """Load collector-id to raw Ed25519 public key bytes from a JSON keyring."""
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return {
        collector_id: base64.b64decode(encoded)
        for collector_id, encoded in raw.items()
    }


def sign_evidence(
    evidence: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Return a copy of ``evidence`` with a detached Ed25519 signature attached."""
    signed = dict(evidence)
    kid = key_id if key_id is not None else evidence.get("collector", "")
    signature_bytes = private_key.sign(canonical_payload(evidence))
    signed["signature"] = {
        "algorithm": "ed25519",
        "key-id": kid,
        "value": base64.b64encode(signature_bytes).decode("ascii"),
    }
    return signed


def verify_evidence(evidence: dict[str, Any], keyring: dict[str, bytes]) -> bool:
    """Verify an evidence signature against the keyring.

    Returns False for a missing, malformed, unknown-key or invalid signature.
    Programming errors are not swallowed: only the exceptions a hostile or
    corrupt signature can actually raise are caught.
    """
    signature = evidence.get("signature")
    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    key_id = signature.get("key-id")
    value = signature.get("value")
    if not isinstance(key_id, str) or not isinstance(value, str):
        return False
    public_key_bytes = keyring.get(key_id)
    if public_key_bytes is None:
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(base64.b64decode(value, validate=True), canonical_payload(evidence))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False
    return True


def _error(object_id: str | None, message: str) -> Finding:
    return Finding(level=4, severity=SEVERITY_ERROR, object_id=object_id, message=message)


def _warning(object_id: str | None, message: str) -> Finding:
    return Finding(level=4, severity=SEVERITY_WARNING, object_id=object_id, message=message)


def _check_signatures(
    package: Any,
    keyring: dict[str, bytes] | None,
) -> list[Finding]:
    if keyring is None:
        return [
            _warning(
                None,
                "signature verification was not performed; no keyring was supplied",
            )
        ]

    findings: list[Finding] = []
    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id", "(unknown)"))
        signature = evidence.get("signature")
        if signature is None:
            findings.append(_error(evidence_id, "evidence is unsigned"))
            continue
        key_id = signature.get("key-id") if isinstance(signature, dict) else None
        collector = evidence.get("collector")
        if key_id != collector:
            findings.append(
                _error(
                    evidence_id,
                    f"signature key-id {key_id!r} does not match collector {collector!r}; "
                    "evidence must be signed by the collector it is attributed to",
                )
            )
            continue
        if not verify_evidence(evidence, keyring):
            findings.append(_error(evidence_id, "evidence signature verification failed"))
    return findings


def _check_artifact_binding(package: Any) -> list[Finding]:
    findings: list[Finding] = []
    digests = component_digests(package)
    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id", "(unknown)"))
        subject_digests = evidence.get("subject-digests")
        if not subject_digests:
            findings.append(
                _warning(
                    evidence_id,
                    "evidence declares no subject-digests, so it cannot be shown to be "
                    "about any deployed artifact",
                )
            )
            continue
        for digest in subject_digests:
            if digest not in digests:
                findings.append(
                    _error(
                        evidence_id,
                        f"evidence is bound to an artifact that is not in the package "
                        f"inventory: {digest}",
                    )
                )
    return findings


def _check_methods(package: Any, policy: Policy) -> list[Finding]:
    if not policy.method_policy_in_force:
        return [
            _warning(
                None,
                f"policy {policy.name} approves no specific evidence-collection methods, "
                "so no method check was performed",
            )
        ]
    approved = policy.approved_evidence_methods
    return [
        _error(
            str(evidence.get("id", "(unknown)")),
            f"evidence method {evidence.get('method')!r} is not approved by policy {policy.name}",
        )
        for evidence in objects(package, "evidence")
        if evidence.get("method") not in approved
    ]


def _check_validity_window(package: Any, now: Any) -> list[Finding]:
    """A.5 level 4: evidence is within its validity window.

    Reported as a warning here and turned into a gate consequence at level 5 by
    the contract state, so that ``validate`` output distinguishes "this evidence
    has aged out" from "the claim it supports has therefore failed".
    """
    if now is None:
        return []
    findings: list[Finding] = []
    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id", "(unknown)"))
        if evidence.get("invalidated-at") is not None:
            findings.append(
                _warning(
                    evidence_id,
                    f"evidence was explicitly invalidated at {evidence.get('invalidated-at')}",
                )
            )
            continue
        try:
            fresh = evidence_is_fresh(
                evidence.get("collected-at"), evidence.get("max-age"), None, now
            )
        except TimestampError:
            continue
        if not fresh:
            findings.append(
                _warning(evidence_id, "evidence is outside its declared validity window")
            )
    return findings


def _check_attestation(package: Any, root: Path | None) -> list[Finding]:
    if root is None:
        return [
            _warning(
                None,
                "artifact attestation was not performed; no attestation root was supplied",
            )
        ]

    findings: list[Finding] = []
    for record in check_attestation(package, root):
        component_id = record["component-id"]
        status = record["status"]
        if status == STATUS_DRIFT:
            findings.append(
                _error(
                    component_id,
                    f"artifact digest drift: on-disk artifact hashes to "
                    f"{record['computed-digest']}, package records "
                    f"{record['recorded-digest']}",
                )
            )
        elif status == STATUS_MISSING_FILE:
            # Declaring an artifact-path is a claim that the binding is
            # checkable. Deleting the file must not be a cheaper way to pass
            # than keeping it unchanged.
            findings.append(
                _error(
                    component_id,
                    f"artifact file {record['artifact-path']!r} is missing, so the "
                    "declared digest binding cannot be verified",
                )
            )
        elif status == STATUS_OUTSIDE_ROOT:
            findings.append(
                _error(
                    component_id,
                    f"artifact-path {record['artifact-path']!r} resolves outside the "
                    "attestation root and was refused",
                )
            )
    return findings


def validate_l4_evidence(
    package: Any,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
    now: Any = None,
) -> list[Finding]:
    """Conformance level 4: evidence validity."""
    if policy is None:
        policy = default_policy()
    findings: list[Finding] = []
    findings.extend(_check_signatures(package, keyring))
    findings.extend(_check_artifact_binding(package))
    findings.extend(_check_methods(package, policy))
    findings.extend(_check_validity_window(package, now))
    findings.extend(_check_attestation(package, root))
    return findings


def public_key_to_keyring_entry(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def private_key_from_pem(pem_bytes: bytes) -> Ed25519PrivateKey:
    key = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


__all__ = [
    "canonical_payload",
    "load_keyring",
    "private_key_from_pem",
    "private_key_to_pem",
    "public_key_to_keyring_entry",
    "sign_evidence",
    "validate_l4_evidence",
    "verify_evidence",
]
