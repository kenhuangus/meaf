"""Ed25519 evidence signing and L4 evidence validity checks."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from meaf.validator import Finding


def canonical_payload(evidence: dict[str, Any]) -> bytes:
    """UTF-8 bytes of evidence JSON with signature field removed."""
    unsigned = {key: value for key, value in evidence.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_keyring(path: Path) -> dict[str, bytes]:
    """Load collector-id -> raw Ed25519 public key bytes from JSON keyring."""
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    keyring: dict[str, bytes] = {}
    for collector_id, encoded in raw.items():
        keyring[collector_id] = base64.b64decode(encoded)
    return keyring


def sign_evidence(
    evidence: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Return evidence with detached Ed25519 signature attached."""
    signed = dict(evidence)
    collector = evidence.get("collector", "")
    kid = key_id if key_id is not None else collector
    signature_bytes = private_key.sign(canonical_payload(evidence))
    signed["signature"] = {
        "algorithm": "ed25519",
        "key-id": kid,
        "value": base64.b64encode(signature_bytes).decode("ascii"),
    }
    return signed


def verify_evidence(evidence: dict[str, Any], keyring: dict[str, bytes]) -> bool:
    """Verify evidence signature against the keyring; False if missing/invalid."""
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
        public_key.verify(base64.b64decode(value), canonical_payload(evidence))
    except Exception:
        return False
    return True


def component_digests(package: dict[str, Any]) -> set[str]:
    return {component["digest"] for component in package.get("components", [])}


def validate_l4_evidence(
    package: dict[str, Any],
    keyring: dict[str, bytes] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    digests = component_digests(package)

    if keyring is None:
        findings.append(
            Finding(
                level=4,
                severity="warning",
                object_id=None,
                message="signature verification was not performed",
            )
        )
    else:
        for evidence in package.get("evidence", []):
            evidence_id = evidence.get("id", "(unknown)")
            if "signature" not in evidence:
                findings.append(
                    Finding(
                        level=4,
                        severity="error",
                        object_id=evidence_id,
                        message="evidence is unsigned",
                    )
                )
            elif not verify_evidence(evidence, keyring):
                findings.append(
                    Finding(
                        level=4,
                        severity="error",
                        object_id=evidence_id,
                        message="evidence signature verification failed",
                    )
                )

    for evidence in package.get("evidence", []):
        evidence_id = evidence.get("id", "(unknown)")
        subject_digests = evidence.get("subject-digests", [])
        if not subject_digests:
            findings.append(
                Finding(
                    level=4,
                    severity="warning",
                    object_id=evidence_id,
                    message="evidence has empty subject-digests",
                )
            )
            continue
        for digest in subject_digests:
            if digest not in digests:
                findings.append(
                    Finding(
                        level=4,
                        severity="error",
                        object_id=evidence_id,
                        message=(
                            f"evidence bound to an artifact not in the package "
                            f"inventory: {digest}"
                        ),
                    )
                )

    return findings


def public_key_to_keyring_entry(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def private_key_from_pem(pem_bytes: bytes) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected Ed25519 private key")
    return key


def private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    )
