"""Level 4 decides whether an observation may be believed at all.

Everything above level 4 reasons about what the evidence says. Level 4 is the
only place that asks whether the evidence is evidence: attributable to a named
collector, about the artifact that is actually deployed, collected by a method
the organisation approved. A defect here does not produce a wrong answer, it
produces a confident answer built on an unattributable observation, which is the
failure mode the whole framework exists to prevent.

The signing tests therefore pin two things that are easy to get subtly wrong and
impossible to notice afterwards: the exact bytes that get signed, and the rule
that a key may only sign as the collector it belongs to.
"""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from meaf.model import SEVERITY_ERROR, SEVERITY_WARNING, Finding
from meaf.signing import (
    canonical_payload,
    public_key_to_keyring_entry,
    sign_evidence,
    validate_l4_evidence,
    verify_evidence,
)
from tests.conftest import FROZEN_NOW

#: A deliberately small evidence object. Small enough that the canonical bytes
#: can be written out in full below and read by a human implementing a second
#: producer, which is the only way two implementations can agree on a signature.
SMALL_EVIDENCE: dict[str, Any] = {
    "id": "ev-small",
    "collector": "tool:demo:1.0.0",
    "collected-at": "2026-07-15T00:00:00Z",
    "result": "pass",
    "signature": {
        "algorithm": "ed25519",
        "key-id": "tool:demo:1.0.0",
        "value": "AAAA",
    },
}

#: Sorted keys, no whitespace, signature omitted.
SMALL_EVIDENCE_PAYLOAD = (
    b'{"collected-at":"2026-07-15T00:00:00Z","collector":"tool:demo:1.0.0",'
    b'"id":"ev-small","result":"pass"}'
)


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def messages(findings: list[Finding], fragment: str) -> list[Finding]:
    """Findings whose message contains ``fragment``, for targeted assertions."""
    return [finding for finding in findings if fragment in finding.message]


@pytest.fixture
def fresh_key() -> Ed25519PrivateKey:
    """A key generated per test, so no test can pass on a shipped signature."""
    return Ed25519PrivateKey.generate()


# --------------------------------------------------------------------------
# canonical_payload
# --------------------------------------------------------------------------


def test_the_canonical_payload_excludes_the_signature_member():
    # A signature over bytes that include the signature cannot be computed, and
    # a producer that left it in would sign a different message every time.
    assert b"signature" not in canonical_payload(SMALL_EVIDENCE)
    assert b"ed25519" not in canonical_payload(SMALL_EVIDENCE)


def test_the_canonical_payload_is_the_exact_documented_byte_string():
    assert canonical_payload(SMALL_EVIDENCE) == SMALL_EVIDENCE_PAYLOAD


def test_the_canonical_payload_does_not_depend_on_member_insertion_order():
    """Two producers serialising the same evidence must sign the same bytes.

    A.5 level 6 requires that "a second conforming evaluator using the same
    package, external evidence, and policy bundle reaches the same deterministic
    gate result". If key order changed the payload, whether a signature verified
    would depend on which JSON library wrote the file.
    """
    reordered = {key: SMALL_EVIDENCE[key] for key in reversed(list(SMALL_EVIDENCE))}
    assert list(reordered) != list(SMALL_EVIDENCE)
    assert canonical_payload(reordered) == canonical_payload(SMALL_EVIDENCE)


def test_the_canonical_payload_of_an_unsigned_object_matches_its_signed_form():
    unsigned = {key: value for key, value in SMALL_EVIDENCE.items() if key != "signature"}
    assert canonical_payload(unsigned) == canonical_payload(SMALL_EVIDENCE)


# --------------------------------------------------------------------------
# sign / verify
# --------------------------------------------------------------------------


def test_signing_then_verifying_with_the_matching_key_succeeds(fresh_key):
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is True


def test_signing_defaults_the_key_id_to_the_collector(fresh_key):
    # The default has to be the collector, because that is the binding level 4
    # then enforces; defaulting to anything else would make the common path the
    # non-conforming one.
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    assert signed["signature"]["key-id"] == SMALL_EVIDENCE["collector"]
    assert signed["signature"]["algorithm"] == "ed25519"


def test_signing_does_not_mutate_the_evidence_it_was_given(fresh_key):
    before = copy.deepcopy(SMALL_EVIDENCE)
    sign_evidence(SMALL_EVIDENCE, fresh_key)
    assert SMALL_EVIDENCE == before


@pytest.mark.parametrize("member", ["id", "collector", "collected-at", "result"])
def test_tampering_with_any_signed_member_breaks_verification(fresh_key, member):
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is True

    tampered = dict(signed)
    tampered[member] = "tampered"
    assert verify_evidence(tampered, keyring) is False


def test_adding_a_member_after_signing_breaks_verification(fresh_key):
    """Detached signatures must cover the whole object, not a chosen subset.

    A signature that only covered the members present at signing time would let
    an attacker append an ``invalidated-at`` or a second ``subject-digests``
    entry to already-signed evidence.
    """
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    signed["invalidated-at"] = None
    assert verify_evidence(signed, keyring) is False


# --------------------------------------------------------------------------
# verify_evidence never raises
# --------------------------------------------------------------------------


def test_verify_evidence_rejects_evidence_with_no_signature(fresh_key):
    unsigned = {key: value for key, value in SMALL_EVIDENCE.items() if key != "signature"}
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(unsigned, keyring) is False


def test_verify_evidence_rejects_a_signature_that_is_not_an_object(fresh_key):
    # 1.0.0 packages carried a signature as a bare reference string. A verifier
    # that treated a string as "present" would report it as verified.
    evidence = dict(SMALL_EVIDENCE, signature="REPLACE_WITH_DETACHED_SIGNATURE_REFERENCE")
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(evidence, keyring) is False


def test_verify_evidence_rejects_an_algorithm_it_did_not_implement(fresh_key):
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    signed["signature"]["algorithm"] = "rsa-pkcs1"
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is False


def test_verify_evidence_rejects_a_key_id_that_is_not_in_the_keyring(fresh_key):
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key, key_id="tool:unknown:1.0.0")
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is False


def test_verify_evidence_rejects_a_malformed_base64_signature_value(fresh_key):
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    signed["signature"]["value"] = "not!valid!base64!"
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is False


def test_verify_evidence_rejects_a_well_formed_signature_from_the_wrong_key(fresh_key):
    """The signature is valid; it is simply not this collector's signature."""
    other_key = Ed25519PrivateKey.generate()
    signed = sign_evidence(SMALL_EVIDENCE, other_key)
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is False


def test_verify_evidence_rejects_a_signature_value_that_is_not_a_string(fresh_key):
    signed = sign_evidence(SMALL_EVIDENCE, fresh_key)
    signed["signature"]["value"] = 42
    keyring = {SMALL_EVIDENCE["collector"]: raw_public_key(fresh_key)}
    assert verify_evidence(signed, keyring) is False


def test_public_key_to_keyring_entry_round_trips_through_base64(fresh_key):
    entry = public_key_to_keyring_entry(fresh_key.public_key())
    assert base64.b64decode(entry) == raw_public_key(fresh_key)


# --------------------------------------------------------------------------
# Level 4: signature checking
# --------------------------------------------------------------------------


def test_a_missing_keyring_produces_exactly_one_warning_and_never_a_silent_pass(covert, policy):
    """An unrunnable check must be visible in the output.

    A.5 level 4 requires evidence to be "signed or otherwise attributable". When
    no keyring is supplied the validator cannot answer that question, and an
    answer it cannot give must not look like an answer of "yes".
    """
    findings = validate_l4_evidence(
        covert, keyring=None, root=None, policy=policy, now=FROZEN_NOW
    )
    signature_findings = messages(findings, "signature")
    assert len(signature_findings) == 1
    finding = signature_findings[0]
    assert finding.level == 4
    assert finding.severity == SEVERITY_WARNING
    assert "was not performed" in finding.message


def test_a_fully_signed_package_produces_no_signature_findings(covert, keyring, policy):
    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=policy, now=FROZEN_NOW
    )
    assert messages(findings, "signature") == []


def test_unsigned_evidence_is_reported_as_unsigned_not_as_a_failed_verification(
    covert, keyring, policy
):
    """Two different problems that need two different remediations.

    "Nobody signed this" is a collector configuration gap. "This signature does
    not verify" is a tampering or key-rotation incident. Collapsing them into one
    message sends the wrong team to the wrong problem.
    """
    del covert["evidence"][0]["signature"]
    evidence_id = covert["evidence"][0]["id"]

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=policy, now=FROZEN_NOW
    )
    reported = [f for f in findings if f.object_id == evidence_id and "signed" in f.message]
    assert len(reported) == 1
    assert reported[0].severity == SEVERITY_ERROR
    assert reported[0].message == "evidence is unsigned"
    assert messages(findings, "verification failed") == []


def test_a_broken_signature_is_reported_as_a_verification_failure(covert, keyring, policy):
    covert["evidence"][0]["result"] = "fail-after-signing"
    evidence_id = covert["evidence"][0]["id"]

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=policy, now=FROZEN_NOW
    )
    reported = [f for f in findings if f.object_id == evidence_id]
    assert [f.severity for f in reported] == [SEVERITY_ERROR]
    assert "verification failed" in reported[0].message


def test_a_key_id_that_is_not_the_collector_is_an_error_even_when_the_signature_verifies(
    covert, keyring, policy
):
    """The signature binds a key to a collector, not merely to a package.

    Without this rule, any holder of a keyring key could sign as any other
    collector, so one compromised tool could manufacture evidence attributed to
    every other tool in the assurance system. The signature below is
    cryptographically valid, and that is exactly why it has to be refused.
    """
    impostor_key = Ed25519PrivateKey.generate()
    impostor_id = "tool:impostor:9.9.9"
    evidence = covert["evidence"][1]
    evidence_id = evidence["id"]
    covert["evidence"][1] = sign_evidence(evidence, impostor_key, key_id=impostor_id)

    ring = dict(keyring)
    ring[impostor_id] = raw_public_key(impostor_key)
    assert verify_evidence(covert["evidence"][1], ring) is True

    findings = validate_l4_evidence(
        covert, keyring=ring, root=None, policy=policy, now=FROZEN_NOW
    )
    reported = [f for f in findings if f.object_id == evidence_id]
    assert [f.severity for f in reported] == [SEVERITY_ERROR]
    assert "does not match collector" in reported[0].message


# --------------------------------------------------------------------------
# Level 4: artifact binding
# --------------------------------------------------------------------------


def test_evidence_bound_to_a_digest_outside_the_inventory_is_an_error(covert, keyring, policy):
    """A.1 principle 3: assurance follows the deployed artifact.

    Evidence naming a digest that no component carries is evidence about
    something this package does not deploy, so it cannot support any claim about
    this system however recently it was collected.
    """
    orphan = "sha256:" + "0" * 64
    evidence = covert["evidence"][2]
    evidence["subject-digests"] = [*evidence["subject-digests"], orphan]

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=policy, now=FROZEN_NOW
    )
    reported = messages(findings, "not in the package inventory")
    assert len(reported) == 1
    assert reported[0].severity == SEVERITY_ERROR
    assert reported[0].object_id == evidence["id"]
    assert orphan in reported[0].message


def test_evidence_with_no_subject_digests_is_a_warning_not_an_error(covert, keyring, policy):
    """Unbound evidence is unusable, but it is not a false claim.

    It has claimed nothing about any artifact, so nothing it says can be wrong.
    The contract that requires it is where this turns into a gate consequence,
    via the currency predicate's binding conjunct.
    """
    evidence = covert["evidence"][2]
    evidence["subject-digests"] = []

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=policy, now=FROZEN_NOW
    )
    reported = messages(findings, "no subject-digests")
    assert len(reported) == 1
    assert reported[0].severity == SEVERITY_WARNING
    assert reported[0].object_id == evidence["id"]


# --------------------------------------------------------------------------
# Level 4: approved collection methods
# --------------------------------------------------------------------------


def test_the_default_bundle_approves_no_methods_and_says_so_once(covert, keyring, policy):
    """A.5 level 4 asks for evidence "collected by an approved method".

    Which methods are approved is an organisational choice, so the shipped
    bundle declares none. That makes the check unrunnable rather than passing,
    and an unrunnable check is reported.
    """
    assert policy.method_policy_in_force is False

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=policy, now=FROZEN_NOW
    )
    reported = messages(findings, "approves no specific evidence-collection methods")
    assert len(reported) == 1
    assert reported[0].severity == SEVERITY_WARNING
    assert reported[0].object_id is None


def test_a_bundle_with_an_approved_list_checks_every_method(covert, keyring, strict_policy):
    assert strict_policy.method_policy_in_force is True

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=strict_policy, now=FROZEN_NOW
    )
    assert messages(findings, "is not approved by policy") == []


def test_an_unapproved_collection_method_is_an_error_under_a_strict_bundle(
    covert, keyring, strict_policy
):
    evidence = covert["evidence"][0]
    evidence["method"] = "ad-hoc-manual-inspection"

    findings = validate_l4_evidence(
        covert, keyring=keyring, root=None, policy=strict_policy, now=FROZEN_NOW
    )
    reported = messages(findings, "is not approved by policy")
    assert len(reported) == 1
    assert reported[0].severity == SEVERITY_ERROR
    assert reported[0].object_id == evidence["id"]
    assert strict_policy.name in reported[0].message
