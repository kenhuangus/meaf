"""Tests for MEAF validator."""

from __future__ import annotations

import copy
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from meaf.lifecycle import attempt_transition, check_transition_guard, current_state
from meaf.oscal import EXPORT_FILES, export_oscal
from meaf.signing import load_keyring, sign_evidence, validate_l4_evidence, verify_evidence
from meaf.testpack import run_tests
from meaf.validator import (
    evidence_is_fresh,
    format_findings,
    has_errors,
    load_package,
    validate_package,
)

EXAMPLES = Path(__file__).parent / "examples"
REPO_ROOT = Path(__file__).parent.parent
FROZEN_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)


def test_covert_influence_validates_clean():
    package = load_package(EXAMPLES / "covert-influence.json")
    findings = validate_package(package, now=FROZEN_NOW)
    errors = [f for f in findings if f.severity == "error"]
    assert errors == [], format_findings(findings)


def test_broken_has_errors_at_each_level():
    package = load_package(EXAMPLES / "broken.json")
    findings = validate_package(package, now=FROZEN_NOW)
    levels_with_errors = {f.level for f in findings if f.severity == "error"}
    assert 1 in levels_with_errors, "expected L1 syntactic errors"
    assert 2 in levels_with_errors, "expected L2 referential errors"
    assert 3 in levels_with_errors, "expected L3 semantic errors"


def test_evidence_freshness_frozen_now():
    assert evidence_is_fresh(
        "2026-07-15T00:00:00Z",
        "P30D",
        None,
        FROZEN_NOW,
    )
    assert not evidence_is_fresh(
        "2026-06-01T00:00:00Z",
        "P30D",
        None,
        FROZEN_NOW,
    )
    assert not evidence_is_fresh(
        "2026-07-15T00:00:00Z",
        "P30D",
        "2026-07-20T00:00:00Z",
        FROZEN_NOW,
    )


def test_stale_evidence_is_warning_not_error():
    package = load_package(EXAMPLES / "covert-influence.json")
    stale_now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    findings = validate_package(package, now=stale_now)
    l3_stale = [
        f
        for f in findings
        if f.level == 3 and f.message == "evidence is stale at evaluation time"
    ]
    assert l3_stale
    assert all(f.severity == "warning" for f in l3_stale)
    l5_contract_stale = [
        f
        for f in findings
        if f.level == 5
        and f.severity == "error"
        and "contract policy violation" in f.message
    ]
    assert l5_contract_stale
    assert not has_errors([f for f in findings if f.level != 5])


def test_injectable_now_changes_freshness_outcome():
    package = load_package(EXAMPLES / "covert-influence.json")
    fresh_findings = validate_package(
        package,
        now=datetime(2026, 7, 20, tzinfo=timezone.utc),
    )
    stale_findings = validate_package(
        package,
        now=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    l3_fresh = [
        f for f in fresh_findings if f.level == 3 and "stale at evaluation time" in f.message
    ]
    l3_stale = [
        f for f in stale_findings if f.level == 3 and "stale at evaluation time" in f.message
    ]
    assert not l3_fresh
    assert l3_stale


def test_ed25519_signature_round_trip():
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keyring = {"test-collector:1.0.0": public_bytes}
    evidence = {
        "id": "ev-sign-test",
        "class": "deterministic-observation",
        "subject-digests": ["sha256:abc"],
        "method": "unit-test",
        "collector": "test-collector:1.0.0",
        "collected-at": "2026-07-15T00:00:00Z",
        "max-age": "P30D",
        "invalidated-at": None,
        "result": "pass",
    }
    signed = sign_evidence(evidence, private_key, key_id="test-collector:1.0.0")
    assert verify_evidence(signed, keyring)
    tampered = dict(signed)
    tampered["result"] = "fail"
    assert not verify_evidence(tampered, keyring)


def test_missing_keyring_produces_one_l4_warning():
    package = load_package(EXAMPLES / "covert-influence.json")
    findings = validate_package(package, now=FROZEN_NOW, keyring=None)
    sig_warnings = [
        f
        for f in findings
        if f.level == 4
        and f.severity == "warning"
        and f.message == "signature verification was not performed"
    ]
    assert len(sig_warnings) == 1
    other_sig = [
        f
        for f in findings
        if f.level == 4 and "signature" in f.message and f not in sig_warnings
    ]
    assert not other_sig


def test_artifact_binding_unbound_digest_is_l4_error():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    package["evidence"].append(
        {
            "id": "ev-unbound-digest",
            "class": "deterministic-observation",
            "subject-digests": ["sha256:NOT_IN_INVENTORY"],
            "method": "unit-test",
            "collector": "tool:provenance-verifier:1.0.0",
            "collected-at": "2026-07-15T00:00:00Z",
            "max-age": "P30D",
            "invalidated-at": None,
            "result": "pass",
            "signature": {
                "algorithm": "ed25519",
                "key-id": "tool:provenance-verifier:1.0.0",
                "value": "unused",
            },
        }
    )
    findings = validate_l4_evidence(package, keyring=None)
    binding_errors = [
        f
        for f in findings
        if f.level == 4
        and f.severity == "error"
        and f.object_id == "ev-unbound-digest"
        and "not in the package inventory" in f.message
    ]
    assert len(binding_errors) == 1


def test_counterfactual_symmetry_runner_passes():
    package = load_package(EXAMPLES / "covert-influence.json")
    results = run_tests(
        package,
        test_id="test-counterfactual-symmetry-001",
        cwd=REPO_ROOT,
        now=FROZEN_NOW,
    )
    assert len(results) == 1
    assert results[0].runner_result == "pass"
    assert results[0].evidence["result"] == "pass"


def test_bad_runner_yields_indeterminate_not_fail():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    for test in package["tests"]:
        if test["id"] == "test-counterfactual-symmetry-001":
            test["runner"] = {
                "command": [sys.executable, "-c", "import sys; sys.exit(1)"],
                "timeout-seconds": 5,
            }
    results = run_tests(
        package,
        test_id="test-counterfactual-symmetry-001",
        cwd=REPO_ROOT,
        now=FROZEN_NOW,
    )
    assert results[0].runner_result == "indeterminate"
    assert results[0].evidence["result"] == "indeterminate"

    package["tests"][0]["runner"] = {
        "command": [sys.executable, "-c", "print('not-json')"],
        "timeout-seconds": 5,
    }
    results = run_tests(
        package,
        test_id="test-counterfactual-symmetry-001",
        cwd=REPO_ROOT,
        now=FROZEN_NOW,
    )
    assert results[0].runner_result == "indeterminate"
    assert results[0].evidence["result"] == "indeterminate"
    assert results[0].evidence["result"] != "fail"


def test_lifecycle_legal_transitions_granted():
    package = load_package(EXAMPLES / "covert-influence.json")
    keyring_path = EXAMPLES / "keyring.json"
    keyring = load_keyring(keyring_path)

    granted, _ = check_transition_guard(
        package, "draft", "validated", now=FROZEN_NOW, keyring=keyring
    )
    assert granted

    transition, pkg_validated = attempt_transition(
        package, "validated", now=FROZEN_NOW, keyring=keyring
    )
    assert transition.granted

    granted, _ = check_transition_guard(
        pkg_validated, "validated", "assessed", now=FROZEN_NOW, keyring=keyring
    )
    assert granted

    transition, pkg_assessed = attempt_transition(
        pkg_validated, "assessed", now=FROZEN_NOW, keyring=keyring
    )
    assert transition.granted

    granted, _ = check_transition_guard(
        pkg_assessed, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring
    )
    assert granted

    transition, pkg_authorized = attempt_transition(
        pkg_assessed, "authorized", now=FROZEN_NOW, keyring=keyring
    )
    assert transition.granted
    assert current_state(pkg_authorized) == "authorized"

    granted, _ = check_transition_guard(
        pkg_authorized, "authorized", "suspended", now=FROZEN_NOW, keyring=keyring
    )
    assert granted

    granted, _ = check_transition_guard(
        pkg_authorized, "authorized", "retired", now=FROZEN_NOW, keyring=keyring
    )
    assert granted


def test_lifecycle_illegal_transitions_refused():
    package = load_package(EXAMPLES / "covert-influence.json")

    retired_pkg = copy.deepcopy(package)
    retired_pkg["lifecycle"] = {"state": "retired", "history": []}
    for target in ("draft", "validated", "authorized"):
        granted, reason = check_transition_guard(
            retired_pkg, "retired", target, now=FROZEN_NOW
        )
        assert not granted
        assert "not legal" in reason

    granted, reason = check_transition_guard(
        package, "draft", "authorized", now=FROZEN_NOW
    )
    assert not granted
    assert "not legal" in reason

    validated_pkg = copy.deepcopy(package)
    validated_pkg["lifecycle"] = {"state": "validated", "history": []}
    granted, reason = check_transition_guard(
        validated_pkg, "validated", "authorized", now=FROZEN_NOW
    )
    assert not granted
    assert "not legal" in reason


def test_oscal_export_is_deterministic():
    package = load_package(EXAMPLES / "covert-influence.json")
    with tempfile.TemporaryDirectory() as dir_a, tempfile.TemporaryDirectory() as dir_b:
        path_a = Path(dir_a)
        path_b = Path(dir_b)
        export_oscal(package, path_a)
        export_oscal(package, path_b)
        for filename in EXPORT_FILES:
            assert path_a / filename in [p for p in path_a.iterdir()]
            assert (path_a / filename).read_bytes() == (path_b / filename).read_bytes()


def test_level5_and_level6_findings_fire():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    package["threats"].append(
        {
            "id": "thr-uncontracted",
            "actor": "test",
            "capabilities": ["cap:test"],
            "attack-classes": ["class:test"],
            "objective": "obj:test",
            "entry-layers": ["L1"],
            "path": "path-covert-influence-001",
            "affected-stakeholders": ["tester"],
            "outcomes": ["test-outcome"],
            "temporal-profile": {"persistence": "session"},
        }
    )
    package["evidence"].append(
        {
            "id": "ev-bad-collector",
            "class": "deterministic-observation",
            "subject-digests": ["sha256:REPLACE_WITH_ATTESTED_DIGEST"],
            "method": "unit-test",
            "collector": "unversioned-collector",
            "collected-at": "2026-07-15T00:00:00Z",
            "max-age": "P30D",
            "invalidated-at": None,
            "result": "pass",
        }
    )
    findings = validate_package(package, now=FROZEN_NOW)
    l5_errors = [f for f in findings if f.level == 5 and f.severity == "error"]
    l6_errors = [f for f in findings if f.level == 6 and f.severity == "error"]
    assert any(f.object_id == "thr-uncontracted" for f in l5_errors)
    assert any(f.object_id == "ev-bad-collector" for f in l6_errors)


def test_validate_package_accepts_keyring_kwarg():
    package = load_package(EXAMPLES / "covert-influence.json")
    keyring = load_keyring(EXAMPLES / "keyring.json")
    findings = validate_package(package, now=FROZEN_NOW, keyring=keyring)
    sig_warnings = [
        f for f in findings if f.message == "signature verification was not performed"
    ]
    assert not sig_warnings


def test_run_tests_without_sign_with_emits_no_signature():
    package = load_package(EXAMPLES / "covert-influence.json")
    results = run_tests(
        package,
        test_id="test-counterfactual-symmetry-001",
        cwd=REPO_ROOT,
        now=FROZEN_NOW,
    )
    assert len(results) == 1
    assert "signature" not in results[0].evidence


def test_unsigned_evidence_with_keyring_reports_unsigned_not_verify_failed():
    package = load_package(EXAMPLES / "covert-influence.json")
    results = run_tests(
        package,
        test_id="test-counterfactual-symmetry-001",
        cwd=REPO_ROOT,
        now=FROZEN_NOW,
    )
    unsigned_evidence = results[0].evidence
    assert "signature" not in unsigned_evidence
    mini_package = {
        "components": package["components"],
        "evidence": [unsigned_evidence],
    }
    keyring = load_keyring(EXAMPLES / "keyring.json")
    findings = validate_l4_evidence(mini_package, keyring=keyring)
    unsigned_errors = [
        f
        for f in findings
        if f.level == 4
        and f.severity == "error"
        and f.message == "evidence is unsigned"
    ]
    assert len(unsigned_errors) == 1
    verify_failed = [
        f for f in findings if f.message == "evidence signature verification failed"
    ]
    assert not verify_failed


def test_format_findings_groups_levels_4_through_6():
    package = load_package(EXAMPLES / "covert-influence.json")
    findings = validate_package(package, now=FROZEN_NOW)
    text = format_findings(findings)
    assert "L4:" in text
    for level in (5, 6):
        level_findings = [f for f in findings if f.level == level]
        if level_findings:
            assert f"L{level}:" in text
