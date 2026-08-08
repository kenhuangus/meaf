"""Tests for MEAF validator."""

from __future__ import annotations

import copy
import inspect
import sys
import tempfile
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import meaf
from meaf.attest import check_attestation, compute_digest, update_attestation
from meaf.contracts import (
    contracts_exit_code,
    evaluate_contract,
    evaluate_contracts,
)
from meaf.lifecycle import attempt_transition, check_transition_guard, current_state
from meaf.oscal import EXPORT_FILES, export_oscal
from meaf.signing import load_keyring, sign_evidence, validate_l4_evidence, verify_evidence
from meaf.summary import SUMMARY_KEYS, build_summary
from meaf.testpack import evaluate_contract_rules, run_tests
from meaf.validator import (
    evidence_is_fresh,
    format_findings,
    has_errors,
    load_package,
    load_schema,
    validate_package,
)

EXAMPLES = Path(__file__).parent / "examples"
REPO_ROOT = Path(__file__).parent.parent
FROZEN_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)

PUBLIC_API_EXPORTS = frozenset(
    {
        "load_package",
        "validate_package",
        "format_findings",
        "has_errors",
        "Finding",
        "check_attestation",
        "update_attestation",
        "compute_digest",
        "default_root_for_package",
        "run_tests",
        "TestRunResult",
        "attempt_transition",
        "current_state",
        "legal_next_states",
        "TransitionResult",
        "export_oscal",
        "sign_evidence",
        "verify_evidence",
        "load_keyring",
        "canonical_payload",
        "evaluate_contract",
        "evaluate_contracts",
        "build_summary",
    }
)

EXPECTED_CALLABLE_SIGNATURES: dict[str, tuple[list[str], list[str]]] = {
    "validate_package": (["package"], ["now", "schema", "keyring", "root"]),
    "check_attestation": (["package", "root"], []),
    "run_tests": (["package"], ["test_id", "sign_with", "now", "cwd"]),
    "attempt_transition": (
        ["package", "to_state"],
        ["actor", "reason", "now", "keyring", "root"],
    ),
    "export_oscal": (["package", "out_dir"], []),
    "sign_evidence": (["evidence", "private_key"], ["key_id"]),
    "verify_evidence": (["evidence", "keyring"], []),
    "evaluate_contract": (
        ["package", "contract"],
        ["now", "keyring", "root"],
    ),
    "evaluate_contracts": (["package"], ["now", "keyring", "root"]),
    "build_summary": (["package"], ["now", "keyring", "root"]),
}

ATTESTATION_RECORD_KEYS = frozenset(
    {
        "artifact-path",
        "component-id",
        "computed-digest",
        "recorded-digest",
        "status",
    }
)

FINDING_FIELD_NAMES = frozenset({"level", "message", "object_id", "severity"})

CANONICAL_PAYLOAD_FIXTURE = (
    {
        "collector": "tool:example:1.0.0",
        "id": "ev-canonical-fixture",
        "result": "pass",
        "signature": {
            "algorithm": "ed25519",
            "key-id": "tool:example:1.0.0",
            "value": "ignored-for-canonicalization",
        },
    },
    b'{"collector":"tool:example:1.0.0","id":"ev-canonical-fixture","result":"pass"}',
)


def test_public_api_surface():
    assert frozenset(meaf.__all__) == PUBLIC_API_EXPORTS
    for name in meaf.__all__:
        obj = getattr(meaf, name)
        if name in ("Finding", "TestRunResult", "TransitionResult"):
            assert inspect.isclass(obj), f"{name} should be a class"
        else:
            assert callable(obj), f"{name} should be callable"


def test_public_callable_signatures():
    for func_name, (positional, keyword_only) in EXPECTED_CALLABLE_SIGNATURES.items():
        func = getattr(meaf, func_name)
        sig = inspect.signature(func)
        pos_params = [
            name
            for name, param in sig.parameters.items()
            if param.kind
            in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        kwonly_params = [
            name
            for name, param in sig.parameters.items()
            if param.kind == inspect.Parameter.KEYWORD_ONLY
        ]
        assert pos_params == positional, func_name
        assert kwonly_params == keyword_only, func_name


def test_schema_version_matches_package_version():
    assert meaf.SCHEMA_VERSION == "1.1.0"
    assert meaf.__version__ == "1.1.0"
    package = load_package(EXAMPLES / "covert-influence.json")
    assert package["meaf-version"] == meaf.SCHEMA_VERSION
    schema = load_schema()
    pattern = schema["properties"]["meaf-version"]["pattern"]
    assert pattern == "^1\\.[0-9]+\\.[0-9]+$"


def test_frozen_wire_contracts():
    package = load_package(EXAMPLES / "covert-influence.json")
    records = check_attestation(package, REPO_ROOT)
    assert records
    for record in records:
        assert frozenset(record.keys()) == ATTESTATION_RECORD_KEYS

    finding_fields = {field.name for field in fields(meaf.Finding)}
    assert finding_fields == FINDING_FIELD_NAMES

    evidence, expected_bytes = CANONICAL_PAYLOAD_FIXTURE
    assert meaf.canonical_payload(evidence) == expected_bytes


def test_covert_influence_validates_clean():
    package = load_package(EXAMPLES / "covert-influence.json")
    findings = validate_package(package, now=FROZEN_NOW, root=REPO_ROOT)
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
    findings = validate_l4_evidence(package, keyring=None, root=REPO_ROOT)
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
        package, "draft", "validated", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert granted

    transition, pkg_validated = attempt_transition(
        package, "validated", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert transition.granted

    granted, _ = check_transition_guard(
        pkg_validated, "validated", "assessed", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert granted

    transition, pkg_assessed = attempt_transition(
        pkg_validated, "assessed", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert transition.granted

    granted, _ = check_transition_guard(
        pkg_assessed, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert granted

    transition, pkg_authorized = attempt_transition(
        pkg_assessed, "authorized", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert transition.granted
    assert current_state(pkg_authorized) == "authorized"

    granted, _ = check_transition_guard(
        pkg_authorized, "authorized", "suspended", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert granted

    granted, _ = check_transition_guard(
        pkg_authorized, "authorized", "retired", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
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
    findings = validate_package(package, now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT)
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
    findings = validate_l4_evidence(mini_package, keyring=keyring, root=REPO_ROOT)
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
    findings = validate_package(package, now=FROZEN_NOW, root=REPO_ROOT)
    text = format_findings(findings)
    assert "L4:" in text
    for level in (5, 6):
        level_findings = [f for f in findings if f.level == level]
        if level_findings:
            assert f"L{level}:" in text


def test_example_artifact_digests_match_recorded_values():
    package = load_package(EXAMPLES / "covert-influence.json")
    model_path = REPO_ROOT / "meaf/examples/artifacts/model-card.json"
    corpus_path = REPO_ROOT / "meaf/examples/artifacts/corpus-manifest.json"
    model_digest = compute_digest(model_path)
    corpus_digest = compute_digest(corpus_path)

    components = {c["id"]: c for c in package["components"]}
    assert components["cmp-foundation-model"]["digest"] == model_digest
    assert components["cmp-rag-corpus"]["digest"] == corpus_digest

    records = check_attestation(package, REPO_ROOT)
    assert all(record["status"] == "match" for record in records)


def test_attestation_drift_detected_and_validated(tmp_path):
    import shutil

    work_root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "meaf/examples", work_root / "meaf/examples")
    package_path = work_root / "meaf/examples/covert-influence.json"
    package = load_package(package_path)

    artifact_path = work_root / "meaf/examples/artifacts/model-card.json"
    artifact_path.write_text(artifact_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    records = check_attestation(package, work_root)
    drift_records = [r for r in records if r["status"] == "drift"]
    assert len(drift_records) == 1
    assert drift_records[0]["component-id"] == "cmp-foundation-model"

    findings = validate_package(package, now=FROZEN_NOW, root=work_root)
    drift_errors = [
        f
        for f in findings
        if f.level == 4
        and f.severity == "error"
        and f.message == "artifact digest drift: cmp-foundation-model"
    ]
    assert len(drift_errors) == 1


def test_missing_artifact_file_is_warning_not_error(tmp_path):
    import shutil

    work_root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "meaf/examples", work_root / "meaf/examples")
    package_path = work_root / "meaf/examples/covert-influence.json"
    package = load_package(package_path)

    missing_path = work_root / "meaf/examples/artifacts/model-card.json"
    missing_path.unlink()

    records = check_attestation(package, work_root)
    missing_records = [r for r in records if r["status"] == "missing-file"]
    assert len(missing_records) == 1
    assert missing_records[0]["component-id"] == "cmp-foundation-model"

    findings = validate_package(package, now=FROZEN_NOW, root=work_root)
    missing_warnings = [
        f
        for f in findings
        if f.level == 4
        and f.severity == "warning"
        and f.object_id == "cmp-foundation-model"
        and "artifact file missing" in f.message
    ]
    assert len(missing_warnings) == 1
    drift_errors = [f for f in findings if f.level == 4 and f.severity == "error" and "drift" in f.message]
    assert not drift_errors


def test_attest_update_repairs_drift_and_preserves_evidence_bindings(tmp_path):
    import shutil

    work_root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "meaf/examples", work_root / "meaf/examples")
    package_path = work_root / "meaf/examples/covert-influence.json"
    package = load_package(package_path)

    artifact_path = work_root / "meaf/examples/artifacts/model-card.json"
    artifact_path.write_text(artifact_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    old_digest = package["components"][0]["digest"]
    updated, changes = update_attestation(package, work_root)
    assert changes
    assert updated["components"][0]["digest"] != old_digest
    new_digest = updated["components"][0]["digest"]

    for evidence in updated["evidence"]:
        for digest in evidence.get("subject-digests", []):
            assert digest != old_digest
        if evidence["id"] in ("ev-counterfactual-run-2026-07", "ev-model-attestation"):
            assert new_digest in evidence["subject-digests"]

    findings = validate_package(updated, now=FROZEN_NOW, root=work_root)
    assert not has_errors(findings)


def test_lifecycle_degraded_requires_attestation_drift_when_root_supplied():
    package = load_package(EXAMPLES / "covert-influence.json")
    keyring = load_keyring(EXAMPLES / "keyring.json")

    transition, pkg_validated = attempt_transition(
        package, "validated", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert transition.granted
    transition, pkg_assessed = attempt_transition(
        pkg_validated, "assessed", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert transition.granted
    transition, pkg_authorized = attempt_transition(
        pkg_assessed, "authorized", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert transition.granted

    granted, reason = check_transition_guard(
        pkg_authorized, "authorized", "degraded", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert not granted
    assert "no degradation trigger" in reason

    drifted = copy.deepcopy(pkg_authorized)
    drifted["components"][0]["digest"] = "sha256:" + "0" * 64
    granted, reason = check_transition_guard(
        drifted, "authorized", "degraded", now=FROZEN_NOW, keyring=keyring, root=REPO_ROOT
    )
    assert granted
    assert "bound artifact digest changed" in reason


def test_contract_state_pass():
    package = load_package(EXAMPLES / "covert-influence.json")
    evaluations = evaluate_contracts(package, now=FROZEN_NOW)
    by_id = {item["contract-id"]: item for item in evaluations}
    assert by_id["ac-epistemic-integrity-001"]["state"] == "pass"
    assert by_id["ac-containment-001"]["state"] == "pass"


def test_contract_state_fail():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    for evidence in package["evidence"]:
        if evidence["id"] == "ev-counterfactual-run-2026-07":
            evidence["result"] = "fail"
    contract = next(
        c for c in package["assurance-contracts"] if c["id"] == "ac-epistemic-integrity-001"
    )
    result = evaluate_contract(package, contract, now=FROZEN_NOW)
    assert result["state"] == "fail"
    assert "fail" in result["reason"]


def test_contract_state_indeterminate_stale_evidence():
    package = load_package(EXAMPLES / "covert-influence.json")
    stale_now = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    contract = next(
        c for c in package["assurance-contracts"] if c["id"] == "ac-epistemic-integrity-001"
    )
    result = evaluate_contract(package, contract, now=stale_now)
    assert result["state"] == "indeterminate"
    assert result["state"] not in ("pass", "fail")


def test_contract_state_not_applicable_requires_applicability():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    contract = next(
        c for c in package["assurance-contracts"] if c["id"] == "ac-containment-001"
    )
    without = evaluate_contract(package, contract, now=FROZEN_NOW)
    assert without["state"] != "not-applicable"

    contract["applicability"] = {
        "approved-by": "ai-assurance-review-board",
        "rationale": "containment handled by external SOC",
        "scope": "production-research-agent",
    }
    with_applicability = evaluate_contract(package, contract, now=FROZEN_NOW)
    assert with_applicability["state"] == "not-applicable"


def test_indeterminate_contract_does_not_cause_contracts_exit_one():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    for evidence in package["evidence"]:
        evidence["collected-at"] = "2020-01-01T00:00:00Z"
    evaluations = evaluate_contracts(
        package, now=datetime(2026, 9, 1, tzinfo=timezone.utc)
    )
    assert all(e["state"] == "indeterminate" for e in evaluations)
    assert contracts_exit_code(evaluations) == 0
    assert not any(e["state"] == "fail" for e in evaluations)


def test_fail_contract_without_finding_is_l5_error():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    for evidence in package["evidence"]:
        if evidence["id"] == "ev-counterfactual-run-2026-07":
            evidence["result"] = "fail"
    findings = validate_package(package, now=FROZEN_NOW, root=REPO_ROOT)
    errors = [
        f
        for f in findings
        if f.level == 5
        and f.severity == "error"
        and f.object_id == "ac-epistemic-integrity-001"
        and "failed assurance-contract lacks findings object" in f.message
    ]
    assert len(errors) == 1


def test_summary_has_eight_keys_and_no_aggregate_score():
    package = load_package(EXAMPLES / "covert-influence.json")
    summary = build_summary(package, now=FROZEN_NOW, root=REPO_ROOT)
    assert frozenset(summary.keys()) == SUMMARY_KEYS
    forbidden = {"score", "overall", "aggregate", "total-score", "overall-score"}
    assert forbidden.isdisjoint(summary.keys())
    for value in summary.values():
        if isinstance(value, dict):
            assert forbidden.isdisjoint(value.keys())


def test_utility_rule_satisfied_and_violated():
    contract = {
        "decision-rule": {"metric-a-max": 1.0},
        "utility-rule": {"benign-task-completion-rate-min": 0.85},
    }
    assert (
        evaluate_contract_rules(
            contract,
            {"metric-a": 0.5},
            {"benign-task-completion-rate": 0.9},
        )
        == "pass"
    )
    assert (
        evaluate_contract_rules(
            contract,
            {"metric-a": 0.5},
            {"benign-task-completion-rate": 0.5},
        )
        == "fail"
    )


def test_missing_utility_metrics_yields_indeterminate():
    contract = {
        "decision-rule": {"metric-a-max": 1.0},
        "utility-rule": {"benign-task-completion-rate-min": 0.85},
    }
    assert evaluate_contract_rules(contract, {"metric-a": 0.5}, None) == "indeterminate"
    assert evaluate_contract_rules(contract, {"metric-a": 0.5}, {}) == "indeterminate"


def test_prevent_detect_without_utility_rule_is_l5_warning():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    package["assurance-contracts"].append(
        {
            "id": "ac-prevent-no-utility",
            "claim": "test prevent without utility threshold",
            "subject": "cmp-foundation-model",
            "threats": ["thr-covert-influence-001"],
            "function": "prevent",
            "interruption-point": "L3:response-planning",
            "interruption-type": "blocks",
            "test": "test-counterfactual-symmetry-001",
            "decision-rule": {"blocked-rate-min": 0.9},
            "required-evidence": ["ev-model-attestation"],
            "cadence": "daily",
            "failure-action": "block",
            "owner": "role-test",
        }
    )
    findings = validate_package(package, now=FROZEN_NOW, root=REPO_ROOT)
    warnings = [
        f
        for f in findings
        if f.level == 5
        and f.severity == "warning"
        and f.object_id == "ac-prevent-no-utility"
        and f.message == "security threshold declared without a utility threshold"
    ]
    assert len(warnings) == 1
