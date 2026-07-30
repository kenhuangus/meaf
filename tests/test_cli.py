"""Exit codes are the interface, because the point of the tool is to gate pipelines.

Nobody reads the CLI's prose in CI. A build system reads the exit status, and
``meaf``'s docstring commits to what each status means: 0 clean, 1 conformance
errors, 2 review-required from the gate, 2 a usage error the operator has to fix.
Those numbers are what stops a failing assurance claim from shipping, so they are
tested as a contract rather than as incidental behaviour.

``main(argv)`` is called in process. A subprocess would prove the same thing more
slowly while making failures harder to read, and the module under test is
deliberately thin enough that in-process calls exercise all of it.

Every invocation that depends on time passes ``--now``. Every invocation that
writes uses the ``example_tree`` copy or ``tmp_path``; nothing here may touch
``meaf/examples``.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from meaf.__main__ import main
from meaf.packs import load_registry
from tests.conftest import FROZEN_NOW, write_package

#: The evaluation instant, in the form the CLI parses, tied to the suite's own.
NOW = FROZEN_NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    """Invoke the CLI and return (exit code, stdout, stderr)."""
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def tree_digests(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }


@pytest.fixture
def memory_path(example_tree: Path) -> Path:
    return example_tree / "memory-poisoning.json"


@pytest.fixture
def broken_path(example_tree: Path) -> Path:
    return example_tree / "broken.json"


@pytest.fixture
def keyring_path(example_tree: Path) -> Path:
    return example_tree / "keyring.json"


@pytest.fixture
def legacy_path(example_tree: Path) -> Path:
    return example_tree / "legacy" / "covert-influence-1.0.0.json"


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


def test_validate_exits_zero_for_a_conforming_package(capsys, covert_path, keyring_path):
    code, out, _ = run(
        capsys,
        "validate",
        str(covert_path),
        "--now",
        NOW,
        "--keyring",
        str(keyring_path),
    )
    assert code == 0
    assert "0 error(s)" in out


def test_validate_exits_one_when_conformance_errors_remain(
    capsys, broken_path, keyring_path
):
    code, _, _ = run(
        capsys,
        "validate",
        str(broken_path),
        "--now",
        NOW,
        "--keyring",
        str(keyring_path),
    )
    assert code == 1


def test_validate_json_emits_a_parseable_findings_array(capsys, broken_path):
    code, out, _ = run(capsys, "validate", str(broken_path), "--now", NOW, "--json")
    findings = json.loads(out)
    assert isinstance(findings, list)
    assert findings
    for finding in findings:
        assert set(finding) == {"level", "severity", "object_id", "message"}
        assert finding["level"] in range(1, 7)
        assert finding["severity"] in ("error", "warning")
    assert code == 1


def test_validate_warns_rather_than_errors_when_no_keyring_is_supplied(
    capsys, covert_path
):
    """Not checking a signature is not the same as checking it and failing."""
    code, out, _ = run(capsys, "validate", str(covert_path), "--now", NOW, "--json")
    findings = json.loads(out)
    unchecked = [
        finding
        for finding in findings
        if "signature verification was not performed" in finding["message"]
    ]
    assert unchecked and unchecked[0]["severity"] == "warning"
    assert code == 0


# --------------------------------------------------------------------------
# gate
# --------------------------------------------------------------------------


def test_gate_allows_the_clean_package(capsys, covert_path):
    code, out, _ = run(capsys, "gate", str(covert_path), "--now", NOW)
    assert code == 0
    assert "allow" in out


def test_gate_requires_review_when_a_failure_is_under_a_live_exception(
    capsys, memory_path
):
    """A.5: "expired evidence or exceptions change the gate state."

    A live exception does not make the failing claim true, so the gate must not
    reach allow; it records that a named authority accepted the failure.
    """
    code, out, _ = run(capsys, "gate", str(memory_path), "--now", NOW)
    assert code == 2
    assert "review-required" in out


def test_gate_blocks_when_the_exception_covering_the_failure_is_removed(
    capsys, memory_path, tmp_path
):
    package = load(memory_path)
    package["decisions"] = [
        decision
        for decision in package["decisions"]
        if decision["decision-type"] != "exception"
    ]
    unexcepted = write_package(tmp_path / "memory-without-exception.json", package)

    code, out, _ = run(capsys, "gate", str(unexcepted), "--now", NOW)
    assert code == 1
    assert "block" in out


def test_gate_json_reports_the_decision_and_every_contract_state(capsys, covert_path):
    code, out, _ = run(capsys, "gate", str(covert_path), "--now", NOW, "--json")
    result = json.loads(out)
    assert result["gate-decision"] == "allow"
    assert {state["contract-id"] for state in result["contract-states"]} == {
        "ac-epistemic-integrity-001",
        "ac-containment-001",
    }
    assert code == 0


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------


def test_summary_exits_zero_and_reports_the_eight_dimensions(capsys, covert_path):
    # A.5 lists exactly what a conforming summary must report.
    code, out, _ = run(capsys, "summary", str(covert_path), "--now", NOW, "--json")
    document = json.loads(out)
    assert code == 0
    assert {
        "threat-model-completeness",
        "path-interruption-coverage",
        "control-test-status",
        "evidence-freshness",
        "open-findings-by-severity",
        "recovery-readiness",
        "probabilistic-evidence-dependence",
        "exception-age",
    } <= set(document)


def test_summary_without_json_is_human_readable_and_still_exits_zero(
    capsys, covert_path
):
    code, out, _ = run(capsys, "summary", str(covert_path), "--now", NOW)
    assert code == 0
    assert "Conformance summary" in out
    # A.5: "MEAF intentionally does not define a universal aggregate score."
    assert "No aggregate score is reported." in out


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


def test_report_writes_to_the_requested_output_path(capsys, covert_path, tmp_path):
    destination = tmp_path / "report.md"
    code, out, _ = run(
        capsys, "report", str(covert_path), "--now", NOW, "--output", str(destination)
    )
    assert code == 0
    assert destination.is_file()
    assert destination.read_text(encoding="utf-8").startswith("# Assurance report:")
    assert str(destination) in out


def test_report_prints_to_standard_output_when_no_output_path_is_given(
    capsys, covert_path
):
    # A.1 principle 6: reports are projections of the package, so the same
    # content must be obtainable without choosing a file to keep it in.
    code, out, _ = run(capsys, "report", str(covert_path), "--now", NOW)
    assert code == 0
    assert out.startswith("# Assurance report:")


# --------------------------------------------------------------------------
# run-tests
# --------------------------------------------------------------------------


def test_run_tests_exits_zero_when_every_selected_test_ran_and_passed(
    capsys, covert_path
):
    code, out, _ = run(
        capsys,
        "run-tests",
        str(covert_path),
        "--now",
        NOW,
        "--test",
        "test-counterfactual-symmetry-001",
    )
    assert code == 0
    assert "runner=pass" in out


def test_run_tests_exits_non_zero_when_a_selected_test_has_no_runner(
    capsys, covert_path
):
    """A test that was never executed must not look like a test that passed."""
    code, out, _ = run(capsys, "run-tests", str(covert_path), "--now", NOW)
    assert code != 0
    assert "test-containment-playbook-001: not executed (no runner declared)" in out


def test_run_tests_output_writes_a_package_carrying_the_new_evidence(
    capsys, covert_path, tmp_path
):
    destination = tmp_path / "after-run.json"
    code, _, _ = run(
        capsys,
        "run-tests",
        str(covert_path),
        "--now",
        NOW,
        "--test",
        "test-counterfactual-symmetry-001",
        "--output",
        str(destination),
    )
    assert code == 0
    before = {item["id"] for item in load(covert_path)["evidence"]}
    after = {item["id"] for item in load(destination)["evidence"]}
    new_ids = after - before
    assert len(new_ids) == 1
    emitted = next(
        item for item in load(destination)["evidence"] if item["id"] in new_ids
    )
    assert emitted["collected-at"] == NOW
    assert emitted["result"] == "pass"
    # A.1 principle 2: an LLM-judged oracle produces probabilistic inference and
    # must carry the metadata that makes the judgment interpretable.
    assert emitted["class"] == "probabilistic-inference"
    assert emitted["model-metadata"]["evaluator-model"]


def test_link_evidence_points_the_exercised_contract_at_the_run_just_performed(
    capsys, covert_path, tmp_path
):
    """Without this the assurance loop never closes.

    A fresh run would emit evidence no contract requires, leaving the contract
    to be evaluated against the run it superseded.
    """
    destination = tmp_path / "linked.json"
    code, _, _ = run(
        capsys,
        "run-tests",
        str(covert_path),
        "--now",
        NOW,
        "--test",
        "test-counterfactual-symmetry-001",
        "--output",
        str(destination),
        "--link-evidence",
    )
    assert code == 0
    updated = load(destination)
    contract = next(
        item
        for item in updated["assurance-contracts"]
        if item["id"] == "ac-epistemic-integrity-001"
    )
    emitted = {item["id"] for item in updated["evidence"]} - {
        item["id"] for item in load(covert_path)["evidence"]
    }
    assert emitted <= set(contract["required-evidence"])


@pytest.fixture
def failing_covert(example_tree: Path, covert_path: Path) -> Path:
    """The clean package with one threshold tightened past what the runner reports.

    The example runner reports a source-inclusion asymmetry of 0.04, so a
    maximum of 0.0 turns the contract from pass to fail without touching the
    runner, the evidence or the digests.
    """
    package = copy.deepcopy(load(covert_path))
    contract = next(
        item
        for item in package["assurance-contracts"]
        if item["id"] == "ac-epistemic-integrity-001"
    )
    contract["decision-rule"]["source-inclusion-asymmetry-max"] = 0.0
    # The package must sit beside the runners it names: runner commands are
    # resolved relative to the package file.
    return write_package(example_tree / "covert-failing.json", package)


def test_create_findings_records_a_finding_for_each_failed_contract(
    capsys, failing_covert, tmp_path
):
    # A.8 step 3: assessment must "create findings automatically for failed
    # contracts, and record indeterminate results without coercion".
    destination = tmp_path / "with-findings.json"
    code, out, _ = run(
        capsys,
        "run-tests",
        str(failing_covert),
        "--now",
        NOW,
        "--test",
        "test-counterfactual-symmetry-001",
        "--output",
        str(destination),
        "--create-findings",
    )
    assert code != 0
    assert "created finding" in out
    findings = load(destination)["findings"]
    assert [finding["failed-claim"] for finding in findings] == [
        "ac-epistemic-integrity-001"
    ]
    assert findings[0]["status"] == "open"
    assert findings[0]["retest-reference"] == "test-counterfactual-symmetry-001"


def test_run_tests_creates_no_finding_when_nothing_failed(
    capsys, covert_path, tmp_path
):
    """Indeterminate and passing outcomes leave nothing to remediate."""
    destination = tmp_path / "no-findings.json"
    code, _, _ = run(
        capsys,
        "run-tests",
        str(covert_path),
        "--now",
        NOW,
        "--test",
        "test-counterfactual-symmetry-001",
        "--output",
        str(destination),
        "--create-findings",
    )
    assert code == 0
    assert load(destination)["findings"] == []


# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------


def test_lifecycle_without_a_target_prints_every_guard_and_its_verdict(
    capsys, covert_path
):
    # A.8: "State transitions are policy decisions backed by package evidence,
    # not labels chosen by the agent", so the operator is shown the verdict and
    # the reason for each transition the current state permits.
    code, out, _ = run(capsys, "lifecycle", str(covert_path), "--now", NOW)
    assert code == 0
    assert "Current state: draft" in out
    assert "-> validated: permitted" in out


def test_lifecycle_grants_a_transition_whose_guard_is_satisfied(capsys, covert_path):
    code, out, _ = run(
        capsys,
        "lifecycle",
        str(covert_path),
        "--now",
        NOW,
        "--to",
        "validated",
        "--actor",
        "role-system-owner",
    )
    assert code == 0
    assert "Transition granted: draft -> validated" in out


def test_lifecycle_refuses_a_transition_the_state_machine_does_not_allow(
    capsys, covert_path
):
    code, out, _ = run(
        capsys,
        "lifecycle",
        str(covert_path),
        "--now",
        NOW,
        "--to",
        "authorized",
        "--actor",
        "role-system-owner",
    )
    assert code == 1
    assert "Transition refused: draft -> authorized" in out


def test_lifecycle_refuses_an_actor_the_package_does_not_name(capsys, covert_path):
    """A.1 principle 5: a state change must be attributable to somebody."""
    code, out, _ = run(
        capsys, "lifecycle", str(covert_path), "--now", NOW, "--to", "validated"
    )
    assert code == 1
    assert "not a declared responsible role" in out


def test_lifecycle_output_records_the_new_state_and_its_history(
    capsys, covert_path, tmp_path
):
    destination = tmp_path / "validated.json"
    code, _, _ = run(
        capsys,
        "lifecycle",
        str(covert_path),
        "--now",
        NOW,
        "--to",
        "validated",
        "--actor",
        "role-system-owner",
        "--reason",
        "levels 1 to 3 are clean",
        "--output",
        str(destination),
    )
    assert code == 0
    lifecycle = load(destination)["lifecycle"]
    assert lifecycle["state"] == "validated"
    assert lifecycle["history"][-1] == {
        "from": "draft",
        "to": "validated",
        "at": NOW,
        "actor": "role-system-owner",
        "reason": "levels 1 to 3 are clean",
    }


# --------------------------------------------------------------------------
# export-oscal
# --------------------------------------------------------------------------


def test_export_oscal_writes_the_seven_documents(capsys, covert_path, tmp_path):
    # A.4 maps MEAF content onto six OSCAL models; the profile that tailors the
    # catalog is the seventh document an implementation is asked to publish.
    out_dir = tmp_path / "oscal"
    code, out, _ = run(
        capsys, "export-oscal", str(covert_path), "--now", NOW, "--out-dir", str(out_dir)
    )
    assert code == 0
    written = sorted(path.name for path in out_dir.glob("*.json"))
    assert len(written) == 7
    assert len(out.strip().splitlines()) == 7
    for path in out_dir.glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# attest
# --------------------------------------------------------------------------


def test_attest_exits_zero_when_every_artifact_matches_its_digest(capsys, covert_path):
    code, out, _ = run(capsys, "attest", str(covert_path))
    assert code == 0
    assert "drift" not in out


def test_attest_exits_one_when_an_artifact_has_drifted(
    capsys, covert_path, example_tree
):
    # A.1 principle 3: a change to a bound artifact invalidates dependent results.
    artifact = example_tree / "artifacts" / "model-card.json"
    artifact.write_text(
        artifact.read_text(encoding="utf-8").replace("v3", "v4"), encoding="utf-8"
    )
    code, out, _ = run(capsys, "attest", str(covert_path))
    assert code == 1
    assert "cmp-foundation-model: drift" in out


def test_attest_update_without_a_destination_is_refused_and_writes_nothing(
    capsys, covert_path, example_tree
):
    """Rebinding digests in place is a destructive edit; it must be asked for.

    The refusal is a usage error, so it exits 2 rather than 1: nothing about the
    package was found to be wrong.
    """
    before = tree_digests(example_tree)
    code, out, err = run(capsys, "attest", str(covert_path), "--update")
    assert code == 2
    assert "--update needs --output" in err
    assert out == ""
    assert tree_digests(example_tree) == before


def test_attest_update_with_an_output_rebinds_component_digests_only(
    capsys, covert_path, example_tree, tmp_path
):
    """Evidence subject-digests are never rewritten.

    Rewriting them would forge the relationship the framework exists to protect:
    evidence collected against the old artifact would claim to be about the new
    one, inverting "artifact binding takes precedence over calendar freshness".
    """
    artifact = example_tree / "artifacts" / "model-card.json"
    artifact.write_text(
        artifact.read_text(encoding="utf-8").replace("v3", "v4"), encoding="utf-8"
    )
    original = load(covert_path)
    destination = tmp_path / "rebound.json"

    code, out, _ = run(
        capsys, "attest", str(covert_path), "--update", "--output", str(destination)
    )
    assert code == 0
    updated = load(destination)
    old_digest = original["components"][0]["digest"]
    assert updated["components"][0]["digest"] != old_digest
    assert "requiring re-collection" in out
    unchanged = [item["subject-digests"] for item in original["evidence"]]
    assert [item["subject-digests"] for item in updated["evidence"]] == unchanged


def test_attest_json_emits_one_record_per_component(capsys, covert_path):
    code, out, _ = run(capsys, "attest", str(covert_path), "--json")
    records = json.loads(out)
    assert code == 0
    assert {record["component-id"] for record in records} == {
        "cmp-foundation-model",
        "cmp-rag-corpus",
        "cmp-evaluator-prompt",
    }


# --------------------------------------------------------------------------
# impact
# --------------------------------------------------------------------------


def test_impact_refuses_to_run_without_a_changed_component(capsys, covert_path):
    """Analysing "no change" would report that nothing breaks, which is useless."""
    code, out, err = run(capsys, "impact", str(covert_path), "--now", NOW)
    assert code == 2
    assert "--changed COMPONENT_ID is required" in err
    assert out == ""


def test_impact_reports_what_a_component_change_would_invalidate(capsys, covert_path):
    # A.8 step 5: model or corpus changes "invalidate dependent contracts and
    # can move the system to degraded or suspended".
    code, out, _ = run(
        capsys,
        "impact",
        str(covert_path),
        "--now",
        NOW,
        "--changed",
        "cmp-foundation-model",
        "--json",
    )
    analysis = json.loads(out)
    assert code == 0
    assert analysis["changed-components"] == ["cmp-foundation-model"]
    assert "ev-counterfactual-run-2026-07" in analysis["invalidated-evidence"]
    assert analysis["recommended-lifecycle-state"] != "authorized"


# --------------------------------------------------------------------------
# migrate
# --------------------------------------------------------------------------


def test_migrate_exits_one_while_decisions_remain_outstanding(
    capsys, legacy_path, tmp_path
):
    """The migration refuses to invent risk judgments a human has to make.

    Exit 1 keeps a half-migrated package out of a pipeline that would otherwise
    treat "the tool ran" as "the package is ready".
    """
    destination = tmp_path / "migrated.json"
    code, out, err = run(
        capsys, "migrate", str(legacy_path), "--output", str(destination)
    )
    assert code == 1
    assert "Requires a human decision" in err
    assert str(destination) in out
    migrated = load(destination)
    assert migrated["meaf-version"] == "2.0.0"
    # A.3's separation of the two objects is the substance of the migration.
    assert migrated["control-implementations"]


# --------------------------------------------------------------------------
# adoption and testpacks
# --------------------------------------------------------------------------


def test_adoption_exits_zero_and_names_the_level_reached(
    capsys, covert_path, keyring_path
):
    """A.9's sequence is non-normative, so it reports rather than gates."""
    code, out, _ = run(
        capsys,
        "adoption",
        str(covert_path),
        "--now",
        NOW,
        "--keyring",
        str(keyring_path),
    )
    assert code == 0
    assert "Adoption level reached:" in out
    assert "not a conformance level" in out


def test_testpacks_lists_all_nine_standard_packs(capsys):
    # A.7 tabulates nine packs; the registry is the executable form of that table.
    code, out, _ = run(capsys, "testpacks")
    assert code == 0
    pack_ids = set(load_registry())
    assert len(pack_ids) == 9
    for pack_id in pack_ids:
        assert pack_id in out


# --------------------------------------------------------------------------
# Cross-cutting behaviour
# --------------------------------------------------------------------------


def test_an_unreadable_policy_bundle_exits_two_rather_than_raising(
    capsys, covert_path, tmp_path
):
    """An operator typo is a usage error, not a traceback."""
    missing = tmp_path / "no-such-policy.json"
    code, _, err = run(
        capsys, "validate", str(covert_path), "--now", NOW, "--policy", str(missing)
    )
    assert code == 2
    assert err.startswith("error: ")


def test_a_nonconforming_policy_bundle_exits_two(capsys, covert_path, tmp_path):
    """A.4: the bundle carries rules JSON Schema cannot enforce, so it is itself
    schema-checked before it is allowed anywhere near a gate."""
    bogus = write_package(tmp_path / "bad-policy.json", {"policy-id": "nonsense"})
    code, _, err = run(
        capsys, "validate", str(covert_path), "--now", NOW, "--policy", str(bogus)
    )
    assert code == 2
    assert "does not conform" in err


def test_a_stricter_policy_bundle_changes_the_gate_result(
    capsys, covert_path, example_tree
):
    """The risk choices live in the bundle, so swapping it must change the answer."""
    strict = example_tree / "policy-strict.json"
    default_code, _, _ = run(capsys, "gate", str(covert_path), "--now", NOW)
    strict_code, strict_out, _ = run(
        capsys, "gate", str(covert_path), "--now", NOW, "--policy", str(strict)
    )
    assert default_code == 0
    assert strict_code != 0
    assert "meaf-example-strict" in strict_out


def test_injecting_now_makes_output_reproducible(capsys, covert_path):
    """A.5 level 6: a second evaluator using the same package and policy must
    reach the same result, which is only checkable if the instant is an input."""
    _, first, _ = run(capsys, "summary", str(covert_path), "--now", NOW, "--json")
    _, second, _ = run(capsys, "summary", str(covert_path), "--now", NOW, "--json")
    assert first == second
    assert json.loads(first)["evaluated-at"] == NOW


def test_a_later_evaluation_instant_ages_the_same_evidence_out(capsys, covert_path):
    """Freshness is a property of the instant, not of the package.

    The counterfactual run declares a 30 day window, so evaluating it three
    months later must change the gate even though no byte of the package moved.
    """
    fresh_code, _, _ = run(capsys, "gate", str(covert_path), "--now", NOW)
    stale_code, stale_out, _ = run(
        capsys, "gate", str(covert_path), "--now", "2026-12-01T00:00:00Z"
    )
    assert fresh_code == 0
    assert stale_code != 0
    assert "indeterminate" in stale_out


def test_an_unknown_subcommand_is_rejected_by_the_parser(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["not-a-command"])
    assert exit_info.value.code == 2
