"""Migration has to be honest about the difference between derived and guessed.

A 1.0.0 package was authored by people who never answered the questions 2.0.0
asks: how bad is this attack path, does this control fail open, which system of
record produced this evidence. The migration can restructure what is there. It
cannot know what is not. These tests exist to keep the second half true, because
a migration that fills the gaps with plausible defaults produces a package that
validates cleanly and is quietly wrong about somebody's risk position.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from meaf.migrate import (
    SOURCE_VERSION,
    TARGET_VERSION,
    MigrationReport,
    format_report,
    migrate_package,
)
from meaf.validator import load_schema, validate_l1_syntactic
from tests.conftest import EXAMPLES

LEGACY_PACKAGE = EXAMPLES / "legacy" / "covert-influence-1.0.0.json"

#: Fields the migration cannot derive, transcribed from the 2.0.0 schema's
#: required members rather than from a migration run. Every one is a judgment:
#: how severe the path is, whether the control fails open, what the detector's
#: known failure modes are. See
#: ``test_level_1_names_exactly_the_fields_the_report_defers_to_a_human``.
UNDECIDABLE_FIELDS = {
    # attack path
    "impact",
    # component
    "provider",
    # control implementation
    "enforcement-mode",
    "failure-behavior",
    # assurance contract
    "failure-action",
    # threat
    "stage",
    "preconditions",
    "target",
    # temporal profile
    "persistence",
    "activation-latency",
    "dormancy",
    "detection-horizon",
    "reversibility",
    "recovery-objective",
    # test
    "adversarial",
    "evidence-class",
    # evidence
    "source",
    # probabilistic evidence metadata
    "evaluator-prompt-digest",
    "known-failure-modes",
    "escalation-path",
}


#: What a 1.0.0 finding and a 1.0.0 decision lose when their vocabulary has no
#: 2.0.0 equivalent. An unmappable gate verdict costs the decision type too: the
#: migration only types a decision as an authorization when it could read the
#: verdict, and inferring the type from an unreadable verdict would be the same
#: guess one step removed.
UNDECIDABLE_JUDGMENTS = {"severity", "gate-decision", "decision-type"}


@pytest.fixture(scope="session")
def _legacy_source() -> Any:
    with LEGACY_PACKAGE.open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def legacy(_legacy_source: Any) -> dict[str, Any]:
    """The shipped 1.0.0 package, the only input the migration accepts."""
    return copy.deepcopy(_legacy_source)


@pytest.fixture
def legacy_with_local_vocabulary(legacy: dict[str, Any]) -> dict[str, Any]:
    """The shipped package carrying a severity and a gate verdict 2.0.0 cannot read.

    The shipped 1.0.0 document has no findings and one cleanly mappable decision,
    so on its own it never reaches the branches that have to drop a value. A real
    package under remediation carries both: local severity ladders ("Sev-1") and
    local gate vocabulary ("approved pending board ratification") were exactly
    what 1.0.0 permitted, and the closest 2.0.0 word is a guess about how bad
    something is and about whether it was authorised.
    """
    legacy["findings"] = [
        {
            "id": "finding-symmetry-regression-001",
            "failed-claim": "ac-epistemic-integrity-001",
            "severity": "Sev-1",
            "status": "open",
            "affected-paths": ["path-covert-influence-001"],
            "root-cause": (
                "Source-inclusion asymmetry exceeded its bound after the corpus refresh."
            ),
            "corrective-action": (
                "Rebalance the retrieval corpus and rerun the paired counterfactual pack."
            ),
            "due-date": "2026-09-30",
            "retest-reference": "test-counterfactual-symmetry-001",
        }
    ]
    by_id(legacy["decisions"], "dec-gate-2026-07")["gate-decision"] = (
        "approved-pending-board-ratification"
    )
    return legacy


def by_id(collection: list[dict[str, Any]], object_id: str) -> dict[str, Any]:
    matches = [item for item in collection if item.get("id") == object_id]
    assert len(matches) == 1, f"expected exactly one {object_id!r}, found {len(matches)}"
    return matches[0]


def missing_required_fields(findings: list[Any]) -> set[str]:
    """Field names from jsonschema's "'x' is a required property" messages."""
    names: set[str] = set()
    for finding in findings:
        assert finding.message.endswith("is a required property"), (
            f"unexpected level 1 error that is not a missing field: {finding.message}"
        )
        names.add(finding.message.split("'")[1])
    return names


# --------------------------------------------------------------------------
# Input contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version",
    [TARGET_VERSION, "0.1.0", "1.0.1", "1.0", None],
)
def test_migration_refuses_a_package_that_is_not_the_source_version(legacy, version):
    if version is None:
        legacy.pop("meaf-version")
    else:
        legacy["meaf-version"] = version

    with pytest.raises(ValueError, match=SOURCE_VERSION):
        migrate_package(legacy)


def test_migration_refuses_input_that_is_not_a_package_at_all():
    with pytest.raises(ValueError, match="not a JSON object"):
        migrate_package(["assurance-contracts"])


def test_the_migrated_package_declares_the_target_version(legacy):
    migrated, _ = migrate_package(legacy)

    assert migrated["meaf-version"] == TARGET_VERSION


def test_migration_does_not_mutate_the_input_package(legacy):
    """A migration that edits its input cannot be re-run or compared against.

    The 1.0.0 document is the only record of what the organisation actually
    asserted before the migration, so it has to survive the migration intact.
    """
    before = copy.deepcopy(legacy)

    migrate_package(legacy)

    assert legacy == before


# --------------------------------------------------------------------------
# The structural half: what the migration can derive
# --------------------------------------------------------------------------


def test_every_contract_yields_one_control_implementation(legacy):
    # A.3: "Every control implementation is paired with an assurance contract."
    # 1.0.0 had one object doing both jobs, so the split is one-for-one.
    migrated, report = migrate_package(legacy)

    assert len(migrated["control-implementations"]) == len(legacy["assurance-contracts"])
    assert [control["id"] for control in migrated["control-implementations"]] == [
        "ctl-epistemic-integrity-001",
        "ctl-containment-001",
    ]
    assert any("ctl-epistemic-integrity-001 split out of" in line for line in report.derived)


def test_each_contract_points_at_the_control_split_out_of_it(legacy):
    migrated, _ = migrate_package(legacy)

    controls = {control["id"] for control in migrated["control-implementations"]}
    for contract in migrated["assurance-contracts"]:
        assert contract["control"] in controls
    assert by_id(migrated["assurance-contracts"], "ac-containment-001")["control"] == (
        "ctl-containment-001"
    )


@pytest.mark.parametrize("field", ["interruption-point", "interruption-type"])
def test_the_interruption_moves_from_the_contract_to_the_control(legacy, field):
    """A.3 puts the path mapping on the control, not on the contract.

    The contract says how the mitigation is verified; the control says where and
    how the mitigation interrupts the path. Leaving a copy on the contract is
    what made the two objects indistinguishable in 1.0.0.
    """
    source_contract = by_id(legacy["assurance-contracts"], "ac-epistemic-integrity-001")
    migrated, _ = migrate_package(legacy)

    contract = by_id(migrated["assurance-contracts"], "ac-epistemic-integrity-001")
    control = by_id(migrated["control-implementations"], "ctl-epistemic-integrity-001")

    assert field not in contract
    assert control[field] == source_contract[field]


def test_the_control_inherits_the_paths_of_the_contracts_threats(legacy):
    migrated, _ = migrate_package(legacy)

    control = by_id(migrated["control-implementations"], "ctl-epistemic-integrity-001")

    assert control["attack-paths"] == ["path-covert-influence-001"]


def test_evidence_classes_are_derived_from_the_required_evidence(legacy):
    migrated, report = migrate_package(legacy)

    assert by_id(migrated["assurance-contracts"], "ac-epistemic-integrity-001")[
        "evidence-classes"
    ] == ["probabilistic-inference"]
    assert by_id(migrated["assurance-contracts"], "ac-containment-001")[
        "evidence-classes"
    ] == ["deterministic-observation"]
    assert any("evidence-classes derived" in line for line in report.derived)


def test_evidence_classes_cover_every_class_the_contract_relies_on(legacy):
    contract = by_id(legacy["assurance-contracts"], "ac-epistemic-integrity-001")
    contract["required-evidence"].append("ev-model-attestation")

    migrated, _ = migrate_package(legacy)

    assert by_id(migrated["assurance-contracts"], "ac-epistemic-integrity-001")[
        "evidence-classes"
    ] == ["deterministic-observation", "probabilistic-inference"]


@pytest.mark.parametrize(
    ("contract_id", "additional_evidence"),
    [
        # P30D contract widened with a P90D item, and the reverse, so that a
        # migration picking the first or the last window fails one of the two.
        ("ac-epistemic-integrity-001", "ev-model-attestation"),
        ("ac-containment-001", "ev-counterfactual-run-2026-07"),
    ],
)
def test_evidence_max_age_is_the_shortest_window_among_the_required_evidence(
    legacy, contract_id, additional_evidence
):
    """A contract may tighten freshness relative to its evidence, never loosen it.

    A.5 makes currency a per-evidence predicate, so a contract that accepted the
    longest of its windows would treat an item as current past the point its own
    collector said it stops meaning anything.
    """
    by_id(legacy["assurance-contracts"], contract_id)["required-evidence"].append(
        additional_evidence
    )

    migrated, report = migrate_package(legacy)

    assert by_id(migrated["assurance-contracts"], contract_id)["evidence-max-age"] == "P30D"
    assert any(
        f"{contract_id}/evidence-max-age set to P30D" in line for line in report.derived
    )


def test_prose_failure_actions_are_preserved_rather_than_mapped_to_an_enum(legacy):
    """The six enumerated actions are not a superset of what 1.0.0 recorded.

    "suspend-high-impact-recommendations-and-require-independent-review" is not
    one of them, and choosing the nearest is choosing what the system does when
    the control fails. The prose is kept so the decision can be made from it.
    """
    source = by_id(legacy["assurance-contracts"], "ac-epistemic-integrity-001")
    migrated, report = migrate_package(legacy)

    contract = by_id(migrated["assurance-contracts"], "ac-epistemic-integrity-001")

    assert "failure-action" not in contract
    assert contract["failure-action-detail"] == source["failure-action"]
    assert any(
        "ac-epistemic-integrity-001/failure-action" in line for line in report.manual
    )


# --------------------------------------------------------------------------
# The honest half: what the migration refuses to invent
# --------------------------------------------------------------------------


def test_the_migrated_package_does_not_yet_pass_level_1(legacy):
    """Failing validation is the intended outcome, not a defect in the migration.

    The alternative is a package that validates because the migration answered
    the risk questions on the organisation's behalf.
    """
    migrated, report = migrate_package(legacy)

    findings = validate_l1_syntactic(migrated, load_schema())

    assert findings
    assert not report.complete
    assert report.manual


def test_level_1_names_exactly_the_fields_the_report_defers_to_a_human(legacy):
    """The validator's gap list and the migration's decision list must agree.

    If level 1 named a field the report did not, the migration would have left a
    hole nobody was told about. If the report named a missing field level 1 did
    not, the schema would be accepting a package with an unanswered risk
    question in it.
    """
    migrated, report = migrate_package(legacy)

    findings = validate_l1_syntactic(migrated, load_schema())
    missing = missing_required_fields(findings)

    assert missing == UNDECIDABLE_FIELDS
    deferred = "\n".join(report.manual)
    for field in sorted(missing):
        assert field in deferred, f"level 1 reports {field!r} but the report never mentions it"


@pytest.mark.parametrize(
    ("object_id", "field"),
    [
        # A.5 level 5 keys interruption requirements off path impact, so the
        # rating decides how much coverage the path is required to carry.
        ("path-covert-influence-001", "impact"),
        # A.2: a control implementation states "enforcement mode; failure
        # behavior". Whether a guardrail fails open is the first thing an
        # incident responder asks and the last thing a tool should assume.
        ("ctl-epistemic-integrity-001", "enforcement-mode"),
        ("ctl-epistemic-integrity-001", "failure-behavior"),
        # A.2's threat tuple positions that 1.0.0 never carried.
        ("thr-covert-influence-001", "stage"),
        ("thr-covert-influence-001", "preconditions"),
        ("thr-covert-influence-001", "target"),
        # A.2: evidence records the "source" it came from; attribution cannot be
        # reconstructed from the 1.0.0 document.
        ("ev-counterfactual-run-2026-07", "source"),
    ],
)
def test_the_report_defers_each_risk_judgment_to_its_owner(legacy, object_id, field):
    _, report = migrate_package(legacy)

    assert any(
        object_id in line and field in line for line in report.manual
    ), f"nothing in the report asks a human to decide {object_id}/{field}"


def test_the_report_requires_evidence_to_be_re_signed(legacy):
    """The signed payload changed, so a 1.0.0 signature no longer attests to it.

    Carrying the old signature forward would leave evidence that verifies
    against a payload nobody signed.
    """
    _, report = migrate_package(legacy)

    signed = [item["id"] for item in legacy["evidence"] if "signature" in item]
    assert signed
    for evidence_id in signed:
        assert any(
            f"evidence/{evidence_id}/signature" in line and "re-signed" in line
            for line in report.manual
        )


def test_undecidable_fields_are_absent_rather_than_filled_with_a_default(legacy):
    """Omission is not the same as a placeholder value.

    A migrated package carrying ``"impact": "medium"`` would pass level 1 and
    put a number on somebody's risk register that nobody chose. An absent field
    is reported by the validator and has to be answered.
    """
    migrated, _ = migrate_package(legacy)

    assert "impact" not in by_id(migrated["attack-paths"], "path-covert-influence-001")
    control = by_id(migrated["control-implementations"], "ctl-epistemic-integrity-001")
    assert "enforcement-mode" not in control
    assert "failure-behavior" not in control
    threat = by_id(migrated["threats"], "thr-covert-influence-001")
    assert {"stage", "preconditions", "target"}.isdisjoint(threat)
    assert "source" not in by_id(migrated["evidence"], "ev-counterfactual-run-2026-07")


def test_an_unreadable_finding_severity_is_dropped_rather_than_downgraded(
    legacy_with_local_vocabulary,
):
    """A guessed severity is a risk rating nobody chose, on somebody's register.

    The module states the rule: "Where it cannot, the field is omitted rather
    than filled with a plausible default." Severity is the field where a default
    does the most damage, because "Sev-1" quietly becoming "low" leaves a package
    that passes level 1, migrates with a complete-looking report, and understates
    an open failure to everyone downstream who reads it.
    """
    migrated, report = migrate_package(legacy_with_local_vocabulary)

    finding = by_id(migrated["findings"], "finding-symmetry-regression-001")
    assert "severity" not in finding
    # Everything the migration could carry across is still there, so the omission
    # reads as one unanswered question rather than as a dropped finding.
    assert finding["failed-claim"] == "ac-epistemic-integrity-001"
    assert finding["status"] == "open"
    assert any(
        "findings/finding-symmetry-regression-001/severity" in line
        and "'Sev-1'" in line
        for line in report.manual
    )


def test_an_unreadable_gate_verdict_leaves_the_decision_untyped_rather_than_authorized(
    legacy_with_local_vocabulary,
):
    """A.1 principle 5: "Automation does not silently accept residual risk."

    A migration that read "approved-pending-board-ratification" as ``approve``
    would have recorded an authorization that the board had not yet granted, and
    typed it as one. Both the verdict and the type are therefore left for the
    human who knows what the ratification did.
    """
    migrated, report = migrate_package(legacy_with_local_vocabulary)

    decision = by_id(migrated["decisions"], "dec-gate-2026-07")
    assert "gate-decision" not in decision
    assert "decision-type" not in decision
    assert decision["decision-maker"] == "ai-assurance-review-board"
    assert any(
        "decisions/dec-gate-2026-07/gate-decision" in line
        and "'approved-pending-board-ratification'" in line
        for line in report.manual
    )
    assert any(
        "decisions/dec-gate-2026-07/decision-type" in line for line in report.manual
    )
    assert not any("typed as an authorization" in line for line in report.derived)


def test_level_1_names_the_dropped_judgments_and_nothing_was_defaulted(
    legacy_with_local_vocabulary,
):
    """The same agreement as for the shipped fixture, now with both branches taken.

    Level 1 has to name the two fields the migration dropped, and only those on
    top of the gaps the shipped package already leaves. A field that came out
    defaulted would be absent from this list, which is the whole point: the
    validator is what makes an omission visible, and a guess is invisible to it.
    """
    migrated, report = migrate_package(legacy_with_local_vocabulary)

    missing = missing_required_fields(validate_l1_syntactic(migrated, load_schema()))

    assert missing == UNDECIDABLE_FIELDS | UNDECIDABLE_JUDGMENTS
    deferred = "\n".join(report.manual)
    for field in sorted(UNDECIDABLE_JUDGMENTS):
        assert field in deferred, f"level 1 reports {field!r} but the report is silent"


@pytest.mark.parametrize(
    ("recorded", "expected"),
    [
        ("critical", "critical"),
        # 1.0.0 packages that used a four-word ladder are renamed, not re-rated.
        ("moderate", "medium"),
        ("Low", "low"),
    ],
)
def test_a_severity_the_2_0_0_ladder_can_read_is_carried_across_unchanged(
    legacy_with_local_vocabulary, recorded: str, expected: str
):
    by_id(legacy_with_local_vocabulary["findings"], "finding-symmetry-regression-001")[
        "severity"
    ] = recorded

    migrated, report = migrate_package(legacy_with_local_vocabulary)

    assert by_id(migrated["findings"], "finding-symmetry-regression-001")[
        "severity"
    ] == expected
    assert not any(
        "finding-symmetry-regression-001/severity" in line for line in report.manual
    )


def test_a_gate_verdict_the_migration_can_read_types_the_decision_as_an_authorization(
    legacy,
):
    """Monitoring is a condition, so the shipped verdict is a rename, not a rating.

    The type is derived only in this branch, which is why it is asserted here and
    left absent in the branch above: 2.0.0 needs to know whether a decision
    authorises, excepts or declares out of scope, and only a readable verdict
    says so.
    """
    migrated, report = migrate_package(legacy)

    decision = by_id(migrated["decisions"], "dec-gate-2026-07")
    assert decision["gate-decision"] == "approve-with-conditions"
    assert decision["decision-type"] == "authorization"
    assert any(
        "decisions/dec-gate-2026-07 typed as an authorization with verdict "
        "approve-with-conditions" in line
        for line in report.derived
    )


def test_unmappable_temporal_prose_is_dropped_and_reported(legacy):
    """1.0.0 recorded temporal fields as prose that spans two 2.0.0 enum values.

    "model-version-or-corpus-snapshot" is a choice between two persistence
    tiers, and the migration is not the party entitled to make it.
    """
    migrated, report = migrate_package(legacy)

    profile = by_id(migrated["threats"], "thr-covert-influence-001")["temporal-profile"]

    assert "persistence" not in profile
    assert "reversibility" not in profile
    # The fields whose 1.0.0 prose does map unambiguously are carried across.
    assert profile["compounding-rule"] == "cumulative"
    assert profile["exposure-unit"] == "turn"
    assert any("temporal-profile/persistence" in line for line in report.manual)


def test_the_formatted_report_states_why_gaps_were_left_open(legacy):
    _, report = migrate_package(legacy)

    text = format_report(report)

    assert "omitted rather than guessed" in text
    assert f"Requires a human decision ({len(report.manual)})" in text
    assert all(item in text for item in report.manual)


def test_an_empty_report_is_complete():
    """``complete`` tracks the decision list, not the derivation list."""
    assert MigrationReport(derived=["something"], manual=[]).complete
    assert not MigrationReport(derived=[], manual=["decide this"]).complete
