"""The conformance summary is the framework's answer to "how are we doing?".

Two things make it worth testing carefully. First, appendix A.5 enumerates the
dimensions a conforming summary must report, so an implementation that quietly
drops one still calls itself conforming while answering a different question.
Second, and more importantly, A.5 refuses to define an aggregate score, and a
refusal is only real if something enforces it. The test named for that refusal
is the reason this file exists.

Every assertion here is made at :data:`FROZEN_NOW` or :data:`STALE_NOW`, because
freshness and exception age are the two dimensions whose answer changes with the
calendar and a summary that passes only in July is not a summary.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime
from typing import Any

import pytest

from meaf.contract import evaluate_contracts
from meaf.summary import SUMMARY_DIMENSIONS, conformance_summary, format_summary
from tests.conftest import FROZEN_NOW, STALE_NOW

#: A.5: "A conforming summary reports at least: threat-model completeness,
#: path-interruption coverage, control-test status, evidence freshness, open
#: findings by severity, recovery readiness, probabilistic-evidence dependence,
#: and exception age." Transcribed from the manuscript, in the manuscript's
#: order, so that a rename in the implementation fails here.
A5_DIMENSIONS = (
    "threat-model-completeness",
    "path-interruption-coverage",
    "control-test-status",
    "evidence-freshness",
    "open-findings-by-severity",
    "recovery-readiness",
    "probabilistic-evidence-dependence",
    "exception-age",
)

#: The heading each dimension is given in the human-readable rendering.
DIMENSION_HEADINGS = {
    "threat-model-completeness": "Threat-model completeness",
    "path-interruption-coverage": "Path-interruption coverage",
    "control-test-status": "Control-test status",
    "evidence-freshness": "Evidence freshness",
    "open-findings-by-severity": "Open findings by severity",
    "recovery-readiness": "Recovery readiness",
    "probabilistic-evidence-dependence": "Probabilistic dependence",
    "exception-age": "Exception age",
}

#: The members a summary carries besides the eight dimensions: what it is about,
#: when it was computed, and under which bundle. Pinned exactly, because a ninth
#: top-level member is how an aggregate would arrive.
SUMMARY_PREAMBLE = {"package-id", "evaluated-at", "policy"}

#: The fields each dimension reports, transcribed from a run against both shipped
#: examples at both evaluation instants. Pinned exactly so that an aggregate
#: smuggled one level down -- where the top-level key set cannot see it -- fails
#: here instead of shipping.
DIMENSION_FIELDS = {
    "threat-model-completeness": {
        "threats-declared",
        "threats-with-contracts",
        "threats-without-contracts",
        "threats-persisting-beyond-session",
    },
    "path-interruption-coverage": {"paths-declared", "paths-fully-covered", "by-path"},
    "control-test-status": {
        "contracts-declared",
        "by-state",
        "failing",
        "indeterminate",
    },
    "evidence-freshness": {
        "evidence-items",
        "current",
        "not-current",
        "gating-evidence-items",
    },
    "open-findings-by-severity": {"open-by-severity", "open-ids-by-severity"},
    "recovery-readiness": {
        "recovery-controls",
        "verified-recovery-contracts",
        "unverified-recovery-contracts",
        "paths-without-recovery-control",
    },
    "probabilistic-evidence-dependence": {
        "gating-contracts",
        "gating-contracts-depending-on-inference",
        "probabilistic-evidence-items",
        "share-of-gating-contracts",
    },
    "exception-age": {"exceptions", "expired-exceptions"},
}

#: Words that name an aggregate verdict rather than an observation. Whole words
#: only: "degraded" is a lifecycle state and "degrade-privileges" a failure
#: action, and neither of them is a grade. The second half of the alternation is
#: the vocabulary a dashboard reaches for once "score" has been ruled out --
#: "assurance index", "risk band", "composite" -- and it is here because ruling
#: out one word and not its synonyms is not a refusal.
SCORE_LIKE_WORDS = re.compile(
    r"\b(scores?|grades?|grading|ratings?|overall|total-score|posture"
    r"|aggregates?|composite|index|indices|percentile|band|verdict)\b",
    re.IGNORECASE,
)

#: The rendering's fixed layout: one title line, a blank, the eight dimension
#: lines, a blank, then the two-line refusal paragraph. Everything after that is
#: an unresolved item.
TITLE_LINE = 0
FIRST_DIMENSION_LINE = 2
REFUSAL_LINE = 11
FIRST_UNRESOLVED_LINE = 13


def obj(package: Any, collection: str, object_id: str) -> dict[str, Any]:
    """The single member of ``collection`` with this identifier."""
    for item in package[collection]:
        if item.get("id") == object_id:
            return item
    raise AssertionError(f"{object_id} is not in {collection}")


def walk(node: Any, path: str = "") -> list[tuple[str, Any]]:
    """Every (path, value) pair in a nested structure, keys included as paths."""
    found: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}/{key}"
            found.append((child, key))
            found.extend(walk(value, child))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(walk(value, f"{path}[{index}]"))
    else:
        found.append((path, node))
    return found


def rendered_body(text: str) -> list[str]:
    """Every line of the rendering except the paragraph that states the refusal.

    That paragraph is the one place in the output where the words "aggregate"
    and "score" belong, so it is excluded rather than special-cased inside the
    pattern, which would let the same wording through anywhere else.
    """
    lines = text.splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("No aggregate score is reported")
    )
    return lines[:start] + lines[start + 2 :]


@pytest.fixture
def covert_summary(covert: dict[str, Any]) -> dict[str, Any]:
    return conformance_summary(covert, now=FROZEN_NOW)


@pytest.fixture
def memory_summary(memory: dict[str, Any]) -> dict[str, Any]:
    return conformance_summary(memory, now=FROZEN_NOW)


def test_the_declared_dimensions_are_the_eight_the_manuscript_names():
    assert SUMMARY_DIMENSIONS == A5_DIMENSIONS


@pytest.mark.parametrize("dimension", A5_DIMENSIONS)
def test_every_dimension_is_reported_under_its_declared_key(covert_summary, dimension):
    # "Reports at least" is a floor, but the key has to be the declared one or a
    # second implementation cannot read the summary this one produces.
    assert dimension in covert_summary
    assert covert_summary[dimension] != {}


def test_the_summary_states_the_instant_and_the_policy_it_was_computed_under(
    covert_summary,
):
    # A.5 closes with "decisions are conditional on ... evidence freshness and
    # acceptance policy" (A.1). A summary that does not say which instant and
    # which bundle produced it cannot be compared with another one.
    assert covert_summary["evaluated-at"] == "2026-07-28T12:00:00Z"
    assert covert_summary["policy"] == "meaf-default:2.0.0"
    assert covert_summary["package-id"] == "pkg-covert-influence-research-agent"


# ---------------------------------------------------------------------------
# The refusal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("package_fixture", "now"),
    [
        ("covert", FROZEN_NOW),
        ("covert", STALE_NOW),
        ("memory", FROZEN_NOW),
        ("memory", STALE_NOW),
    ],
)
def test_no_part_of_the_summary_looks_like_an_aggregate_score(
    request, package_fixture: str, now: datetime
):
    """A.5's refusal, enforced.

        MEAF intentionally does not define a universal aggregate security score.
        A single number conceals whether weak assurance comes from missing
        threats, uncovered paths, stale evidence, failed tests, or accepted
        residual risk.

    This test exists because the pressure to add "overall: 84%" to a security
    dashboard is constant and comes from people who will not read the eight
    dimensions. The first such field would be added here, to the summary that
    everything else projects from, and every consumer downstream would then have
    a number to sort by. Deleting this test is the only honest way to add one,
    and that is the point: it forces the change to be argued rather than slipped
    in. Both evaluation instants are covered so that the stale-evidence branches
    of the structure, which only appear when something has aged out, are walked
    too.
    """
    package = request.getfixturevalue(package_fixture)
    summary = conformance_summary(package, now=now)

    offenders = [
        (path, value)
        for path, value in walk(summary)
        if isinstance(value, str) and SCORE_LIKE_WORDS.search(value)
    ]
    assert offenders == []


@pytest.mark.parametrize(
    ("package_fixture", "now"),
    [
        ("covert", FROZEN_NOW),
        ("covert", STALE_NOW),
        ("memory", FROZEN_NOW),
        ("memory", STALE_NOW),
    ],
)
def test_the_summary_carries_the_eight_dimensions_and_no_ninth_member(
    request, package_fixture: str, now: datetime
):
    """A.5's list is a floor for what must be there and a ceiling for what a score
    can hide behind.

        MEAF intentionally does not define a universal aggregate security score.

    Naming the forbidden words is not enough on its own: an aggregate arriving as
    ``"assurance-index": {"value": 0.84, "band": "amber"}`` is a single number
    about the package whatever it is called, and a word list can always be
    stepped around by renaming. Pinning the member set exactly means a new
    top-level field has to be argued for here before any consumer can sort by it.
    """
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=now)

    assert set(summary) == SUMMARY_PREAMBLE | set(A5_DIMENSIONS)


@pytest.mark.parametrize("dimension", A5_DIMENSIONS)
def test_each_dimension_reports_its_declared_fields_and_nothing_else(
    covert_summary, memory_summary, dimension: str
):
    """The same ceiling one level down, where a top-level key set cannot see.

    A dimension is where an aggregate would hide most comfortably, because it
    would arrive next to the counts that dimension legitimately reports and read
    as one of them.
    """
    assert set(covert_summary[dimension]) == DIMENSION_FIELDS[dimension]
    assert set(memory_summary[dimension]) == DIMENSION_FIELDS[dimension]


def test_the_summary_reports_counts_and_identifiers_rather_than_a_verdict(
    covert_summary,
):
    """Nothing at the top level is a bare number standing for the whole package.

    The dimensions may contain numbers, and do: counts, day totals, and one
    ratio scoped to a single dimension. What A.5 forbids is a number *about the
    package*, so the check is on the top level, where such a field would live.
    """
    top_level_numbers = {
        key: value
        for key, value in covert_summary.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    assert top_level_numbers == {}


# ---------------------------------------------------------------------------
# Threat-model completeness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_every_example_threat_has_a_contract(request, package_fixture: str):
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=FROZEN_NOW)
    completeness = summary["threat-model-completeness"]
    assert completeness["threats-declared"] == 1
    assert completeness["threats-with-contracts"] == 1
    assert completeness["threats-without-contracts"] == []


def test_a_threat_no_contract_names_is_counted_as_uncovered(covert):
    # A.5 level 5: "required threats have assurance contracts". A threat nobody
    # contracted to verify is the gap the dimension exists to surface.
    orphan = copy.deepcopy(obj(covert, "threats", "thr-covert-influence-001"))
    orphan["id"] = "thr-unverified-002"
    covert["threats"].append(orphan)

    completeness = conformance_summary(covert, now=FROZEN_NOW)["threat-model-completeness"]
    assert completeness["threats-declared"] == 2
    assert completeness["threats-with-contracts"] == 1
    assert completeness["threats-without-contracts"] == ["thr-unverified-002"]


def test_threats_that_outlive_a_session_are_called_out(covert, memory):
    # The temporal profile is the manuscript's central claim about long-running
    # agents, so a summary that never mentions persistence loses it.
    covert_completeness = conformance_summary(covert, now=FROZEN_NOW)[
        "threat-model-completeness"
    ]
    memory_completeness = conformance_summary(memory, now=FROZEN_NOW)[
        "threat-model-completeness"
    ]
    assert covert_completeness["threats-persisting-beyond-session"] == [
        "thr-covert-influence-001"
    ]
    assert memory_completeness["threats-persisting-beyond-session"] == [
        "thr-memory-to-goal-001"
    ]


def test_a_session_scoped_threat_is_not_called_out_as_persisting(covert):
    threat = obj(covert, "threats", "thr-covert-influence-001")
    threat["temporal-profile"]["persistence"] = "session"
    completeness = conformance_summary(covert, now=FROZEN_NOW)["threat-model-completeness"]
    assert completeness["threats-persisting-beyond-session"] == []


# ---------------------------------------------------------------------------
# Path-interruption coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("package_fixture", "path_id", "expected_types"),
    [
        ("covert", "path-covert-influence-001", ["contains", "detects"]),
        ("memory", "path-memory-to-goal-001", ["blocks", "restores"]),
    ],
)
def test_a_covered_path_satisfies_both_halves_of_its_tier(
    request, package_fixture: str, path_id: str, expected_types: list[str]
):
    # A.3: "For each high-impact path, deployment policy should require at least
    # one currently verified control before the harmful outcome and one verified
    # containment or recovery mechanism." Both examples are high impact and
    # carry exactly that pair.
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=FROZEN_NOW)
    coverage = summary["path-interruption-coverage"]
    assert coverage["paths-declared"] == 1
    assert coverage["paths-fully-covered"] == 1
    entry = coverage["by-path"][0]
    assert entry["path"] == path_id
    assert entry["impact"] == "high"
    assert entry["interruption-types"] == expected_types
    assert entry["before-outcome-satisfied"] is True
    assert entry["recovery-satisfied"] is True


def test_a_path_with_no_recovery_control_is_marked_unsatisfied(covert):
    covert["control-implementations"] = [
        control
        for control in covert["control-implementations"]
        if control["id"] != "ctl-high-impact-recommendation-hold"
    ]
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-high-impact-recommendation-hold"
    ]

    coverage = conformance_summary(covert, now=FROZEN_NOW)["path-interruption-coverage"]
    entry = coverage["by-path"][0]
    assert entry["before-outcome-satisfied"] is True
    assert entry["recovery-satisfied"] is False
    assert coverage["paths-fully-covered"] == 0


def test_a_path_with_only_recovery_is_unsatisfied_before_the_outcome(covert):
    covert["control-implementations"] = [
        control
        for control in covert["control-implementations"]
        if control["id"] != "ctl-counterfactual-symmetry-monitor"
    ]
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-counterfactual-symmetry-monitor"
    ]

    coverage = conformance_summary(covert, now=FROZEN_NOW)["path-interruption-coverage"]
    entry = coverage["by-path"][0]
    assert entry["before-outcome-satisfied"] is False
    assert entry["recovery-satisfied"] is True
    assert coverage["paths-fully-covered"] == 0


@pytest.mark.parametrize(
    ("impact", "expected_satisfied"),
    [
        # The default bundle requires an interruption and a recovery at critical
        # and high, an interruption only at medium, and nothing at low. The same
        # bare path is therefore covered or not depending on what it can cost.
        ("critical", False),
        ("high", False),
        ("medium", False),
        ("low", True),
    ],
)
def test_coverage_is_judged_against_the_tier_the_path_declares(
    covert, impact: str, expected_satisfied: bool
):
    covert["control-implementations"] = []
    covert["assurance-contracts"] = []
    obj(covert, "attack-paths", "path-covert-influence-001")["impact"] = impact

    coverage = conformance_summary(covert, now=FROZEN_NOW)["path-interruption-coverage"]
    entry = coverage["by-path"][0]
    satisfied = entry["before-outcome-satisfied"] and entry["recovery-satisfied"]
    assert satisfied is expected_satisfied


# ---------------------------------------------------------------------------
# Control-test status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_control_test_status_reports_the_evaluated_contract_states(
    request, package_fixture: str
):
    package = request.getfixturevalue(package_fixture)
    states = evaluate_contracts(package, now=FROZEN_NOW)
    status = conformance_summary(package, now=FROZEN_NOW)["control-test-status"]

    assert status["contracts-declared"] == len(states)
    for name in ("pass", "fail", "indeterminate", "not-applicable"):
        assert status["by-state"][name] == sum(1 for s in states if s.state == name)
    assert status["failing"] == sorted(s.contract_id for s in states if s.state == "fail")
    assert status["indeterminate"] == sorted(
        s.contract_id for s in states if s.state == "indeterminate"
    )


def test_the_clean_package_has_no_failing_or_indeterminate_contract(covert_summary):
    status = covert_summary["control-test-status"]
    assert status["by-state"] == {
        "pass": 2,
        "fail": 0,
        "indeterminate": 0,
        "not-applicable": 0,
    }


def test_the_package_under_remediation_names_its_failing_contract(memory_summary):
    status = memory_summary["control-test-status"]
    assert status["by-state"]["fail"] == 1
    assert status["failing"] == ["ac-memory-write-screening-001"]


def test_a_contract_whose_evidence_is_missing_is_reported_indeterminate(covert):
    # A.5: indeterminate covers evidence that is "missing, stale, contradictory
    # ...", and "indeterminate must not be silently coerced to pass", so the
    # summary has to carry it as its own count rather than folding it into fail.
    obj(covert, "assurance-contracts", "ac-epistemic-integrity-001")["required-evidence"] = [
        "ev-never-collected"
    ]
    status = conformance_summary(covert, now=FROZEN_NOW)["control-test-status"]
    assert status["by-state"]["indeterminate"] == 1
    assert status["indeterminate"] == ["ac-epistemic-integrity-001"]
    assert status["by-state"]["fail"] == 0


# ---------------------------------------------------------------------------
# Evidence freshness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("package_fixture", "expected_items"),
    [("covert", 5), ("memory", 4)],
)
def test_all_example_evidence_is_current_at_the_frozen_instant(
    request, package_fixture: str, expected_items: int
):
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=FROZEN_NOW)
    freshness = summary["evidence-freshness"]
    assert freshness["evidence-items"] == expected_items
    assert len(freshness["current"]) == expected_items
    assert freshness["not-current"] == []
    # Two of the items are required by a contract; the rest are provenance
    # evidence that no contract gates on.
    assert freshness["gating-evidence-items"] == 2


def test_a_later_evaluation_instant_moves_evidence_to_not_current(covert):
    # current(e, t) = (t - e.collected_at <= e.max_age) AND ... The package did
    # not change; the instant did, and that alone empties the current list.
    freshness = conformance_summary(covert, now=STALE_NOW)["evidence-freshness"]
    assert freshness["current"] == []
    assert len(freshness["not-current"]) == freshness["evidence-items"]
    assert all(entry["reasons"] for entry in freshness["not-current"])


def test_each_evidence_item_ages_out_on_its_own_declared_window(memory):
    """Freshness is per item, not a single cut-off applied to the package.

    At STALE_NOW the write probe is past its P90D window and the two P180D
    attestations are 183 days old, but the quarantine drill was collected two
    weeks later and its P180D window has not closed. A summary that reported one
    verdict for the package would have to round that away in one direction.
    """
    freshness = conformance_summary(memory, now=STALE_NOW)["evidence-freshness"]
    assert {entry["evidence"] for entry in freshness["not-current"]} == {
        "ev-poison-write-probe-2026-05",
        "ev-memory-store-attestation",
        "ev-planner-graph-attestation",
    }
    assert freshness["current"] == ["ev-memory-quarantine-drill-2026-06"]


def test_freshness_is_measured_against_the_subject_the_contract_claims_about(covert):
    """A.5: "Artifact binding takes precedence over calendar freshness."

    The foundation model is redeployed under a new digest. Every item collected
    against it goes stale in the same instant, however recently it was gathered
    in calendar terms, and for two distinct reasons that the reasons list keeps
    apart:

    * the contracts requiring it claim about a subject that no longer resolves
      to what was measured, and
    * the artifact it was collected against is no longer deployed at all.

    ``ev-model-attestation`` demonstrates the second on its own. No contract
    requires it, so it has no claimed subject to be stale against, yet it is
    still an observation of an artifact that has been replaced. A.5's list --
    "a superseded prompt, adapter, model endpoint, graph, policy, or retrieval
    snapshot" -- makes no exception for evidence nobody is currently citing.
    """
    obj(covert, "components", "cmp-foundation-model")["digest"] = (
        "sha256:" + "9" * 64
    )

    freshness = conformance_summary(covert, now=FROZEN_NOW)["evidence-freshness"]
    not_current = {entry["evidence"]: entry["reasons"] for entry in freshness["not-current"]}

    assert set(not_current) == {
        "ev-counterfactual-run-2026-07",
        "ev-containment-drill-2026-07",
        "ev-model-attestation",
    }
    assert any(
        "not bound to the deployed subject" in reason
        for reason in not_current["ev-counterfactual-run-2026-07"]
    )
    assert any(
        "no longer deployed" in reason
        for reason in not_current["ev-model-attestation"]
    )
    # The corpus and prompt were not touched, so their attestations stand.
    assert set(freshness["current"]) == {
        "ev-corpus-manifest",
        "ev-evaluator-prompt-attestation",
    }


def test_invalidated_evidence_is_not_current_however_recently_collected(covert):
    obj(covert, "evidence", "ev-counterfactual-run-2026-07")["invalidated-at"] = (
        "2026-07-27T00:00:00Z"
    )
    freshness = conformance_summary(covert, now=FROZEN_NOW)["evidence-freshness"]
    entry = next(
        item
        for item in freshness["not-current"]
        if item["evidence"] == "ev-counterfactual-run-2026-07"
    )
    assert any("invalidated" in reason for reason in entry["reasons"])


def test_a_contract_may_tighten_freshness_but_the_evidence_cannot_loosen_it(covert):
    # The counterfactual run declares P30D and is 13 days old. A contract that
    # demands P7D makes the same item stale without touching the item.
    obj(covert, "assurance-contracts", "ac-epistemic-integrity-001")[
        "evidence-max-age"
    ] = "P7D"
    freshness = conformance_summary(covert, now=FROZEN_NOW)["evidence-freshness"]
    assert [entry["evidence"] for entry in freshness["not-current"]] == [
        "ev-counterfactual-run-2026-07"
    ]


# ---------------------------------------------------------------------------
# Open findings by severity
# ---------------------------------------------------------------------------


def test_the_clean_package_has_no_open_findings(covert_summary):
    findings = covert_summary["open-findings-by-severity"]
    assert findings["open-by-severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert findings["open-ids-by-severity"]["high"] == []


def test_an_in_progress_finding_still_counts_as_open(memory_summary):
    findings = memory_summary["open-findings-by-severity"]
    assert findings["open-by-severity"]["high"] == 1
    assert findings["open-ids-by-severity"]["high"] == ["finding-memory-write-screening-001"]


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        # A.5 asks for "open findings by severity". Work in progress is not
        # resolved, and risk that has been accepted is carried by the decision
        # object rather than by the finding, so only the first two count.
        ("open", 1),
        ("in-progress", 1),
        ("resolved", 0),
        ("risk-accepted", 0),
    ],
)
def test_only_unresolved_findings_are_aggregated(memory, status: str, expected: int):
    obj(memory, "findings", "finding-memory-write-screening-001")["status"] = status
    findings = conformance_summary(memory, now=FROZEN_NOW)["open-findings-by-severity"]
    assert findings["open-by-severity"]["high"] == expected


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
def test_findings_are_aggregated_under_the_severity_they_declare(memory, severity: str):
    obj(memory, "findings", "finding-memory-write-screening-001")["severity"] = severity
    findings = conformance_summary(memory, now=FROZEN_NOW)["open-findings-by-severity"]
    assert findings["open-by-severity"][severity] == 1
    assert sum(findings["open-by-severity"].values()) == 1


# ---------------------------------------------------------------------------
# Recovery readiness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("package_fixture", "control_id", "contract_id"),
    [
        ("covert", "ctl-high-impact-recommendation-hold", "ac-containment-001"),
        ("memory", "ctl-memory-quarantine-and-replay", "ac-memory-recovery-001"),
    ],
)
def test_recovery_readiness_names_the_verified_recovery_contract(
    request, package_fixture: str, control_id: str, contract_id: str
):
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=FROZEN_NOW)
    recovery = summary["recovery-readiness"]
    assert recovery["recovery-controls"] == [control_id]
    assert recovery["verified-recovery-contracts"] == [contract_id]
    assert recovery["unverified-recovery-contracts"] == []
    assert recovery["paths-without-recovery-control"] == []


def test_a_recovery_contract_that_does_not_pass_is_reported_unverified(covert):
    """A.7's recovery-readiness pack is about demonstration, not declaration.

    A containment control whose drill failed is still a containment control, so
    it stays in ``recovery-controls``; what changes is that the package can no
    longer claim it works. Reporting the two separately is the difference
    between "we have no recovery" and "our recovery is untested".
    """
    obj(covert, "evidence", "ev-containment-drill-2026-07")["result"] = "fail"

    recovery = conformance_summary(covert, now=FROZEN_NOW)["recovery-readiness"]
    assert recovery["recovery-controls"] == ["ctl-high-impact-recommendation-hold"]
    assert recovery["verified-recovery-contracts"] == []
    assert recovery["unverified-recovery-contracts"] == ["ac-containment-001"]


def test_a_stale_recovery_drill_is_reported_unverified(covert):
    recovery = conformance_summary(covert, now=STALE_NOW)["recovery-readiness"]
    assert recovery["unverified-recovery-contracts"] == ["ac-containment-001"]
    assert recovery["verified-recovery-contracts"] == []


def test_a_path_with_no_recovery_control_at_all_is_named(covert):
    covert["control-implementations"] = [
        control
        for control in covert["control-implementations"]
        if control["id"] != "ctl-high-impact-recommendation-hold"
    ]
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-high-impact-recommendation-hold"
    ]

    recovery = conformance_summary(covert, now=FROZEN_NOW)["recovery-readiness"]
    assert recovery["recovery-controls"] == []
    assert recovery["paths-without-recovery-control"] == ["path-covert-influence-001"]


# ---------------------------------------------------------------------------
# Probabilistic-evidence dependence
# ---------------------------------------------------------------------------


def test_probabilistic_dependence_reports_the_share_of_gating_contracts(covert_summary):
    # A.5: "an LLM-generated judgment is not deterministic telemetry. When such
    # a judgment contributes to a gate..." The dimension is about contracts that
    # gate, so the denominator is gating contracts and not all contracts.
    dependence = covert_summary["probabilistic-evidence-dependence"]
    assert dependence["gating-contracts"] == 2
    assert dependence["gating-contracts-depending-on-inference"] == [
        "ac-epistemic-integrity-001"
    ]
    assert dependence["probabilistic-evidence-items"] == ["ev-counterfactual-run-2026-07"]
    assert dependence["share-of-gating-contracts"] == 0.5


def test_a_package_with_no_inference_reports_a_zero_share(memory_summary):
    dependence = memory_summary["probabilistic-evidence-dependence"]
    assert dependence["gating-contracts"] == 2
    assert dependence["gating-contracts-depending-on-inference"] == []
    assert dependence["probabilistic-evidence-items"] == []
    assert dependence["share-of-gating-contracts"] == 0.0


def not_applicable_decision(package: Any, contract_id: str) -> dict[str, Any]:
    """A live, named, scoped not-applicable decision for one contract."""
    decision = copy.deepcopy(package["decisions"][0])
    decision["id"] = f"dec-not-applicable-{contract_id}"
    decision["decision-type"] = "not-applicable"
    decision["gate-decision"] = "approve"
    decision["applies-to"] = [contract_id]
    decision["expiry"] = "2026-12-01"
    return decision


def test_a_contract_declared_not_applicable_leaves_the_gating_population(covert):
    """The denominator is what gates, and not-applicable does not gate.

    A named authority has excused the containment contract, so one contract
    remains capable of moving the gate and it is the one resting on inference.
    The share reported has to reflect that the exposure is now total, not that
    it stayed at a comfortable half.
    """
    covert["decisions"].append(not_applicable_decision(covert, "ac-containment-001"))

    dependence = conformance_summary(covert, now=FROZEN_NOW)[
        "probabilistic-evidence-dependence"
    ]
    assert dependence["gating-contracts"] == 1
    assert dependence["gating-contracts-depending-on-inference"] == [
        "ac-epistemic-integrity-001"
    ]
    assert dependence["share-of-gating-contracts"] == 1.0


def test_excusing_the_inference_backed_contract_drops_it_from_the_numerator(covert):
    covert["decisions"].append(
        not_applicable_decision(covert, "ac-epistemic-integrity-001")
    )

    dependence = conformance_summary(covert, now=FROZEN_NOW)[
        "probabilistic-evidence-dependence"
    ]
    assert dependence["gating-contracts"] == 1
    assert dependence["gating-contracts-depending-on-inference"] == []
    assert dependence["share-of-gating-contracts"] == 0.0
    # The evidence item is still in the package and still probabilistic; what
    # changed is only that no gating contract now rests on it.
    assert dependence["probabilistic-evidence-items"] == ["ev-counterfactual-run-2026-07"]


# ---------------------------------------------------------------------------
# Exception age
# ---------------------------------------------------------------------------


def test_a_live_exception_reports_the_days_it_has_left(memory_summary):
    # A.3: exceptions "must be explicit, scoped, approved, and time-bounded".
    # 2026-07-28 to 2026-10-31 is 95 days.
    exceptions = memory_summary["exception-age"]["exceptions"]
    assert len(exceptions) == 1
    entry = exceptions[0]
    assert entry["decision"] == "dec-exception-memory-write-2026-06"
    assert entry["type"] == "exception"
    assert entry["applies-to"] == ["ac-memory-write-screening-001"]
    assert entry["decision-maker"] == "role-risk-committee"
    assert entry["expiry"] == "2026-10-31"
    assert entry["days-remaining"] == 95
    assert entry["expired"] is False
    assert memory_summary["exception-age"]["expired-exceptions"] == []


def test_an_exception_past_its_expiry_is_flagged_and_its_remaining_days_go_negative(
    memory,
):
    # A.5 level 5: "expired evidence or exceptions change the gate state", which
    # they cannot do unless the summary notices the expiry first.
    summary = conformance_summary(memory, now=STALE_NOW)
    entry = summary["exception-age"]["exceptions"][0]
    assert entry["days-remaining"] == -31
    assert entry["expired"] is True
    assert summary["exception-age"]["expired-exceptions"] == [
        "dec-exception-memory-write-2026-06"
    ]


def test_a_package_with_no_exception_reports_none(covert_summary):
    # The authorization decision is not an exception and must not be aged as one.
    assert covert_summary["exception-age"]["exceptions"] == []
    assert covert_summary["exception-age"]["expired-exceptions"] == []


def test_a_not_applicable_declaration_is_aged_like_an_exception(covert):
    """Both kinds of decision accept risk, so both are time-bounded.

    A.5 makes not-applicable "a named authority has approved a documented
    rationale tied to the current system boundary". The boundary moves, so an
    undated not-applicable would be a permanent exemption under another name.
    """
    covert["decisions"].append(not_applicable_decision(covert, "ac-containment-001"))

    exceptions = conformance_summary(covert, now=FROZEN_NOW)["exception-age"]["exceptions"]
    assert [entry["type"] for entry in exceptions] == ["not-applicable"]
    assert exceptions[0]["days-remaining"] == 126
    assert exceptions[0]["expired"] is False


def test_an_unparseable_expiry_is_reported_as_unknown_rather_than_as_fresh(memory):
    # Failing to read the date must not silently produce a comfortable answer.
    obj(memory, "decisions", "dec-exception-memory-write-2026-06")["expiry"] = "whenever"
    entry = conformance_summary(memory, now=FROZEN_NOW)["exception-age"]["exceptions"][0]
    assert entry["days-remaining"] is None
    assert entry["expired"] is None


# ---------------------------------------------------------------------------
# The human-readable rendering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dimension", A5_DIMENSIONS)
def test_the_formatted_summary_names_every_dimension(covert_summary, dimension: str):
    text = format_summary(covert_summary)
    assert DIMENSION_HEADINGS[dimension] in text


def test_the_formatted_summary_says_that_no_aggregate_score_is_reported(covert_summary):
    """The refusal is stated to the reader, not only enforced in the structure.

    Somebody reading a dashboard will look for the number. Saying why it is
    absent, in the place where it would be, is the only way the omission reads
    as a decision rather than as an unfinished feature.
    """
    text = format_summary(covert_summary)
    assert "No aggregate score is reported" in text
    assert "conceal" in text


@pytest.mark.parametrize(
    ("package_fixture", "now"),
    [
        ("covert", FROZEN_NOW),
        ("covert", STALE_NOW),
        ("memory", FROZEN_NOW),
        ("memory", STALE_NOW),
    ],
)
def test_the_rendering_carries_the_eight_dimension_lines_and_no_ninth(
    request, package_fixture: str, now: datetime
):
    """The refusal has to hold in the text a human actually reads.

    ``meaf summary`` without ``--json`` prints this, so this is the artifact that
    reaches a dashboard, and a line reading "Assurance index 84%" inserted above
    the refusal paragraph would be read as the answer while the paragraph beneath
    it still claimed none was reported. Asserting the presence of the eight
    headings cannot catch a ninth line; pinning the layout can. Every line is
    accounted for: title, blank, the eight dimensions in the manuscript's order,
    blank, the two-line refusal, then unresolved items and nothing else.
    """
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=now)
    lines = format_summary(summary).splitlines()

    assert lines[TITLE_LINE].startswith("Conformance summary for ")
    assert lines[TITLE_LINE + 1] == ""
    headings = [
        line.split("  ")[0] for line in lines[FIRST_DIMENSION_LINE:REFUSAL_LINE - 1]
    ]
    assert headings == list(DIMENSION_HEADINGS.values())
    assert lines[REFUSAL_LINE - 1] == ""
    refusal = lines[REFUSAL_LINE:FIRST_UNRESOLVED_LINE]
    assert refusal[0].startswith("No aggregate score is reported")
    assert refusal[1] != ""
    assert "conceal" in " ".join(refusal)
    assert all(
        line.startswith("  unresolved: ") for line in lines[FIRST_UNRESOLVED_LINE:]
    )


@pytest.mark.parametrize(
    ("package_fixture", "now"),
    [
        ("covert", FROZEN_NOW),
        ("covert", STALE_NOW),
        ("memory", FROZEN_NOW),
        ("memory", STALE_NOW),
    ],
)
def test_no_line_of_the_rendering_reads_as_an_aggregate_score(
    request, package_fixture: str, now: datetime
):
    """The same word list the structure is held to, applied to the rendering.

    A.5's sentence -- "a single number conceals whether weak assurance comes from
    missing threats, uncovered paths, stale evidence, failed tests, or accepted
    residual risk" -- is about what a reader is told, and the reader is told the
    text. The paragraph that states the refusal is excluded, since it is the one
    place these words belong.
    """
    summary = conformance_summary(request.getfixturevalue(package_fixture), now=now)

    offenders = [
        line
        for line in rendered_body(format_summary(summary))
        if SCORE_LIKE_WORDS.search(line)
    ]
    assert offenders == []


def test_the_formatted_summary_reports_the_package_instant_and_policy(covert_summary):
    text = format_summary(covert_summary)
    first_line = text.splitlines()[0]
    assert "pkg-covert-influence-research-agent" in first_line
    assert "2026-07-28T12:00:00Z" in first_line
    assert "meaf-default:2.0.0" in first_line


def test_the_formatted_summary_lists_what_is_unresolved(memory_summary):
    text = format_summary(memory_summary)
    assert "unresolved: ac-memory-write-screening-001 is fail" in text


def test_a_clean_package_produces_no_unresolved_lines(covert_summary):
    text = format_summary(covert_summary)
    assert "unresolved" not in text


def test_stale_evidence_and_uncovered_paths_appear_as_unresolved_lines(covert):
    covert["control-implementations"] = [
        control
        for control in covert["control-implementations"]
        if control["id"] != "ctl-high-impact-recommendation-hold"
    ]
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-high-impact-recommendation-hold"
    ]
    obj(covert, "evidence", "ev-counterfactual-run-2026-07")["invalidated-at"] = (
        "2026-07-27T00:00:00Z"
    )

    text = format_summary(conformance_summary(covert, now=FROZEN_NOW))
    assert "unresolved: path-covert-influence-001 (high): no recovery control" in text
    assert "unresolved: ev-counterfactual-run-2026-07:" in text
