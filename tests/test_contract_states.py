"""The four contract states are where MEAF either tells the truth or does not.

A.5 gives an assurance contract exactly four states and then adds one
prohibition: "Indeterminate must not be silently coerced to pass." Everything
in this file exists to hold that line. Each named route into ``indeterminate``
gets its own test, built by mutating a copy of a shipped example so that the
mutation is the only difference between a package that passes and one that
cannot be established. The gate tests then check that the reason strings
actually explain the decision, because a gate that blocks without saying why is
a gate nobody will keep switched on.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

import pytest

from meaf.contract import (
    GATE_ALLOW,
    GATE_BLOCK,
    GATE_REVIEW_REQUIRED,
    STATE_FAIL,
    STATE_INDETERMINATE,
    STATE_NOT_APPLICABLE,
    STATE_PASS,
    contract_impact,
    contract_states_by_id,
    evaluate_contract,
    evaluate_contracts,
    evaluate_gate,
    has_evaluable_decision_rule,
)
from tests.conftest import FROZEN_NOW, STALE_NOW

#: A syntactically valid digest that no example evidence item was collected
#: against, used to simulate a redeployed artifact.
SUPERSEDED_DIGEST = "sha256:" + "0" * 64


def contract_of(package: Any, contract_id: str) -> dict[str, Any]:
    for contract in package["assurance-contracts"]:
        if contract["id"] == contract_id:
            return contract
    raise AssertionError(f"no assurance contract {contract_id!r} in this package")


def evidence_of(package: Any, evidence_id: str) -> dict[str, Any]:
    for evidence in package["evidence"]:
        if evidence["id"] == evidence_id:
            return evidence
    raise AssertionError(f"no evidence item {evidence_id!r} in this package")


def component_of(package: Any, component_id: str) -> dict[str, Any]:
    for component in package["components"]:
        if component["id"] == component_id:
            return component
    raise AssertionError(f"no component {component_id!r} in this package")


def state_of(package: Any, contract_id: str, **kwargs: Any):
    return evaluate_contract(package, contract_of(package, contract_id), **kwargs)


def joined_reasons(reasons: tuple[str, ...]) -> str:
    return "\n".join(reasons)


def not_applicable_decision(**overrides: Any) -> dict[str, Any]:
    """A well-formed not-applicable decision, before any test spoils one field."""
    decision = {
        "id": "dec-not-applicable-2026-06",
        "decision-type": "not-applicable",
        "gate-decision": "approve",
        "applies-to": ["ac-memory-write-screening-001"],
        "policy-used": "meaf-default:2.0.0",
        "decision-maker": "role-risk-committee",
        "residual-risk": "none; the memory store no longer accepts third-party writes",
        "scope": "ac-memory-write-screening-001 only",
        "justification": "The write path this claim covers was removed from the boundary.",
        "expiry": "2026-12-31",
        "compensating-controls": [],
    }
    decision.update(overrides)
    return decision


# --------------------------------------------------------------------------
# pass
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "contract_id",
    ["ac-epistemic-integrity-001", "ac-containment-001"],
)
def test_the_reference_package_contracts_pass_at_the_frozen_instant(covert, contract_id):
    # A.5 pass: "every required test passes, all required evidence is current,
    # and the artifact binding matches deployment".
    state = state_of(covert, contract_id, now=FROZEN_NOW)
    assert state.state == STATE_PASS


def test_a_passing_contract_states_an_affirmative_reason(covert):
    """Pass is a claim about what was observed, not the absence of complaints."""
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.reasons
    assert "current" in joined_reasons(state.reasons)


def test_a_passing_contract_reports_every_required_evidence_item_as_current(covert):
    state = state_of(covert, "ac-containment-001", now=FROZEN_NOW)
    assert set(state.evidence_currency) == {"ev-containment-drill-2026-07"}
    assert all(currency.current for currency in state.evidence_currency.values())


def test_contracts_are_evaluated_in_package_order(covert):
    states = evaluate_contracts(covert, now=FROZEN_NOW)
    assert [state.contract_id for state in states] == [
        contract["id"] for contract in covert["assurance-contracts"]
    ]


# --------------------------------------------------------------------------
# fail
# --------------------------------------------------------------------------


def test_a_contract_whose_required_evidence_reports_fail_is_fail(memory):
    # A.5 fail: "at least one required test or deterministic policy predicate
    # fails". ev-poison-write-probe-2026-05 records result fail.
    state = state_of(memory, "ac-memory-write-screening-001", now=FROZEN_NOW)
    assert state.state == STATE_FAIL
    assert "ev-poison-write-probe-2026-05" in joined_reasons(state.reasons)


def test_evidence_that_is_both_failing_and_stale_yields_fail_not_indeterminate(memory):
    """A recorded failure survives its own expiry date.

    At STALE_NOW the probe evidence is both a recorded failure and past its
    max-age, so two states are arguable. Fail is the safe one: the failure is an
    observation somebody actually made, whereas indeterminate says the property
    could not be measured. Reading the stale failure as "could not measure"
    would discard information in the permissive direction, and under a policy
    that permits indeterminate at this impact tier it would convert a known
    broken control into a deployable one purely by waiting.
    """
    state = state_of(memory, "ac-memory-write-screening-001", now=STALE_NOW)
    assert state.state == STATE_FAIL
    # The staleness is still reported in the currency detail, so nothing is hidden.
    assert not state.evidence_currency["ev-poison-write-probe-2026-05"].current


# --------------------------------------------------------------------------
# indeterminate, one test per route named in A.5
# --------------------------------------------------------------------------


def test_missing_required_evidence_is_indeterminate(covert):
    # A.5 indeterminate: "evidence is missing".
    covert["evidence"] = [
        item for item in covert["evidence"] if item["id"] != "ev-counterfactual-run-2026-07"
    ]
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "'ev-counterfactual-run-2026-07' is missing" in joined_reasons(state.reasons)


def test_stale_required_evidence_is_indeterminate(covert):
    # A.5 indeterminate: "evidence is ... stale". The contract allows P30D; this
    # run is 57 days old at FROZEN_NOW.
    evidence_of(covert, "ev-counterfactual-run-2026-07")["collected-at"] = "2026-06-01T00:00:00Z"
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "days old" in joined_reasons(state.reasons)


def test_invalidated_required_evidence_is_indeterminate(covert):
    # A.5's currency predicate has "e.invalidated_at is null" as a conjunct, and
    # A.8 step 5 is what sets it: a change event invalidates dependent results.
    evidence_of(covert, "ev-counterfactual-run-2026-07")["invalidated-at"] = (
        "2026-07-20T00:00:00Z"
    )
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "invalidated at" in joined_reasons(state.reasons)


def test_evidence_not_bound_to_the_deployed_subject_is_indeterminate(covert):
    """A.5: "Artifact binding takes precedence over calendar freshness."

    The evidence here was collected minutes ago in calendar terms; the model it
    was collected against has since been replaced, which is exactly the case the
    manuscript calls stale.
    """
    component_of(covert, "cmp-foundation-model")["digest"] = SUPERSEDED_DIGEST
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "not bound to the deployed subject" in joined_reasons(state.reasons)
    currency = state.evidence_currency["ev-counterfactual-run-2026-07"]
    assert currency.within_max_age and not currency.binding_matches


def test_evidence_reporting_indeterminate_makes_the_contract_indeterminate(covert):
    """A.8 step 3: "record indeterminate results without coercion"."""
    evidence_of(covert, "ev-counterfactual-run-2026-07")["result"] = "indeterminate"
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "reports result 'indeterminate'" in joined_reasons(state.reasons)


def test_evidence_of_a_class_the_contract_does_not_accept_is_indeterminate(covert):
    # A.5 indeterminate: evidence "collected outside the declared scope". A.3
    # makes the accepted classes part of the contract, so a probabilistic
    # inference offered to a contract that accepts only deterministic
    # observation is out of scope however good the observation is.
    contract_of(covert, "ac-epistemic-integrity-001")["evidence-classes"] = [
        "deterministic-observation"
    ]
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "which this contract does not accept" in joined_reasons(state.reasons)


def test_contradictory_evidence_is_indeterminate(covert):
    """A.5 indeterminate: "evidence is ... contradictory".

    Two runs of the same method, by the same collector, against the same subject
    digests cannot both be right. The framework has no basis for preferring
    either, so it declines to decide rather than picking the convenient one.
    """
    replica = copy.deepcopy(evidence_of(covert, "ev-counterfactual-run-2026-07"))
    replica["id"] = "ev-counterfactual-rerun-2026-07"
    replica["result"] = "indeterminate"
    covert["evidence"].append(replica)
    contract_of(covert, "ac-epistemic-integrity-001")["required-evidence"].append(replica["id"])

    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "contradictory evidence" in joined_reasons(state.reasons)


def test_probabilistic_evidence_without_an_evaluable_decision_rule_is_indeterminate(covert):
    # A.5 indeterminate: "probabilistic without an accepted decision rule". A
    # sampling-adequacy key is a requirement on the test, not a bound on a
    # metric, so a rule made only of those decides nothing.
    contract_of(covert, "ac-epistemic-integrity-001")["decision-rule"] = {
        "minimum-paired-cases": 500
    }
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "without an accepted decision rule" in joined_reasons(state.reasons)
    assert state.depends_on_probabilistic is True


def test_a_paired_control_that_does_not_resolve_is_indeterminate(covert):
    """A.3 pairs every contract with a control implementation.

    Without the control the claim is not attached to any interruption point, so
    A.4's "cross-layer paths, not isolated checklist entries" requirement cannot
    be checked and the contract cannot be established.
    """
    contract_of(covert, "ac-epistemic-integrity-001")["control"] = "ctl-does-not-exist"
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert "does not resolve" in joined_reasons(state.reasons)


# --------------------------------------------------------------------------
# Indeterminate must not be silently coerced to pass
# --------------------------------------------------------------------------


def _make_stale(package: Any) -> None:
    evidence_of(package, "ev-counterfactual-run-2026-07")["collected-at"] = (
        "2026-01-01T00:00:00Z"
    )


def _invalidate(package: Any) -> None:
    evidence_of(package, "ev-counterfactual-run-2026-07")["invalidated-at"] = (
        "2026-07-16T00:00:00Z"
    )


def _supersede_subject(package: Any) -> None:
    component_of(package, "cmp-foundation-model")["digest"] = SUPERSEDED_DIGEST


def _unparseable_max_age(package: Any) -> None:
    evidence_of(package, "ev-counterfactual-run-2026-07")["max-age"] = "thirty days"


def _remove_evidence(package: Any) -> None:
    package["evidence"] = [
        item for item in package["evidence"] if item["id"] != "ev-counterfactual-run-2026-07"
    ]


@pytest.mark.parametrize(
    "mutate",
    [_make_stale, _invalidate, _supersede_subject, _unparseable_max_age, _remove_evidence],
    ids=["stale", "invalidated", "superseded-subject", "unparseable-max-age", "absent"],
)
def test_no_route_returns_pass_when_required_evidence_is_not_current(
    covert, mutate: Callable[[Any], None]
):
    """A.5: "Indeterminate must not be silently coerced to pass."

    Each mutation breaks one conjunct of the currency predicate and nothing
    else. A pass here would mean the evaluator asserted the claim on evidence it
    had itself judged not current, which is the single failure mode A.5 rules
    out by name.
    """
    mutate(covert)
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state != STATE_PASS
    assert state.state == STATE_INDETERMINATE
    assert all(not currency.current for currency in state.evidence_currency.values())


def test_indeterminate_is_not_coerced_to_pass_by_a_permissive_policy(covert):
    """Policy chooses what to do with indeterminate, never what it is.

    A.5 permits a deployment policy to allow an indeterminate low-impact
    control, but that is a gate decision. The contract state itself stays
    indeterminate so the summary and the report still say the property was not
    established.
    """
    _make_stale(covert)
    covert["attack-paths"][0]["impact"] = "low"
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_INDETERMINATE
    assert state.impact == "low"

    result = evaluate_gate(covert, now=FROZEN_NOW)
    # The default bundle only requires review at the low tier, so the gate does
    # not block; it must still never reach allow on an unestablished claim.
    assert result.decision != GATE_ALLOW


# --------------------------------------------------------------------------
# not-applicable
# --------------------------------------------------------------------------


def _exempt(package: Any, **overrides: Any) -> None:
    """Scope the covert package's detect contract out with a valid decision.

    The decision-maker must be a role the covert package itself declares; a
    decision signed by a role from some other package is exactly what
    test_a_not_applicable_decision_by_an_undeclared_role... rejects.
    """
    package["decisions"].append(
        not_applicable_decision(
            **{
                "applies-to": ["ac-epistemic-integrity-001"],
                "decision-maker": "role-assurance-review-board",
                **overrides,
            }
        )
    )


def test_a_live_scoped_decision_by_a_declared_role_makes_a_contract_not_applicable(covert):
    # A.5 not-applicable: "a named authority has approved a documented rationale
    # tied to the current system boundary". The contract is driven to
    # indeterminate first so that the state change is attributable to the
    # decision alone rather than to evidence that was passing anyway.
    _make_stale(covert)
    _exempt(covert)
    state = state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW)
    assert state.state == STATE_NOT_APPLICABLE
    assert "role-assurance-review-board" in joined_reasons(state.reasons)


def test_an_expired_not_applicable_decision_does_not_exempt_a_contract(covert):
    # A.3: "Exceptions must be explicit, scoped, approved, and time-bounded."
    # Time-bounded means the bound is load-bearing.
    _make_stale(covert)
    _exempt(covert, expiry="2026-07-27")
    assert state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW).state == (
        STATE_INDETERMINATE
    )


def test_a_not_applicable_decision_by_an_undeclared_role_does_not_exempt_a_contract(covert):
    # A.1 principle 5: "A named accountable person or body must approve
    # exceptions and residual-risk acceptance." A decision-maker the package
    # never declared is not a named accountable body.
    _make_stale(covert)
    _exempt(covert, **{"decision-maker": "role-nobody-in-particular"})
    assert state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW).state == (
        STATE_INDETERMINATE
    )


def test_a_denied_not_applicable_decision_does_not_exempt_a_contract(covert):
    """A decision record is not an approval; the verdict on it is."""
    _make_stale(covert)
    _exempt(covert, **{"gate-decision": "deny"})
    assert state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW).state == (
        STATE_INDETERMINATE
    )


def test_a_not_applicable_decision_scoped_to_another_contract_does_not_exempt_this_one(covert):
    _make_stale(covert)
    _exempt(covert, **{"applies-to": ["ac-containment-001"]})
    assert state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW).state == (
        STATE_INDETERMINATE
    )


def test_not_applicable_outranks_an_unestablished_claim(covert):
    """Scope is decided before an absence of evidence is reported.

    If the claim is outside the boundary then nobody owes evidence for it, so
    reporting it as indeterminate would put a permanent unresolved item on the
    package for a claim it does not make.
    """
    _remove_evidence(covert)
    _exempt(covert)
    assert state_of(covert, "ac-epistemic-integrity-001", now=FROZEN_NOW).state == (
        STATE_NOT_APPLICABLE
    )


def test_a_recorded_failure_outranks_a_not_applicable_decision(memory):
    """A scoping decision cannot un-observe a failed test.

    A.5 defines not-applicable as a statement that the claim does not apply to
    this system. That cannot be truthfully said of a claim whose test just
    failed against the deployed artifacts. The mechanism for carrying a failure
    a team cannot fix today is an exception: explicit, scoped, owned,
    time-bounded, and visible in the gate as review-required rather than silent.

    Without this ordering, adding one decision object to a package turns a
    signed, failing test result into a clean gate.
    """
    memory["decisions"].append(not_applicable_decision())
    state = state_of(memory, "ac-memory-write-screening-001", now=FROZEN_NOW)
    assert state.state == STATE_FAIL
    assert "reports result fail" in joined_reasons(state.reasons)
    assert evaluate_gate(memory, now=FROZEN_NOW).decision != GATE_ALLOW


# --------------------------------------------------------------------------
# contract_impact
# --------------------------------------------------------------------------


def test_contract_impact_resolves_through_the_paired_control(covert):
    """A.3: the path mapping lives on the control implementation.

    The control is pointed at a lower-impact path than the contract's threat, so
    a result of medium can only have come through the control.
    """
    covert["attack-paths"].append(
        {
            "id": "path-alternate-001",
            "description": "A lower-impact path used to distinguish the two resolution routes.",
            "nodes": ["L5:locally-benign-evaluation", "L7:user-or-institutional-decision"],
            "edges": ["data-flow"],
            "impact": "medium",
        }
    )
    covert["control-implementations"][0]["attack-paths"] = ["path-alternate-001"]

    assert contract_impact(covert, contract_of(covert, "ac-epistemic-integrity-001")) == "medium"


def test_contract_impact_falls_back_to_the_threats_paths(covert):
    """When the control cannot be resolved the threats still locate the claim."""
    contract = contract_of(covert, "ac-epistemic-integrity-001")
    contract["control"] = "ctl-does-not-exist"
    # thr-covert-influence-001 names path-covert-influence-001, impact high.
    assert contract_impact(covert, contract) == "high"


def test_contract_impact_is_critical_when_nothing_resolves(covert):
    """Unknown impact is treated as the worst, so indeterminate fails closed.

    The default bundle fails closed on indeterminate at critical and high. If an
    unresolvable contract were rated low instead, a dangling reference would
    quietly buy a claim the most permissive indeterminate handling in the
    bundle, which is the opposite of what a broken package should get.
    """
    contract = contract_of(covert, "ac-epistemic-integrity-001")
    contract["control"] = "ctl-does-not-exist"
    contract["threats"] = []
    assert contract_impact(covert, contract) == "critical"


def test_an_unresolvable_contract_blocks_the_gate_under_the_default_bundle(covert):
    contract = contract_of(covert, "ac-epistemic-integrity-001")
    contract["control"] = "ctl-does-not-exist"
    contract["threats"] = []
    result = evaluate_gate(covert, now=FROZEN_NOW)
    assert result.decision == GATE_BLOCK
    assert "critical-impact path and the policy fails closed" in joined_reasons(result.reasons)


def test_contract_impact_takes_the_strictest_of_several_paths(covert):
    covert["attack-paths"].append(
        {
            "id": "path-alternate-001",
            "description": "A second path the same control interrupts.",
            "nodes": ["L1:biased-generation", "L7:user-or-institutional-decision"],
            "edges": ["data-flow"],
            "impact": "critical",
        }
    )
    covert["control-implementations"][0]["attack-paths"].append("path-alternate-001")
    assert contract_impact(covert, contract_of(covert, "ac-epistemic-integrity-001")) == "critical"


# --------------------------------------------------------------------------
# has_evaluable_decision_rule
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("decision_rule", "expected"),
    [
        ({"source-inclusion-asymmetry-max": 0.1}, True),
        ({"claim-support-rate-min": 0.95}, True),
        ({"paired-cases-exact": 500}, True),
        ({"source-inclusion-asymmetry-max": 0.1, "minimum-paired-cases": 500}, True),
        # A sampling requirement states how much to measure, not what counts as
        # acceptable, so on its own it is not a decision procedure.
        ({"minimum-paired-cases": 500}, False),
        ({"minimum-probe-cases": 200, "minimum-sessions": 3}, False),
        # A rule that bounds nothing decides nothing.
        ({}, False),
        # A bare threshold with no comparison direction is not evaluable.
        ({"claim-support-rate": 0.95}, False),
        # A boolean is a deterministic policy predicate, which A.5 names
        # alongside a failing test as a route to fail. evaluate_rule resolves it
        # against the runner's reported predicates, so it is a decision
        # procedure even though it bounds no metric.
        ({"screening-enabled": True}, True),
        ({"auto-contain-on-detect-failure": False}, True),
        # Nor is a bound whose value is not a number.
        ({"claim-support-rate-min": "0.95"}, False),
        (None, False),
        ("claim-support-rate-min: 0.95", False),
    ],
)
def test_has_evaluable_decision_rule(decision_rule, expected):
    assert has_evaluable_decision_rule(decision_rule) is expected


def test_the_shipped_probabilistic_contract_has_an_evaluable_decision_rule(covert):
    # A.5 requires an "accepted decision rule" before a probabilistic judgment
    # may gate, so the reference package must carry one.
    contract = contract_of(covert, "ac-epistemic-integrity-001")
    assert has_evaluable_decision_rule(contract["decision-rule"]) is True


# --------------------------------------------------------------------------
# evaluate_gate
# --------------------------------------------------------------------------


def test_the_reference_package_gate_allows_and_says_why(covert, policy):
    result = evaluate_gate(covert, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_ALLOW
    assert result.policy == "meaf-default:2.0.0"
    assert result.reasons == ("every contract is pass or not-applicable under this policy",)
    assert {state.state for state in result.contract_states} == {STATE_PASS}


def test_a_failing_contract_under_a_live_exception_downgrades_block_to_review(memory, policy):
    """A.5 level 5: "expired evidence or exceptions change the gate state."

    The exception does not make the claim true, so the gate never reaches allow.
    It records that a named authority accepted the failure for a bounded period.
    """
    result = evaluate_gate(memory, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_REVIEW_REQUIRED

    reasons = joined_reasons(result.reasons)
    assert (
        "contract ac-memory-write-screening-001 is fail but role-risk-committee "
        "accepted it in dec-exception-memory-write-2026-06 until 2026-10-31" in reasons
    )
    # A.5 level 5 also requires that "failed tests produce findings"; the open
    # finding is covered by the same exception rather than blocking separately.
    assert (
        "open finding finding-memory-write-screening-001 is covered by exception "
        "dec-exception-memory-write-2026-06" in reasons
    )

    states = contract_states_by_id(list(result.contract_states))
    assert states["ac-memory-write-screening-001"].state == STATE_FAIL
    assert states["ac-memory-recovery-001"].state == STATE_PASS


def test_removing_the_exception_turns_the_same_package_into_a_block(memory, policy):
    memory["decisions"] = [
        decision
        for decision in memory["decisions"]
        if decision["id"] != "dec-exception-memory-write-2026-06"
    ]
    result = evaluate_gate(memory, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_BLOCK

    reasons = joined_reasons(result.reasons)
    assert (
        "contract ac-memory-write-screening-001 is fail; declared failure action "
        "is quarantine-memory" in reasons
    )
    assert (
        "open finding finding-memory-write-screening-001 has blocking severity high" in reasons
    )


def test_a_finding_below_the_policy_severity_does_not_block(memory, policy):
    """The severity filter has to discriminate, not just fire.

    A test that only ever checks the blocking direction would still pass if the
    filter were replaced by "every open finding blocks", which would make the
    policy's severity list decorative. Same package, same failing contract, one
    field changed: the finding must stop being a reason on its own.
    """
    memory["decisions"] = [
        decision
        for decision in memory["decisions"]
        if decision["id"] != "dec-exception-memory-write-2026-06"
    ]
    assert "high" in policy.blocking_finding_severities
    assert "low" not in policy.blocking_finding_severities

    memory["findings"][0]["severity"] = "low"
    reasons = joined_reasons(evaluate_gate(memory, now=FROZEN_NOW, policy=policy).reasons)
    assert "finding-memory-write-screening-001" not in reasons

    # The package still blocks, on the failing contract rather than the finding.
    # Asserting the decision alone could not tell the two reasons apart.
    memory["findings"][0]["severity"] = "high"
    reasons = joined_reasons(evaluate_gate(memory, now=FROZEN_NOW, policy=policy).reasons)
    assert "finding-memory-write-screening-001 has blocking severity high" in reasons


def test_an_expired_exception_no_longer_downgrades_the_block(memory, policy):
    for decision in memory["decisions"]:
        if decision["id"] == "dec-exception-memory-write-2026-06":
            decision["expiry"] = "2026-07-27"
    result = evaluate_gate(memory, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_BLOCK


def test_a_package_with_no_live_authorization_decision_is_blocked(covert, policy):
    """A.1 principle 5: automation does not silently accept residual risk.

    Every contract still passes; what is missing is the human decision that A.8
    step 4 requires before deployment.
    """
    covert["decisions"] = []
    result = evaluate_gate(covert, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_BLOCK
    assert (
        "policy requires a current authorization decision and the package has none"
        in result.reasons
    )
    assert {state.state for state in result.contract_states} == {STATE_PASS}


def test_an_expired_authorization_decision_is_not_a_current_one(covert, policy):
    covert["decisions"][0]["expiry"] = "2026-07-27"
    result = evaluate_gate(covert, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_BLOCK
    assert (
        "policy requires a current authorization decision and the package has none"
        in result.reasons
    )


def test_the_strict_bundle_bars_probabilistic_inference_from_gating(covert, strict_policy):
    """The same package, the same instant, a different organisational choice.

    A.5 leaves the treatment of probabilistic evidence to deployment policy. The
    strict bundle refuses to let an LLM judgment gate at all, so the detect
    contract becomes indeterminate for want of admissible evidence rather than
    for anything wrong with the run.
    """
    result = evaluate_gate(covert, now=FROZEN_NOW, policy=strict_policy)
    assert result.decision == GATE_BLOCK
    assert result.policy == "meaf-example-strict:2.0.0"

    states = contract_states_by_id(list(result.contract_states))
    detect = states["ac-epistemic-integrity-001"]
    assert detect.state == STATE_INDETERMINATE
    assert "does not permit to gate" in joined_reasons(detect.reasons)
    # The deterministic containment contract is untouched by the change.
    assert states["ac-containment-001"].state == STATE_PASS

    reasons = joined_reasons(result.reasons)
    assert (
        "contract ac-epistemic-integrity-001 is indeterminate on a high-impact "
        "path and the policy fails closed" in reasons
    )
    # The strict bundle also sets the probabilistic gating ceiling to zero.
    assert "above the policy ceiling of 0%" in reasons


def test_the_same_package_allows_under_the_default_bundle_and_blocks_under_the_strict_one(
    covert, policy, strict_policy
):
    """A.5 level 6 asks for reproducibility given the same policy bundle.

    Reproducibility is conditional on the bundle, and this pair is the evidence
    that the bundle, not the framework, carries the organisational choice.
    """
    assert evaluate_gate(covert, now=FROZEN_NOW, policy=policy).decision == GATE_ALLOW
    assert evaluate_gate(covert, now=FROZEN_NOW, policy=strict_policy).decision == GATE_BLOCK


def test_the_gate_reuses_states_it_is_handed(covert, policy):
    """The report and the gate must not evaluate the package twice.

    A.1 principle 6 makes the human-readable views projections of one structured
    source; recomputing would let a projection disagree with the gate it claims
    to explain.
    """
    states = evaluate_contracts(covert, now=FROZEN_NOW, policy=policy)
    result = evaluate_gate(covert, now=FROZEN_NOW, policy=policy, states=states)
    assert list(result.contract_states) == states


def test_a_not_applicable_contract_is_excluded_from_the_probabilistic_share(covert, policy):
    """A claim outside the boundary is not a gating claim.

    The default ceiling is half of gating contracts. With the deterministic
    containment contract declared not-applicable, the one remaining gating
    contract is probabilistic, which is 100 per cent and above the ceiling.
    """
    covert["decisions"].append(
        not_applicable_decision(
            **{"applies-to": ["ac-containment-001"], "decision-maker": "role-system-owner"}
        )
    )
    result = evaluate_gate(covert, now=FROZEN_NOW, policy=policy)
    assert result.decision == GATE_REVIEW_REQUIRED
    assert "1 of 1 gating contracts depend on probabilistic inference (100%)" in joined_reasons(
        result.reasons
    )
