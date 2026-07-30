"""The lifecycle is where policy stops being advice and starts being enforcement.

A.8 says that "state transitions are policy decisions backed by package
evidence, not labels chosen by the agent". That sentence is only true if every
legal transition is actually gated, and if the gates that matter for containment
are the ones that cannot be gated away. The tests below therefore split into
three concerns:

* the guard table is complete, so no transition can inherit a permissive default
  (this is the defect the structural test at the top of this file exists to
  catch);
* the guards on the way *up* to authorization refuse on missing, stale,
  unresolved, failing and indeterminate evidence; and
* the guards on the way *into* containment refuse nothing at all, while the
  guards on the way *back out* demand fresh authorization evidence.

Every evaluation instant is injected. A lifecycle whose verdict depends on the
wall clock would be exactly the kind of unreproducible decision A.5 level 6
forbids.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from meaf.contract import GATE_BLOCK, GATE_REVIEW_REQUIRED, evaluate_gate
from meaf.lifecycle import (
    GUARDS,
    LEGAL_TRANSITIONS,
    STATES,
    attempt_transition,
    check_transition_guard,
    current_state,
    legal_next_states,
)
from meaf.validator import validate_l5_policy, validate_package
from tests.conftest import FROZEN_NOW, STALE_NOW

#: Roles the reference package declares. Only these may move it between states.
ASSURANCE_LEAD = "role-ai-assurance-lead"
REVIEW_BOARD = "role-assurance-review-board"


# --------------------------------------------------------------------------
# Helpers. Negative cases are built by mutating a deep copy of a fixture, so
# the mutation itself is the readable part of each test.
# --------------------------------------------------------------------------


def evidence(package: dict[str, Any], evidence_id: str) -> dict[str, Any]:
    for item in package["evidence"]:
        if item["id"] == evidence_id:
            return item
    raise AssertionError(f"the fixture no longer contains evidence {evidence_id!r}")


def contract(package: dict[str, Any], contract_id: str) -> dict[str, Any]:
    for item in package["assurance-contracts"]:
        if item["id"] == contract_id:
            return item
    raise AssertionError(f"the fixture no longer contains contract {contract_id!r}")


def control(package: dict[str, Any], control_id: str) -> dict[str, Any]:
    for item in package["control-implementations"]:
        if item["id"] == control_id:
            return item
    raise AssertionError(f"the fixture no longer contains control {control_id!r}")


def in_state(package: dict[str, Any], state: str) -> dict[str, Any]:
    """Place a package in an operational state without inventing a history."""
    package["lifecycle"] = {"state": state, "history": []}
    return package


ILLEGAL_PAIRS = sorted(
    (source, target)
    for source in STATES
    for target in STATES
    if target not in LEGAL_TRANSITIONS[source]
)

LEGAL_PAIRS = sorted(
    (source, target) for source, targets in LEGAL_TRANSITIONS.items() for target in targets
)


# --------------------------------------------------------------------------
# The guard table
# --------------------------------------------------------------------------


def test_every_legal_transition_has_its_own_registered_guard():
    """The structural invariant that keeps A.8 honest.

    An earlier implementation dispatched on the transition pair and ended in a
    bare ``return True``. Twelve of the thirteen transitions matched a named
    branch; ``degraded -> authorized`` fell through to the default and was
    granted unconditionally, so a package could return to service after a
    degradation with no evidence whatsoever. Comparing the two tables as sets
    catches that class of defect for every transition added later, which
    inspecting any single guard cannot.
    """
    assert set(GUARDS) == set(LEGAL_PAIRS)


def test_the_guard_table_names_no_state_the_machine_does_not_have():
    for source, target in GUARDS:
        assert source in STATES
        assert target in STATES


def test_retirement_is_terminal():
    # A.8: "Retirement is terminal."
    assert LEGAL_TRANSITIONS["retired"] == frozenset()


@pytest.mark.parametrize(("source", "target"), ILLEGAL_PAIRS)
def test_an_illegal_transition_is_refused_before_any_evidence_is_consulted(
    covert, source, target
):
    """Includes every outgoing transition from ``retired``, which has none.

    The refusal must be legible: an operator reading it needs to know the
    transition does not exist, not that some guard happened to say no.
    """
    granted, reason = check_transition_guard(covert, source, target, now=FROZEN_NOW)
    assert granted is False
    assert "not legal" in reason


# --------------------------------------------------------------------------
# The happy path: draft -> validated -> assessed -> authorized
# --------------------------------------------------------------------------


def test_the_reference_package_walks_from_draft_to_authorized(covert, keyring, examples_dir):
    """A.8 steps 1 to 4, run end to end on the clean reference package.

    Each step is asserted on the recorded history rather than only on the
    returned verdict, because the history is what a later reader has: A.8 wants
    a state change to be an attributable decision, so the actor and the reason
    must survive into the package.
    """
    steps = [
        ("draft", "validated", ASSURANCE_LEAD),
        ("validated", "assessed", ASSURANCE_LEAD),
        ("assessed", "authorized", REVIEW_BOARD),
    ]

    package = covert
    assert current_state(package) == "draft"

    for index, (source, target, actor) in enumerate(steps, start=1):
        result, package = attempt_transition(
            package,
            target,
            actor=actor,
            now=FROZEN_NOW,
            keyring=keyring,
            root=examples_dir,
        )
        assert result.granted is True, result.reason
        assert result.from_state == source
        assert result.to_state == target
        assert current_state(package) == target

        history = package["lifecycle"]["history"]
        assert len(history) == index
        entry = history[-1]
        assert entry["from"] == source
        assert entry["to"] == target
        assert entry["actor"] == actor
        assert entry["at"] == "2026-07-28T12:00:00Z"
        # A refusal-free transition still has to say why it was granted; a
        # history entry with an empty reason records a label, not a decision.
        assert entry["reason"]

    assert [entry["to"] for entry in package["lifecycle"]["history"]] == [
        "validated",
        "assessed",
        "authorized",
    ]


# --------------------------------------------------------------------------
# draft -> validated (A.8 step 2)
# --------------------------------------------------------------------------


def break_level_1(package: dict[str, Any]) -> None:
    del package["system"]["owner"]


def break_level_2(package: dict[str, Any]) -> None:
    contract(package, "ac-epistemic-integrity-001")["control"] = "ctl-does-not-exist"


def break_level_3(package: dict[str, Any]) -> None:
    # A detect control that only "limits" is a mislabelled control, which is a
    # semantic error rather than a schema or reference one.
    control(package, "ctl-counterfactual-symmetry-monitor")["interruption-type"] = "limits"


@pytest.mark.parametrize(
    ("mutate", "expected_level"),
    [(break_level_1, "L1"), (break_level_2, "L2"), (break_level_3, "L3")],
    ids=["syntactic", "referential", "semantic"],
)
def test_draft_to_validated_is_refused_while_a_level_1_to_3_error_remains(
    covert, keyring, examples_dir, mutate, expected_level
):
    # A.8 step 2: "run schema, reference, semantic, and policy checks".
    mutate(covert)
    granted, reason = check_transition_guard(
        covert, "draft", "validated", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert expected_level in reason


# --------------------------------------------------------------------------
# validated -> assessed (A.8 step 3)
# --------------------------------------------------------------------------


def test_validated_to_assessed_is_refused_when_required_evidence_does_not_resolve(
    covert, keyring, examples_dir
):
    """Assessment executes test packs; it cannot execute against a dangling id.

    A.5 level 2 requires every reference to resolve to exactly one object, and a
    contract whose required evidence names nothing has no observation behind it
    at all.
    """
    contract(covert, "ac-epistemic-integrity-001")["required-evidence"] = ["ev-never-collected"]
    granted, reason = check_transition_guard(
        covert, "validated", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "does not resolve" in reason
    assert "ev-never-collected" in reason


def test_validated_to_assessed_is_refused_when_a_failing_contract_has_no_finding(
    covert, keyring, examples_dir
):
    # A.8 step 3: "create findings automatically for failed contracts". A failed
    # contract with no finding is a failure that has left no remediation trail.
    evidence(covert, "ev-counterfactual-run-2026-07")["result"] = "fail"
    assert covert["findings"] == []

    granted, reason = check_transition_guard(
        covert, "validated", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "ac-epistemic-integrity-001" in reason
    assert "no finding records it" in reason


# --------------------------------------------------------------------------
# assessed -> authorized (A.8 step 4)
# --------------------------------------------------------------------------


def test_assessed_to_authorized_is_refused_when_no_authorization_decision_exists(
    covert, keyring, examples_dir
):
    """A.1 principle 5: "Automation does not silently accept residual risk."

    The default policy bundle requires a current authorization decision, so a
    package that has passed every test but that nobody has approved must not
    reach the authorized state on the strength of its own test results.
    """
    covert["decisions"] = []
    granted, reason = check_transition_guard(
        covert, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "gate blocks" in reason
    assert "authorization decision" in reason


def test_assessed_to_authorized_is_refused_once_the_required_evidence_has_aged_out(
    covert, keyring, examples_dir
):
    """The same package, the same disk, a later instant, a different answer.

    Nothing about the package changed between this test and the happy path
    above; only the evaluation instant did. That is the whole point of A.5's
    currency predicate, and the reason ``now`` is injected everywhere.
    """
    fresh, _ = check_transition_guard(
        covert, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert fresh is True

    granted, reason = check_transition_guard(
        covert, "assessed", "authorized", now=STALE_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "days old" in reason


def test_assessed_to_authorized_is_refused_when_a_contract_is_indeterminate(
    covert, keyring, examples_dir
):
    """A.5: indeterminate "must not be silently coerced to pass".

    The containment contract accepts only deterministic observations here, so
    requiring it to rest on probabilistic inference makes it indeterminate
    without touching the evidence itself. Its path is high impact and the
    default bundle fails closed on that tier, so authorization must be refused.
    An earlier implementation let indeterminate through, which is precisely the
    silent coercion A.5 forbids.
    """
    contract(covert, "ac-containment-001")["evidence-classes"] = ["probabilistic-inference"]
    granted, reason = check_transition_guard(
        covert, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "ac-containment-001" in reason
    assert "indeterminate" in reason


# --------------------------------------------------------------------------
# Back to authoring (A.8 step 1)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("source", ["validated", "assessed"])
def test_returning_a_package_to_authoring_is_never_refused(
    covert, keyring, examples_dir, source
):
    """The route back to A.8 step 1 has to stay open however bad the package is.

    ``validated -> draft`` and ``assessed -> draft`` are the only escapes from a
    package that has failed validation or assessment. Gating them on the same
    evidence that produced the failure would strand the author in the state they
    are trying to leave, so the guard is unconditional in the same way that
    containment is. Emptying ``decisions`` here makes the gate block, which is
    enough to refuse every forward transition; the backward one must survive it.
    """
    covert["decisions"] = []
    blocked, _ = check_transition_guard(
        covert, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert blocked is False, "the fixture must be in a state that refuses moving forward"

    granted, reason = check_transition_guard(
        covert, source, "draft", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is True
    assert reason == "returning a package to authoring is always permitted"


# --------------------------------------------------------------------------
# Retirement (A.8: "Retirement is terminal")
# --------------------------------------------------------------------------


@pytest.mark.parametrize("source", ["authorized", "degraded", "suspended"])
def test_retirement_is_permitted_from_every_state_that_can_reach_it(
    covert, keyring, examples_dir, source
):
    """Decommissioning is a fact about the world, not a claim about the package.

    A system that has been switched off must be recordable as retired whatever
    its assurance package says, because the alternative is a decommissioned
    system left in ``authorized`` with a live authorization decision on record.
    """
    granted, reason = check_transition_guard(
        covert, source, "retired", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is True
    assert reason == "retirement is always permitted and is terminal"


def test_retiring_a_package_records_the_decision_and_closes_the_machine(
    covert, keyring, examples_dir
):
    """A.8: "Retirement is terminal."

    Asserted on a package that has actually been retired rather than on the
    transition table alone, so that both halves are covered: the retirement is
    attributable, and nothing leads out of the state it lands in.
    """
    in_state(covert, "authorized")

    result, retired = attempt_transition(
        covert,
        "retired",
        actor=REVIEW_BOARD,
        reason="the deployed system was decommissioned on 2026-07-28",
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
    )
    assert result.granted is True
    assert current_state(retired) == "retired"

    entry = retired["lifecycle"]["history"][-1]
    assert entry["from"] == "authorized"
    assert entry["to"] == "retired"
    assert entry["actor"] == REVIEW_BOARD
    assert entry["reason"] == "the deployed system was decommissioned on 2026-07-28"

    revived, unchanged = attempt_transition(
        retired,
        "draft",
        actor=ASSURANCE_LEAD,
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
    )
    assert revived.granted is False
    assert "not legal" in revived.reason
    assert current_state(unchanged) == "retired"


# --------------------------------------------------------------------------
# authorized -> degraded (A.8 step 5)
# --------------------------------------------------------------------------


def test_authorized_to_degraded_is_refused_when_nothing_has_changed(
    covert, keyring, examples_dir
):
    """Degradation is a response to an event, not a mood.

    A.8 step 5 lists the events that move a system to degraded. Absent one of
    them, marking an authorized package degraded would erase a standing
    authorization without any observation behind it.
    """
    granted, reason = check_transition_guard(
        covert, "authorized", "degraded", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "no degradation trigger" in reason


def test_authorized_to_degraded_is_granted_on_artifact_digest_drift(
    example_tree, keyring
):
    # A.8 step 5 counts "adapter updates, prompt changes, graph edits" among the
    # events that invalidate dependent contracts. One appended byte is the
    # smallest possible version of all of them.
    artifact = example_tree / "artifacts" / "model-card.json"
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    package = json.loads((example_tree / "covert-influence.json").read_text(encoding="utf-8"))

    granted, reason = check_transition_guard(
        package, "authorized", "degraded", now=FROZEN_NOW, keyring=keyring, root=example_tree
    )
    assert granted is True
    assert "drift" in reason
    assert "cmp-foundation-model" in reason


def test_authorized_to_degraded_is_granted_when_required_evidence_has_aged_out(
    covert, keyring, examples_dir
):
    # A.8 step 5: "expired evidence [...] invalidate dependent contracts and can
    # move the system to degraded or suspended".
    granted, reason = check_transition_guard(
        covert, "authorized", "degraded", now=STALE_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is True
    assert "not current" in reason


# --------------------------------------------------------------------------
# Containment: always available
# --------------------------------------------------------------------------


@pytest.mark.parametrize("source", ["authorized", "degraded"])
def test_moving_into_containment_is_never_gated(broken, keyring, examples_dir, source):
    """A containment control that a stale package can block is not a containment control.

    ``broken.json`` carries a deliberate error at every conformance level, so it
    would fail every guard on the way to authorization. Suspension must still be
    available: the moment an operator most needs to contain a system is exactly
    the moment its assurance package is least likely to be in good order.
    """
    errors = [
        finding
        for finding in validate_package(
            broken, now=FROZEN_NOW, keyring=keyring, root=examples_dir
        )
        if finding.severity == "error"
    ]
    assert errors, "the broken fixture is supposed to fail validation"

    granted, reason = check_transition_guard(
        broken, source, "suspended", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is True
    assert "never gated" in reason


def test_a_failing_package_can_still_be_suspended_through_attempt_transition(
    broken, keyring, examples_dir
):
    in_state(broken, "authorized")
    result, updated = attempt_transition(
        broken,
        "suspended",
        actor="role-tester",
        reason="containment during incident response",
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
    )
    assert result.granted is True
    assert current_state(updated) == "suspended"
    assert updated["lifecycle"]["history"][-1]["reason"] == (
        "containment during incident response"
    )


# --------------------------------------------------------------------------
# degraded -> authorized (A.8 step 6)
# --------------------------------------------------------------------------


def test_degraded_to_authorized_is_refused_while_the_drift_is_still_present(
    example_tree, keyring
):
    """A.8 step 6: "require new authorization evidence before returning to service".

    Returning to service while the artifact that caused the degradation is still
    drifted would authorize a system nobody has assessed. The guard has to look
    for the absence of the trigger, not merely for a clean gate.
    """
    artifact = example_tree / "artifacts" / "model-card.json"
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    package = json.loads((example_tree / "covert-influence.json").read_text(encoding="utf-8"))

    granted, reason = check_transition_guard(
        package, "degraded", "authorized", now=FROZEN_NOW, keyring=keyring, root=example_tree
    )
    assert granted is False
    assert "still present" in reason
    assert "drift" in reason


def test_degraded_to_authorized_repeats_the_authorization_guards(
    covert, keyring, examples_dir
):
    """Recovery is not a cheaper route to authorized than authorization is.

    The semantic error below is invisible to the degradation triggers: nothing
    has drifted, no evidence has expired and the gate still allows. It is
    nonetheless a conformance error that ``assessed -> authorized`` would refuse,
    so ``degraded -> authorized`` must refuse it too.
    """
    control(covert, "ctl-counterfactual-symmetry-monitor")["interruption-type"] = "limits"

    triggered, _ = check_transition_guard(
        covert, "authorized", "degraded", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert triggered is False, "this mutation must not itself be a degradation trigger"

    granted, reason = check_transition_guard(
        covert, "degraded", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "conformance levels 1 to 5" in reason


def test_degraded_to_authorized_is_granted_once_no_trigger_remains(
    covert, keyring, examples_dir
):
    granted, reason = check_transition_guard(
        covert, "degraded", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is True
    assert "allow" in reason


# --------------------------------------------------------------------------
# suspended -> assessed (A.8 step 6)
# --------------------------------------------------------------------------


def test_suspended_to_assessed_requires_a_passing_contain_or_restore_contract(
    covert, keyring, examples_dir
):
    """A.8 step 6: "execute the declared recovery test pack".

    Coming out of containment is credited to a contract whose control actually
    contains or restores. The reference package's containment contract is pass,
    so the return is permitted and the reason names the contract that earned it.
    """
    granted, reason = check_transition_guard(
        covert, "suspended", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is True
    assert "ac-containment-001" in reason


def test_suspended_to_assessed_is_refused_when_the_recovery_contract_is_not_pass(
    covert, keyring, examples_dir
):
    evidence(covert, "ev-containment-drill-2026-07")["result"] = "fail"
    granted, reason = check_transition_guard(
        covert, "suspended", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "contain-or-restore" in reason


def test_suspended_to_assessed_is_refused_when_only_detection_contracts_pass(
    covert, keyring, examples_dir
):
    """A detector is not a containment mechanism.

    A.3's typed interruption points exist so that "a detector [is not] credited
    as containment". Removing the contain contract leaves a package whose
    detection contract still passes, and that must not be enough to come out of
    containment.
    """
    covert["assurance-contracts"] = [
        item for item in covert["assurance-contracts"] if item["id"] != "ac-containment-001"
    ]
    granted, reason = check_transition_guard(
        covert, "suspended", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "contain-or-restore" in reason


def test_suspended_to_assessed_is_refused_when_another_contracts_evidence_dangles(
    covert, keyring, examples_dir
):
    """A passing containment drill does not vouch for the rest of the package.

    The recovery clause and the resolution clause of this guard are independent:
    here the containment contract still passes, so the drill has been executed
    as A.8 step 6 demands, but a different contract requires an evidence item
    that resolves to nothing. Coming out of containment on the strength of the
    drill alone would return to service a package whose detect contract rests on
    an observation nobody ever collected.
    """
    demonstrated, reason = check_transition_guard(
        covert, "suspended", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert demonstrated is True, reason
    assert "ac-containment-001" in reason

    contract(covert, "ac-epistemic-integrity-001")["required-evidence"] = ["ev-never-collected"]

    granted, reason = check_transition_guard(
        covert, "suspended", "assessed", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )
    assert granted is False
    assert "does not resolve" in reason
    assert "ev-never-collected" in reason


# --------------------------------------------------------------------------
# legal_next_states
#
# The function an integrator builds a console on: it is the only public way to
# ask "what may this package do now?" without running every guard by hand, so
# its answer has to be the guarded one rather than the table's.
# --------------------------------------------------------------------------


def test_legal_next_states_reports_only_the_transitions_whose_guards_grant(
    example_tree, keyring
):
    """The permissive-default defect, asked as a question rather than a move.

    A degraded package whose artifact has drifted may be contained or retired,
    but ``degraded -> authorized`` is exactly the transition A.8 step 6 requires
    new evidence for. Reporting it as available would tell a caller that a
    package with live drift is one click from returning to service.
    """
    artifact = example_tree / "artifacts" / "model-card.json"
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    package = json.loads((example_tree / "covert-influence.json").read_text(encoding="utf-8"))
    in_state(package, "degraded")

    assert LEGAL_TRANSITIONS["degraded"] == frozenset({"authorized", "suspended", "retired"})
    assert legal_next_states(
        package, now=FROZEN_NOW, keyring=keyring, root=example_tree
    ) == ["retired", "suspended"]


def test_legal_next_states_narrows_to_containment_and_retirement_from_authorized(
    covert, keyring, examples_dir
):
    # Degradation is refused because nothing has changed, so the only moves an
    # authorized reference package has are the two ungated ones.
    in_state(covert, "authorized")
    assert legal_next_states(
        covert, now=FROZEN_NOW, keyring=keyring, root=examples_dir
    ) == ["retired", "suspended"]


def test_legal_next_states_is_empty_once_the_package_is_retired(
    covert, keyring, examples_dir
):
    # A.8: "Retirement is terminal."
    in_state(covert, "retired")
    assert legal_next_states(covert, now=FROZEN_NOW, keyring=keyring, root=examples_dir) == []


def test_legal_next_states_changes_when_the_evidence_ages_out(
    covert, keyring, examples_dir
):
    """The same package, the same disk, a later instant, a shorter list.

    Authorization is available while the counterfactual run is current and gone
    once it is not, which is the A.5 currency predicate observed through the
    public API rather than through a single guard.
    """
    in_state(covert, "assessed")

    assert legal_next_states(
        covert, now=FROZEN_NOW, keyring=keyring, root=examples_dir
    ) == ["authorized", "draft"]
    assert legal_next_states(
        covert, now=STALE_NOW, keyring=keyring, root=examples_dir
    ) == ["draft"]


# --------------------------------------------------------------------------
# The expiry boundary
#
# Not strictly a lifecycle concern, but the lifecycle guard is where a
# disagreement would do its damage: ``_guard_to_authorized`` consults
# validator.py and contract.py in turn, so if the two modules drew the boundary
# in different places the guard would refuse for a reason ``meaf validate``
# reports nothing about.
# --------------------------------------------------------------------------


#: The decision-expiry dates flanking FROZEN_NOW, and whether each is still live.
EXPIRY_BOUNDARY = [
    ("2026-07-27", False),
    ("2026-07-28", True),
    ("2026-07-29", True),
]


@pytest.mark.parametrize(("expiry", "live"), EXPIRY_BOUNDARY, ids=[
    "yesterday", "today", "tomorrow"
])
def test_a_decision_expiring_today_is_still_live_in_both_modules(
    memory, keyring, examples_dir, policy, expiry, live
):
    """A.3: exceptions are "time-bounded". The question is which side today is on.

    ``contract.py`` treats a decision as live while ``expiry >= now.date()`` and
    ``validator.py`` independently reports one expired while ``expiry <
    now.date()``. Two comparisons written in two modules can drift apart at
    exactly one instant, and the day of expiry is that instant: an operator
    would see ``meaf validate`` exit 0 while the gate blocked, with neither
    output naming the decision they disagree about. The boundary is therefore
    pinned here in both modules at once, and in the lifecycle guard that reads
    them both.
    """
    for decision in memory["decisions"]:
        decision["expiry"] = expiry
    in_state(memory, "assessed")

    gate = evaluate_gate(memory, now=FROZEN_NOW, policy=policy)
    expired = [
        finding.message
        for finding in validate_l5_policy(memory, FROZEN_NOW, policy)
        if finding.severity == "error" and "expired" in finding.message
    ]
    granted, _ = check_transition_guard(
        memory, "assessed", "authorized", now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )

    if live:
        assert gate.decision == GATE_REVIEW_REQUIRED
        assert expired == []
        assert granted is True
    else:
        assert gate.decision == GATE_BLOCK
        assert expired == [f"decision expired on {expiry}"] * len(memory["decisions"])
        assert granted is False


# --------------------------------------------------------------------------
# attempt_transition
# --------------------------------------------------------------------------


def test_attempt_transition_refuses_an_actor_the_package_does_not_declare(
    covert, keyring, examples_dir
):
    """A state change has to be attributable to somebody the package names.

    A.5 level 3 requires that "required roles exist"; a transition recorded
    against an undeclared actor produces a history entry that cannot be traced
    to any accountable party.
    """
    result, unchanged = attempt_transition(
        covert,
        "validated",
        actor="somebody-not-in-the-package",
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
    )
    assert result.granted is False
    assert "not a declared responsible role" in result.reason
    assert unchanged is covert
    assert "lifecycle" not in unchanged


def test_attempt_transition_returns_the_package_untouched_when_it_refuses(
    covert, keyring, examples_dir
):
    covert["decisions"] = []
    in_state(covert, "assessed")
    before = copy.deepcopy(covert)

    result, returned = attempt_transition(
        covert,
        "authorized",
        actor=REVIEW_BOARD,
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
    )
    assert result.granted is False
    assert returned == before
    assert current_state(returned) == "assessed"


def test_attempt_transition_refuses_a_state_the_machine_does_not_define(covert):
    result, returned = attempt_transition(
        covert, "quarantined", actor=ASSURANCE_LEAD, now=FROZEN_NOW
    )
    assert result.granted is False
    assert "unknown state" in result.reason
    assert returned is covert


def test_attempt_transition_never_mutates_the_package_it_was_given(
    covert, keyring, examples_dir
):
    """The pre-transition package has to survive the transition.

    A.8 step 6 requires an operator to "preserve the pre-incident package". That
    is only possible if attempting a transition produces a new document rather
    than editing the one in hand.
    """
    before = copy.deepcopy(covert)

    result, updated = attempt_transition(
        covert,
        "validated",
        actor=ASSURANCE_LEAD,
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
    )
    assert result.granted is True
    assert covert == before
    assert updated is not covert
    assert current_state(updated) == "validated"


def test_the_recorded_instant_is_the_injected_one_and_not_the_wall_clock(covert):
    """Rather than asserting "close to now", assert the exact injected instant."""
    other_instant = datetime(2027, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    _, updated = attempt_transition(
        covert, "validated", actor=ASSURANCE_LEAD, now=other_instant
    )
    assert updated["lifecycle"]["history"][-1]["at"] == "2027-01-02T03:04:05Z"
