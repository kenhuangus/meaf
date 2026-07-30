"""MEAF package lifecycle state machine (manuscript A.8).

Six operational states plus terminal retirement. "State transitions are policy
decisions backed by package evidence, not labels chosen by the agent", so every
legal transition below reaches a named guard. The previous implementation ended
in a bare ``return True`` that silently permitted ``degraded -> authorized``:
a package could return to service after a degradation with no evidence at all.
Each guard is now registered in :data:`GUARDS` and a test asserts that the guard
table and the transition table have exactly the same keys, so a transition added
later cannot inherit a permissive default.

Recovery is deliberately asymmetric. Moving *into* containment is never gated,
because a control that can be blocked by a stale package is not a containment
control. Moving *out* of containment repeats the authorization guards, because
A.8 step 6 requires "new authorization evidence before returning to service".
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from meaf.attest import check_attestation
from meaf.contract import (
    GATE_BLOCK,
    STATE_FAIL,
    STATE_NOT_APPLICABLE,
    STATE_PASS,
    contract_states_by_id,
    evaluate_contract,
    evaluate_contracts,
    evaluate_gate,
    live_exception,
)
from meaf.model import (
    component_digests,
    evidence_currency,
    objects,
    role_ids,
    subject_digests_for,
    unique_index,
)
from meaf.policy import Policy, default_policy
from meaf.validator import validate_package

STATES = frozenset(
    {"draft", "validated", "assessed", "authorized", "degraded", "suspended", "retired"}
)

LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"validated"}),
    "validated": frozenset({"assessed", "draft"}),
    "assessed": frozenset({"authorized", "draft"}),
    "authorized": frozenset({"degraded", "suspended", "retired"}),
    "degraded": frozenset({"authorized", "suspended", "retired"}),
    "suspended": frozenset({"assessed", "retired"}),
    "retired": frozenset(),
}

#: Interruption types that constitute a demonstrated return-to-service capability.
RECOVERY_INTERRUPTION_TYPES = frozenset({"contains", "restores"})


@dataclass
class TransitionResult:
    granted: bool
    reason: str
    from_state: str
    to_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "granted": self.granted,
            "reason": self.reason,
            "from": self.from_state,
            "to": self.to_state,
        }


@dataclass(frozen=True)
class GuardContext:
    package: Any
    now: datetime
    policy: Policy
    keyring: dict[str, bytes] | None
    root: Path | None


Guard = Callable[[GuardContext], tuple[bool, str]]


def current_state(package: Any) -> str:
    lifecycle = package.get("lifecycle") if isinstance(package, dict) else None
    if not isinstance(lifecycle, dict):
        return "draft"
    return lifecycle.get("state", "draft")


# --------------------------------------------------------------------------
# Guard helpers
# --------------------------------------------------------------------------


def _validation_errors(context: GuardContext, max_level: int) -> list[str]:
    findings = validate_package(
        context.package,
        now=context.now,
        keyring=context.keyring,
        root=context.root,
        policy=context.policy,
    )
    return [
        f"L{finding.level} {finding.object_id or '(package)'}: {finding.message}"
        for finding in findings
        if finding.severity == "error" and finding.level <= max_level
    ]


def _scoped_not_applicable(package: Any, contract_id: str, now: datetime) -> bool:
    contract = unique_index(objects(package, "assurance-contracts")).get(contract_id)
    if contract is None:
        return False
    return evaluate_contract(package, contract, now=now).state == STATE_NOT_APPLICABLE


def _unresolved_required_evidence(package: Any) -> list[str]:
    evidence_index = unique_index(objects(package, "evidence"))
    unresolved: list[str] = []
    for contract in objects(package, "assurance-contracts"):
        missing = [
            evidence_id
            for evidence_id in contract.get("required-evidence", []) or []
            if evidence_id not in evidence_index
        ]
        if missing:
            unresolved.append(f"{contract.get('id')} is missing {', '.join(missing)}")
    return unresolved


def _uncurrent_required_evidence(package: Any, now: datetime) -> list[str]:
    """Required evidence that is not current, checked per item rather than in aggregate.

    The old check required *every* required-evidence item of a contract to be
    stale before it complained, so one fresh item masked an arbitrary number of
    stale ones.

    Contracts a named authority has already scoped out — declared
    not-applicable, or failing under a live exception — are skipped. Otherwise
    the exemption would be worthless: a contract whose evidence nobody intends
    to refresh would block return to service forever, which is the opposite of
    what a time-bounded, owned exception is for.
    """
    evidence_index = unique_index(objects(package, "evidence"))
    deployed = component_digests(package)
    problems: list[str] = []
    for contract in objects(package, "assurance-contracts"):
        contract_id = str(contract.get("id"))
        if live_exception(package, contract_id, now) is not None:
            continue
        if _scoped_not_applicable(package, contract_id, now):
            continue
        required_digests = subject_digests_for(package, contract.get("subject"))
        for evidence_id in contract.get("required-evidence", []) or []:
            evidence = evidence_index.get(evidence_id)
            if evidence is None:
                problems.append(f"{contract.get('id')}: {evidence_id} is missing")
                continue
            currency = evidence_currency(
                evidence,
                now=now,
                required_digests=required_digests,
                deployed_digests=deployed,
                max_age_override=contract.get("evidence-max-age"),
            )
            if not currency.current:
                problems.append(
                    f"{contract.get('id')}: {evidence_id} is not current "
                    f"({'; '.join(currency.reasons)})"
                )
    return problems


def _failing_contracts_without_findings(package: Any, now: datetime, policy: Policy) -> list[str]:
    states = evaluate_contracts(package, now=now, policy=policy)
    recorded = {
        finding.get("failed-claim")
        for finding in objects(package, "findings")
    }
    return [
        state.contract_id
        for state in states
        if state.state == STATE_FAIL and state.contract_id not in recorded
    ]


def _degradation_triggers(context: GuardContext) -> list[str]:
    """Events that make a currently authorized package no longer trustworthy."""
    triggers: list[str] = []

    if context.root is not None:
        for record in check_attestation(context.package, context.root):
            if record["status"] == "drift":
                triggers.append(
                    f"artifact digest drift on {record['component-id']}"
                )
            elif record["status"] == "missing-file":
                triggers.append(
                    f"bound artifact for {record['component-id']} is missing"
                )

    triggers.extend(_uncurrent_required_evidence(context.package, context.now))

    gate = evaluate_gate(
        context.package, now=context.now, policy=context.policy
    )
    if gate.decision == GATE_BLOCK:
        triggers.append(f"gate now blocks: {'; '.join(gate.reasons)}")

    return triggers


def _recovery_demonstrated(package: Any, now: datetime, policy: Policy) -> tuple[bool, str]:
    """A.8 step 6: the declared recovery test pack must have been executed."""
    states = contract_states_by_id(evaluate_contracts(package, now=now, policy=policy))
    control_index = unique_index(objects(package, "control-implementations"))
    for contract in objects(package, "assurance-contracts"):
        control = control_index.get(contract.get("control"))
        if control is None:
            continue
        if control.get("interruption-type") not in RECOVERY_INTERRUPTION_TYPES:
            continue
        state = states.get(str(contract.get("id")))
        if state is not None and state.state == STATE_PASS:
            return True, f"recovery contract {contract.get('id')} is pass"
    return (
        False,
        "no contain-or-restore contract is in state pass, so return to service is "
        "not backed by a current recovery result",
    )


# --------------------------------------------------------------------------
# Guards, one per legal transition
# --------------------------------------------------------------------------


def _guard_draft_to_validated(context: GuardContext) -> tuple[bool, str]:
    errors = _validation_errors(context, max_level=3)
    if errors:
        return False, f"syntactic, referential or semantic errors remain: {errors[0]}"
    return True, "levels 1 to 3 validate without error"


def _guard_to_draft(context: GuardContext) -> tuple[bool, str]:
    return True, "returning a package to authoring is always permitted"


def _guard_validated_to_assessed(context: GuardContext) -> tuple[bool, str]:
    unresolved = _unresolved_required_evidence(context.package)
    if unresolved:
        return False, f"required evidence does not resolve: {unresolved[0]}"
    unrecorded = _failing_contracts_without_findings(
        context.package, context.now, context.policy
    )
    if unrecorded:
        return (
            False,
            f"contract {unrecorded[0]} is fail but no finding records it; assessment "
            "must create findings for failed contracts",
        )
    return True, "every contract has resolving evidence and every failure has a finding"


def _guard_to_authorized(context: GuardContext) -> tuple[bool, str]:
    # Evidence currency is checked first because it is the most specific cause:
    # a stale item also shows up as a path-coverage error at level 5, and
    # reporting the derived finding would tell the operator to fix coverage when
    # what they actually need to do is re-collect one observation.
    problems = _uncurrent_required_evidence(context.package, context.now)
    if problems:
        return False, f"required evidence is not current: {problems[0]}"
    errors = _validation_errors(context, max_level=5)
    if errors:
        return False, f"errors remain at conformance levels 1 to 5: {errors[0]}"
    gate = evaluate_gate(context.package, now=context.now, policy=context.policy)
    if gate.decision == GATE_BLOCK:
        return False, f"gate blocks under {gate.policy}: {'; '.join(gate.reasons)}"
    return True, f"gate returns {gate.decision} under {gate.policy}"


def _guard_authorized_to_degraded(context: GuardContext) -> tuple[bool, str]:
    triggers = _degradation_triggers(context)
    if not triggers:
        return False, "no degradation trigger detected"
    return True, f"degradation trigger: {triggers[0]}"


def _guard_degraded_to_authorized(context: GuardContext) -> tuple[bool, str]:
    triggers = _degradation_triggers(context)
    if triggers:
        return False, f"degradation trigger still present: {triggers[0]}"
    return _guard_to_authorized(context)


def _guard_to_suspended(context: GuardContext) -> tuple[bool, str]:
    return True, "containment is never gated"


def _guard_suspended_to_assessed(context: GuardContext) -> tuple[bool, str]:
    demonstrated, reason = _recovery_demonstrated(
        context.package, context.now, context.policy
    )
    if not demonstrated:
        return False, reason
    unresolved = _unresolved_required_evidence(context.package)
    if unresolved:
        return False, f"required evidence does not resolve: {unresolved[0]}"
    return True, f"return from containment permitted: {reason}"


def _guard_to_retired(context: GuardContext) -> tuple[bool, str]:
    return True, "retirement is always permitted and is terminal"


GUARDS: dict[tuple[str, str], Guard] = {
    ("draft", "validated"): _guard_draft_to_validated,
    ("validated", "assessed"): _guard_validated_to_assessed,
    ("validated", "draft"): _guard_to_draft,
    ("assessed", "authorized"): _guard_to_authorized,
    ("assessed", "draft"): _guard_to_draft,
    ("authorized", "degraded"): _guard_authorized_to_degraded,
    ("authorized", "suspended"): _guard_to_suspended,
    ("authorized", "retired"): _guard_to_retired,
    ("degraded", "authorized"): _guard_degraded_to_authorized,
    ("degraded", "suspended"): _guard_to_suspended,
    ("degraded", "retired"): _guard_to_retired,
    ("suspended", "assessed"): _guard_suspended_to_assessed,
    ("suspended", "retired"): _guard_to_retired,
}


def check_transition_guard(
    package: Any,
    from_state: str,
    to_state: str,
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
) -> tuple[bool, str]:
    """Evaluate the guard for one transition. Unknown pairs are refused."""
    if to_state not in LEGAL_TRANSITIONS.get(from_state, frozenset()):
        return False, f"transition {from_state!r} -> {to_state!r} is not legal"
    guard = GUARDS.get((from_state, to_state))
    if guard is None:
        return False, f"transition {from_state!r} -> {to_state!r} has no registered guard"
    context = GuardContext(
        package=package,
        now=now.astimezone(timezone.utc),
        policy=policy or default_policy(),
        keyring=keyring,
        root=root,
    )
    return guard(context)


def legal_next_states(
    package: Any,
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
) -> list[str]:
    """States the package may move to right now, guards included."""
    state = current_state(package)
    allowed: list[str] = []
    for target in sorted(LEGAL_TRANSITIONS.get(state, frozenset())):
        granted, _ = check_transition_guard(
            package, state, target, now=now, keyring=keyring, root=root, policy=policy
        )
        if granted:
            allowed.append(target)
    return allowed


def attempt_transition(
    package: Any,
    to_state: str,
    *,
    actor: str = "unknown",
    reason: str = "",
    now: datetime | None = None,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
) -> tuple[TransitionResult, Any]:
    """Attempt a transition, returning the verdict and the resulting package."""
    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    from_state = current_state(package)
    if to_state not in STATES:
        return (
            TransitionResult(False, f"unknown state {to_state!r}", from_state, to_state),
            package,
        )

    declared_roles = role_ids(package)
    if declared_roles and actor not in declared_roles:
        return (
            TransitionResult(
                False,
                f"actor {actor!r} is not a declared responsible role; a state change "
                "must be attributable to somebody the package names",
                from_state,
                to_state,
            ),
            package,
        )

    granted, guard_reason = check_transition_guard(
        package, from_state, to_state, now=now, keyring=keyring, root=root, policy=policy
    )
    if not granted:
        return (
            TransitionResult(False, guard_reason, from_state, to_state),
            package,
        )

    updated = copy.deepcopy(package)
    lifecycle = updated.get("lifecycle") or {"state": "draft", "history": []}
    history = list(lifecycle.get("history", []))
    history.append(
        {
            "from": from_state,
            "to": to_state,
            "at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": actor,
            "reason": reason or guard_reason,
        }
    )
    updated["lifecycle"] = {"state": to_state, "history": history}
    return (
        TransitionResult(True, guard_reason, from_state, to_state),
        updated,
    )


def format_status(
    package: Any,
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
) -> str:
    state = current_state(package)
    lines = [f"Current state: {state}"]
    for target in sorted(LEGAL_TRANSITIONS.get(state, frozenset())):
        granted, reason = check_transition_guard(
            package, state, target, now=now, keyring=keyring, root=root, policy=policy
        )
        verdict = "permitted" if granted else "refused"
        lines.append(f"  -> {target}: {verdict} ({reason})")
    if not LEGAL_TRANSITIONS.get(state):
        lines.append("  (terminal state, no outgoing transitions)")
    return "\n".join(lines)


__all__ = [
    "GUARDS",
    "LEGAL_TRANSITIONS",
    "RECOVERY_INTERRUPTION_TYPES",
    "STATES",
    "TransitionResult",
    "attempt_transition",
    "check_transition_guard",
    "current_state",
    "format_status",
    "legal_next_states",
]
