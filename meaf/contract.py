"""Assurance-contract state evaluation and gate decisions (manuscript A.5).

An assurance contract is "the smallest independently evaluable unit in MEAF"
(A.3), and A.5 gives it exactly four states:

    pass            every required test passes, all required evidence is
                    current, and the artifact binding matches deployment
    fail            at least one required test or deterministic policy
                    predicate fails
    indeterminate   evidence is missing, stale, contradictory, probabilistic
                    without an accepted decision rule, or collected outside the
                    declared scope
    not-applicable  a named authority has approved a documented rationale tied
                    to the current system boundary

They are evaluated fail-closed, in this order:

    fail -> not-applicable -> indeterminate -> pass

and each step of that order is deliberate.

``fail`` is evaluated first, ahead even of ``not-applicable``. A recorded
failure is an observation, and no scoping decision can un-observe it. The
mechanism for accepting a failure a team cannot fix today is an *exception*,
which is explicit, scoped, owned, time-bounded, and moves the gate to
review-required; ``not-applicable`` means the claim does not apply to this
system at all, which is not a thing anyone can truthfully say about a claim
whose test just failed.

``fail`` also outranks staleness, because discarding a recorded failure as
"could not measure" is the more permissive reading.

Everything that cannot be established yields ``indeterminate``, which A.5
forbids coercing to ``pass``. ``pass`` requires an affirmative result from every
required evidence item; anything that is neither ``pass`` nor ``fail`` — a
missing ``result``, an unrecognised value — is an absence of observation, not a
success.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from meaf.model import (
    Currency,
    TimestampError,
    component_digests,
    evidence_currency,
    objects,
    parse_date,
    role_ids,
    subject_digests_for,
    unique_index,
)
from meaf.policy import (
    INDETERMINATE_FAIL_CLOSED,
    INDETERMINATE_PERMIT,
    INDETERMINATE_REQUIRE_REVIEW,
    Policy,
    default_policy,
    strictest_impact,
)

STATE_PASS = "pass"
STATE_FAIL = "fail"
STATE_INDETERMINATE = "indeterminate"
STATE_NOT_APPLICABLE = "not-applicable"

CONTRACT_STATES = (STATE_PASS, STATE_FAIL, STATE_INDETERMINATE, STATE_NOT_APPLICABLE)

GATE_ALLOW = "allow"
GATE_REVIEW_REQUIRED = "review-required"
GATE_BLOCK = "block"

APPROVING_GATE_DECISIONS = frozenset({"approve", "approve-with-conditions"})

#: Decision-rule keys that assert sampling adequacy rather than a metric bound.
SAMPLING_RULE_PREFIX = "minimum-"


@dataclass(frozen=True)
class ContractState:
    """The evaluated state of one assurance contract."""

    contract_id: str
    state: str
    impact: str
    reasons: tuple[str, ...]
    depends_on_probabilistic: bool
    evidence_currency: dict[str, Currency]

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract-id": self.contract_id,
            "state": self.state,
            "impact": self.impact,
            "reasons": list(self.reasons),
            "depends-on-probabilistic-inference": self.depends_on_probabilistic,
            "evidence-currency": {
                evidence_id: currency.to_dict()
                for evidence_id, currency in sorted(self.evidence_currency.items())
            },
        }


@dataclass(frozen=True)
class GateResult:
    """The gate decision for a package under a policy bundle."""

    decision: str
    policy: str
    reasons: tuple[str, ...]
    contract_states: tuple[ContractState, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate-decision": self.decision,
            "policy": self.policy,
            "reasons": list(self.reasons),
            "contract-states": [state.to_dict() for state in self.contract_states],
        }


def _decision_is_live(decision: dict[str, Any], now: datetime) -> bool:
    """True when a decision has an approving verdict and has not expired."""
    if decision.get("gate-decision") not in APPROVING_GATE_DECISIONS:
        return False
    try:
        expiry = parse_date(decision.get("expiry"))
    except TimestampError:
        return False
    return expiry >= now.date()


def _scoping_decision(
    package: Any,
    contract_id: str,
    decision_type: str,
    now: datetime,
) -> dict[str, Any] | None:
    """Return a live decision of ``decision_type`` scoped to ``contract_id``."""
    declared_roles = role_ids(package)
    for decision in objects(package, "decisions"):
        if decision.get("decision-type") != decision_type:
            continue
        applies_to = decision.get("applies-to")
        if not isinstance(applies_to, list) or contract_id not in applies_to:
            continue
        if not _decision_is_live(decision, now):
            continue
        # A.1 principle 5: automation does not silently accept residual risk.
        # An exception signed by nobody the package declares is not an exception.
        if decision.get("decision-maker") not in declared_roles:
            continue
        return decision
    return None


def live_exception(package: Any, contract_id: str, now: datetime) -> dict[str, Any] | None:
    """The unexpired, role-approved exception scoped to ``contract_id``, if any.

    A.3: "Exceptions must be explicit, scoped, approved, and time-bounded." All
    four conditions are checked here so that callers cannot accidentally honour
    a decision missing one of them.
    """
    return _scoping_decision(package, contract_id, "exception", now)


def contract_impact(package: Any, contract: dict[str, Any]) -> str:
    """Strictest impact of the attack paths this contract bears on.

    Resolution runs through the paired control implementation, which is the
    object that carries the path mapping. When the control cannot be resolved
    the impact is taken from the contract's threats instead, and when neither
    resolves the impact is reported as ``critical`` so that indeterminate
    handling fails closed rather than defaulting to the permissive tier.
    """
    path_index = unique_index(objects(package, "attack-paths"))
    control_index = unique_index(objects(package, "control-implementations"))

    path_ids: list[str] = []
    control = control_index.get(contract.get("control"))
    if control is not None:
        raw = control.get("attack-paths")
        if isinstance(raw, list):
            path_ids.extend(item for item in raw if isinstance(item, str))

    if not path_ids:
        threat_index = unique_index(objects(package, "threats"))
        for threat_id in contract.get("threats", []) or []:
            threat = threat_index.get(threat_id)
            if threat is not None and isinstance(threat.get("path"), str):
                path_ids.append(threat["path"])

    impacts = [
        path_index[path_id]["impact"]
        for path_id in path_ids
        if path_id in path_index and isinstance(path_index[path_id].get("impact"), str)
    ]
    if not impacts:
        return "critical"
    return strictest_impact(impacts)


def has_evaluable_decision_rule(decision_rule: Any) -> bool:
    """True when a decision rule states at least one metric bound.

    Sampling-adequacy keys such as ``minimum-paired-cases`` are requirements on
    the test, not bounds on a metric, so a rule containing only those does not
    count as an accepted decision procedure.
    """
    if not isinstance(decision_rule, dict):
        return False
    for key, value in decision_rule.items():
        # A boolean is a deterministic policy predicate, which the rule
        # evaluator resolves against the runner's reported predicates. It is a
        # decision procedure even though it names no metric bound.
        if isinstance(value, bool):
            return True
        if not isinstance(value, (int, float)):
            continue
        if key.startswith(SAMPLING_RULE_PREFIX):
            continue
        if key.endswith(("-max", "-min", "-exact")):
            return True
    return False


def _contradictory(evidence_items: list[dict[str, Any]]) -> str | None:
    """Detect required evidence that observed the same thing to different ends."""
    seen: dict[tuple[str, str, tuple[str, ...]], str] = {}
    for evidence in evidence_items:
        key = (
            str(evidence.get("method", "")),
            str(evidence.get("collector", "")),
            tuple(sorted(evidence.get("subject-digests", []) or [])),
        )
        result = str(evidence.get("result", ""))
        previous = seen.get(key)
        if previous is not None and previous != result:
            return (
                f"contradictory evidence: method {key[0]!r} by collector {key[1]!r} "
                f"against the same subject reports both {previous!r} and {result!r}"
            )
        seen[key] = result
    return None


def evaluate_contract(
    package: Any,
    contract: dict[str, Any],
    *,
    now: datetime,
    policy: Policy | None = None,
) -> ContractState:
    """Evaluate one assurance contract to one of the four A.5 states."""
    if policy is None:
        policy = default_policy()

    contract_id = str(contract.get("id", "(unknown)"))
    impact = contract_impact(package, contract)
    evidence_index = unique_index(objects(package, "evidence"))
    control_index = unique_index(objects(package, "control-implementations"))

    required_ids = [
        item for item in contract.get("required-evidence", []) or [] if isinstance(item, str)
    ]
    resolved = [evidence_index[eid] for eid in required_ids if eid in evidence_index]
    depends_on_probabilistic = any(
        item.get("class") == "probabilistic-inference" for item in resolved
    )

    required_digests = subject_digests_for(package, contract.get("subject"))
    deployed = component_digests(package)
    currencies: dict[str, Currency] = {
        item["id"]: evidence_currency(
            item,
            now=now,
            required_digests=required_digests,
            deployed_digests=deployed,
            max_age_override=contract.get("evidence-max-age"),
        )
        for item in resolved
        if isinstance(item.get("id"), str)
    }

    def build(state: str, reasons: list[str]) -> ContractState:
        return ContractState(
            contract_id=contract_id,
            state=state,
            impact=impact,
            reasons=tuple(reasons),
            depends_on_probabilistic=depends_on_probabilistic,
            evidence_currency=currencies,
        )

    # 1. fail, which outranks both staleness and any scoping decision.
    failures = [item["id"] for item in resolved if item.get("result") == "fail"]
    if failures:
        return build(
            STATE_FAIL,
            [f"required evidence {eid!r} reports result fail" for eid in failures],
        )

    # 2. not-applicable, which only a named authority can declare.
    exemption = _scoping_decision(package, contract_id, "not-applicable", now)
    if exemption is not None:
        return build(
            STATE_NOT_APPLICABLE,
            [
                f"declared not-applicable by {exemption.get('decision-maker')} "
                f"in {exemption.get('id')} until {exemption.get('expiry')}"
            ],
        )

    # 3. indeterminate: everything that cannot be established.
    reasons: list[str] = []

    missing = [eid for eid in required_ids if eid not in evidence_index]
    reasons.extend(f"required evidence {eid!r} is missing" for eid in missing)

    if contract.get("control") not in control_index:
        reasons.append(
            f"paired control implementation {contract.get('control')!r} does not resolve, "
            "so the claim cannot be attributed to anything"
        )

    for eid, currency in sorted(currencies.items()):
        if not currency.current:
            reasons.extend(f"required evidence {eid!r}: {reason}" for reason in currency.reasons)

    acceptable_classes = contract.get("evidence-classes")
    if isinstance(acceptable_classes, list) and acceptable_classes:
        for item in resolved:
            if item.get("class") not in acceptable_classes:
                reasons.append(
                    f"required evidence {item.get('id')!r} is class "
                    f"{item.get('class')!r}, which this contract does not accept"
                )

    # Anything that is not an affirmative pass is an absence of observation.
    # Testing only for the literal string "indeterminate" would let a missing
    # or unrecognised result fall through every guard and land on pass.
    reasons.extend(
        f"required evidence {item['id']!r} reports result {item.get('result')!r}, "
        "which is not an observation this contract can accept"
        for item in resolved
        if item.get("result") != "pass"
    )

    contradiction = _contradictory(resolved)
    if contradiction is not None:
        reasons.append(contradiction)

    if depends_on_probabilistic:
        if not policy.probabilistic_permitted_for_gate:
            reasons.append(
                "contract depends on probabilistic inference, which the policy "
                "bundle does not permit to gate"
            )
        elif policy.probabilistic_requires_decision_rule and not has_evaluable_decision_rule(
            contract.get("decision-rule")
        ):
            reasons.append(
                "probabilistic evidence without an accepted decision rule: "
                "decision-rule states no metric bound"
            )

    if reasons:
        return build(STATE_INDETERMINATE, reasons)

    # 4. pass, stated affirmatively.
    return build(
        STATE_PASS,
        [
            f"{len(resolved)} required evidence item(s) current, bound to the "
            f"deployed subject, and passing"
        ],
    )


def evaluate_contracts(
    package: Any,
    *,
    now: datetime,
    policy: Policy | None = None,
) -> list[ContractState]:
    """Evaluate every assurance contract in the package, in package order."""
    if policy is None:
        policy = default_policy()
    return [
        evaluate_contract(package, contract, now=now, policy=policy)
        for contract in objects(package, "assurance-contracts")
    ]


def contract_states_by_id(states: list[ContractState]) -> dict[str, ContractState]:
    return {state.contract_id: state for state in states}


def _open_findings(package: Any, now: datetime) -> list[dict[str, Any]]:
    """Findings that still bear on the gate.

    ``risk-accepted`` counts as open unless a live exception or not-applicable
    decision actually scopes the contract it belongs to. Otherwise editing one
    word of a finding's status would silence a blocking finding with no named
    authority, no justification and no expiry anywhere in the package — which is
    exactly the unowned risk acceptance A.1 principle 5 exists to prevent.
    """
    open_findings: list[dict[str, Any]] = []
    for finding in objects(package, "findings"):
        status = finding.get("status", "open")
        if status == "resolved":
            continue
        if status == "risk-accepted":
            contract_id = finding.get("failed-claim")
            if isinstance(contract_id, str) and (
                live_exception(package, contract_id, now) is not None
                or _scoping_decision(package, contract_id, "not-applicable", now) is not None
            ):
                continue
        open_findings.append(finding)
    return open_findings


def evaluate_gate(
    package: Any,
    *,
    now: datetime,
    policy: Policy | None = None,
    states: list[ContractState] | None = None,
) -> GateResult:
    """Apply the policy bundle's gate rules to the evaluated contract states."""
    if policy is None:
        policy = default_policy()
    if states is None:
        states = evaluate_contracts(package, now=now, policy=policy)

    reasons: list[str] = []
    blocking = False
    review = False

    contract_index = unique_index(objects(package, "assurance-contracts"))
    excepted: dict[str, dict[str, Any]] = {}
    for contract_id in contract_index:
        exception = live_exception(package, contract_id, now)
        if exception is not None:
            excepted[contract_id] = exception

    for state in states:
        if state.state == STATE_FAIL:
            contract = contract_index.get(state.contract_id, {})
            action = contract.get("failure-action", "unspecified")
            exception = excepted.get(state.contract_id)
            if exception is None:
                blocking = True
                reasons.append(
                    f"contract {state.contract_id} is fail; declared failure action "
                    f"is {action}"
                )
            else:
                # A.5: "expired evidence or exceptions change the gate state." A
                # live exception does not make the claim true, so the gate never
                # reaches allow; it records that a named authority accepted the
                # failure for a bounded period.
                review = True
                reasons.append(
                    f"contract {state.contract_id} is fail but "
                    f"{exception.get('decision-maker')} accepted it in "
                    f"{exception.get('id')} until {exception.get('expiry')}"
                )
        elif state.state == STATE_INDETERMINATE:
            handling = policy.indeterminate_handling(state.impact)
            exception = excepted.get(state.contract_id)
            if handling == INDETERMINATE_FAIL_CLOSED and exception is not None:
                # An authority may accept "we cannot currently establish this"
                # on the same terms as "this currently fails": visibly, scoped,
                # and with an expiry.
                review = True
                reasons.append(
                    f"contract {state.contract_id} is indeterminate on a "
                    f"{state.impact}-impact path, accepted by "
                    f"{exception.get('decision-maker')} in {exception.get('id')} "
                    f"until {exception.get('expiry')}"
                )
            elif handling == INDETERMINATE_FAIL_CLOSED:
                blocking = True
                reasons.append(
                    f"contract {state.contract_id} is indeterminate on a "
                    f"{state.impact}-impact path and the policy fails closed"
                )
            elif handling == INDETERMINATE_REQUIRE_REVIEW:
                review = True
                reasons.append(
                    f"contract {state.contract_id} is indeterminate on a "
                    f"{state.impact}-impact path and the policy requires review"
                )
            elif handling == INDETERMINATE_PERMIT:
                reasons.append(
                    f"contract {state.contract_id} is indeterminate on a "
                    f"{state.impact}-impact path and the policy permits it"
                )

    blocking_severities = policy.blocking_finding_severities
    for finding in _open_findings(package, now):
        if finding.get("severity") not in blocking_severities:
            continue
        if finding.get("failed-claim") in excepted:
            review = True
            reasons.append(
                f"open finding {finding.get('id')} is covered by exception "
                f"{excepted[finding['failed-claim']].get('id')}"
            )
            continue
        blocking = True
        reasons.append(
            f"open finding {finding.get('id')} has blocking severity "
            f"{finding.get('severity')}"
        )

    if policy.require_authorization_decision:
        authorized = any(
            decision.get("decision-type") == "authorization" and _decision_is_live(decision, now)
            for decision in objects(package, "decisions")
        )
        if not authorized:
            blocking = True
            reasons.append(
                "policy requires a current authorization decision and the package has none"
            )

    share_limit = policy.maximum_probabilistic_gating_share
    gating = [state for state in states if state.state != STATE_NOT_APPLICABLE]
    if share_limit is not None and gating:
        probabilistic = sum(1 for state in gating if state.depends_on_probabilistic)
        share = probabilistic / len(gating)
        if share > share_limit:
            review = True
            reasons.append(
                f"{probabilistic} of {len(gating)} gating contracts depend on "
                f"probabilistic inference ({share:.0%}), above the policy ceiling "
                f"of {share_limit:.0%}"
            )

    if blocking:
        decision = GATE_BLOCK
    elif review:
        decision = GATE_REVIEW_REQUIRED
    else:
        decision = GATE_ALLOW
        reasons.append("every contract is pass or not-applicable under this policy")

    return GateResult(
        decision=decision,
        policy=policy.name,
        reasons=tuple(reasons),
        contract_states=tuple(states),
    )


def format_contract_states(states: list[ContractState]) -> str:
    lines: list[str] = []
    for state in states:
        lines.append(f"{state.contract_id}: {state.state} (impact {state.impact})")
        for reason in state.reasons:
            lines.append(f"  - {reason}")
    counts = {name: 0 for name in CONTRACT_STATES}
    for state in states:
        counts[state.state] = counts.get(state.state, 0) + 1
    summary = ", ".join(f"{count} {name}" for name, count in counts.items())
    lines.append(f"Contract states: {summary}.")
    return "\n".join(lines)


def format_gate(result: GateResult) -> str:
    lines = [
        format_contract_states(list(result.contract_states)),
        "",
        f"Gate decision under {result.policy}: {result.decision}",
    ]
    lines.extend(f"  - {reason}" for reason in result.reasons)
    return "\n".join(lines)


__all__ = [
    "APPROVING_GATE_DECISIONS",
    "CONTRACT_STATES",
    "ContractState",
    "GATE_ALLOW",
    "GATE_BLOCK",
    "GATE_REVIEW_REQUIRED",
    "GateResult",
    "STATE_FAIL",
    "STATE_INDETERMINATE",
    "STATE_NOT_APPLICABLE",
    "STATE_PASS",
    "contract_impact",
    "contract_states_by_id",
    "evaluate_contract",
    "evaluate_contracts",
    "evaluate_gate",
    "format_contract_states",
    "format_gate",
    "has_evaluable_decision_rule",
    "live_exception",
]
