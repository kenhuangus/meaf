"""Change-impact analysis for the monitor activity of manuscript A.8.

A.8 step 5: "Events such as model alias changes, adapter updates, prompt
changes, graph edits, new tools, corpus updates, permission grants, detector
changes, or expired evidence invalidate dependent contracts and can move the
system to degraded or suspended."

This module answers the question a change ticket raises: if this component
changes, what stops being true? It computes the answer without mutating the
package, so it can run in a pre-merge check before the change is made.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from meaf.contract import (
    STATE_PASS,
    contract_states_by_id,
    evaluate_contracts,
    evaluate_gate,
)
from meaf.model import objects, unique_index
from meaf.policy import Policy, default_policy

#: Digest substituted for a changed component. Any value that differs from the
#: recorded one produces the same answer; this one is recognisable in output.
HYPOTHETICAL_DIGEST = "sha256:" + "c" * 64


@dataclass(frozen=True)
class ChangeImpact:
    changed_components: tuple[str, ...]
    invalidated_evidence: tuple[str, ...]
    affected_contracts: tuple[dict[str, Any], ...]
    affected_paths: tuple[str, ...]
    gate_before: str
    gate_after: str
    recommended_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed-components": list(self.changed_components),
            "invalidated-evidence": list(self.invalidated_evidence),
            "affected-contracts": [dict(entry) for entry in self.affected_contracts],
            "affected-paths": list(self.affected_paths),
            "gate-before": self.gate_before,
            "gate-after": self.gate_after,
            "recommended-lifecycle-state": self.recommended_state,
        }


def _with_changed_components(package: Any, component_ids: list[str]) -> dict[str, Any]:
    hypothetical = copy.deepcopy(package)
    for component in hypothetical.get("components", []) or []:
        if component.get("id") in component_ids:
            component["digest"] = HYPOTHETICAL_DIGEST
    return hypothetical


def analyse_change(
    package: Any,
    changed_components: list[str],
    *,
    now: datetime,
    policy: Policy | None = None,
) -> ChangeImpact:
    """Report what a change to ``changed_components`` would invalidate."""
    if policy is None:
        policy = default_policy()

    before_states = contract_states_by_id(
        evaluate_contracts(package, now=now, policy=policy)
    )
    before_gate = evaluate_gate(package, now=now, policy=policy, states=list(before_states.values()))

    old_digests = {
        component["digest"]
        for component in objects(package, "components")
        if component.get("id") in changed_components
        and isinstance(component.get("digest"), str)
    }

    hypothetical = _with_changed_components(package, changed_components)
    after_states = contract_states_by_id(
        evaluate_contracts(hypothetical, now=now, policy=policy)
    )
    after_gate = evaluate_gate(
        hypothetical, now=now, policy=policy, states=list(after_states.values())
    )

    invalidated = sorted(
        str(evidence.get("id"))
        for evidence in objects(package, "evidence")
        if old_digests & set(evidence.get("subject-digests") or [])
    )

    control_index = unique_index(objects(package, "control-implementations"))
    affected: list[dict[str, Any]] = []
    affected_paths: set[str] = set()
    for contract in objects(package, "assurance-contracts"):
        contract_id = str(contract.get("id"))
        before = before_states.get(contract_id)
        after = after_states.get(contract_id)
        if before is None or after is None or before.state == after.state:
            continue
        affected.append(
            {
                "contract": contract_id,
                "state-before": before.state,
                "state-after": after.state,
                "reasons": list(after.reasons),
            }
        )
        control = control_index.get(contract.get("control"))
        if control is not None:
            affected_paths.update(
                path_id
                for path_id in control.get("attack-paths", []) or []
                if isinstance(path_id, str)
            )

    if after_gate.decision == "block":
        recommended = "suspended"
    elif affected or after_gate.decision != before_gate.decision:
        recommended = "degraded"
    else:
        recommended = "authorized"

    return ChangeImpact(
        changed_components=tuple(changed_components),
        invalidated_evidence=tuple(invalidated),
        affected_contracts=tuple(affected),
        affected_paths=tuple(sorted(affected_paths)),
        gate_before=before_gate.decision,
        gate_after=after_gate.decision,
        recommended_state=recommended,
    )


def format_impact(impact: ChangeImpact) -> str:
    lines = [
        f"Change to: {', '.join(impact.changed_components) or '(nothing)'}",
        "",
        f"Evidence invalidated ({len(impact.invalidated_evidence)}):",
    ]
    lines.extend(f"  {evidence_id}" for evidence_id in impact.invalidated_evidence)
    if not impact.invalidated_evidence:
        lines.append("  (none)")

    lines.append("")
    lines.append(f"Contracts changing state ({len(impact.affected_contracts)}):")
    for entry in impact.affected_contracts:
        lines.append(
            f"  {entry['contract']}: {entry['state-before']} -> {entry['state-after']}"
        )
        for reason in entry["reasons"]:
            lines.append(f"    - {reason}")
    if not impact.affected_contracts:
        lines.append("  (none)")

    lines.append("")
    lines.append(f"Attack paths losing verified coverage: {', '.join(impact.affected_paths) or '(none)'}")
    lines.append(f"Gate: {impact.gate_before} -> {impact.gate_after}")
    lines.append(f"Recommended lifecycle state after the change: {impact.recommended_state}")
    return "\n".join(lines)


def stale_contracts(package: Any, *, now: datetime, policy: Policy | None = None) -> list[str]:
    """Contracts not currently in state pass, for cadence-driven monitoring."""
    if policy is None:
        policy = default_policy()
    return [
        state.contract_id
        for state in evaluate_contracts(package, now=now, policy=policy)
        if state.state != STATE_PASS
    ]


__all__ = ["ChangeImpact", "analyse_change", "format_impact", "stale_contracts"]
