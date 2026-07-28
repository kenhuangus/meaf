"""MEAF package lifecycle state machine."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from meaf.validator import (
    Finding,
    evidence_is_fresh,
    has_errors,
    parse_datetime,
    validate_package,
)

STATES = frozenset(
    {"draft", "validated", "assessed", "authorized", "degraded", "suspended", "retired"}
)

LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"validated"}),
    "validated": frozenset({"assessed"}),
    "assessed": frozenset({"authorized", "draft"}),
    "authorized": frozenset({"degraded", "suspended", "retired"}),
    "degraded": frozenset({"authorized", "suspended"}),
    "suspended": frozenset({"assessed", "retired"}),
    "retired": frozenset(),
}


@dataclass
class TransitionResult:
    granted: bool
    reason: str
    from_state: str
    to_state: str


def current_state(package: dict[str, Any]) -> str:
    lifecycle = package.get("lifecycle")
    if not lifecycle:
        return "draft"
    return lifecycle.get("state", "draft")


def _evidence_index(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in package.get("evidence", [])}


def _has_approval_decision(package: dict[str, Any]) -> bool:
    for decision in package.get("decisions", []):
        gate = decision.get("gate-decision", "").lower()
        if "approve" in gate:
            return True
    return False


def _contract_required_evidence_resolves(
    contract: dict[str, Any],
    evidence_index: dict[str, dict[str, Any]],
) -> bool:
    for evidence_id in contract.get("required-evidence", []):
        if evidence_id in evidence_index:
            return True
    return False


def _any_evidence_failed(package: dict[str, Any]) -> bool:
    return any(item.get("result") == "fail" for item in package.get("evidence", []))


def _all_required_evidence_fresh(
    package: dict[str, Any],
    now: datetime,
) -> tuple[bool, str]:
    evidence_index = _evidence_index(package)
    for contract in package.get("assurance-contracts", []):
        for evidence_id in contract.get("required-evidence", []):
            evidence = evidence_index.get(evidence_id)
            if evidence is None:
                return False, f"required evidence {evidence_id!r} missing"
            try:
                fresh = evidence_is_fresh(
                    evidence["collected-at"],
                    evidence["max-age"],
                    evidence.get("invalidated-at"),
                    now,
                )
            except ValueError:
                return False, f"required evidence {evidence_id!r} has invalid timestamps"
            if not fresh:
                return False, f"required evidence {evidence_id!r} is stale"
    return True, ""


def _digest_changed(package: dict[str, Any], bound_digests: set[str]) -> bool:
    current = {component["digest"] for component in package.get("components", [])}
    return not bound_digests.issubset(current)


def _bound_digests_from_history(package: dict[str, Any]) -> set[str]:
    digests: set[str] = set()
    for evidence in package.get("evidence", []):
        digests.update(evidence.get("subject-digests", []))
    return digests


def _any_required_evidence_stale_or_invalidated(
    package: dict[str, Any],
    now: datetime,
) -> bool:
    evidence_index = _evidence_index(package)
    for contract in package.get("assurance-contracts", []):
        for evidence_id in contract.get("required-evidence", []):
            evidence = evidence_index.get(evidence_id)
            if evidence is None:
                continue
            if evidence.get("invalidated-at") is not None:
                return True
            try:
                if not evidence_is_fresh(
                    evidence["collected-at"],
                    evidence["max-age"],
                    evidence.get("invalidated-at"),
                    now,
                ):
                    return True
            except ValueError:
                return True
    return False


def check_transition_guard(
    package: dict[str, Any],
    from_state: str,
    to_state: str,
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> tuple[bool, str]:
    if to_state not in LEGAL_TRANSITIONS.get(from_state, frozenset()):
        return False, f"transition {from_state!r} -> {to_state!r} is not legal"

    if to_state == "suspended" and from_state in ("authorized", "degraded"):
        return True, "containment transition always permitted"

    if from_state == "draft" and to_state == "validated":
        findings = validate_package(package, now=now, keyring=keyring, root=root)
        blocking = [
            f
            for f in findings
            if f.severity == "error" and f.level in (1, 2, 3)
        ]
        if blocking:
            return False, "L1/L2/L3 validation errors remain"
        return True, "syntactic, referential, and semantic validation passed"

    if from_state == "validated" and to_state == "assessed":
        evidence_index = _evidence_index(package)
        for contract in package.get("assurance-contracts", []):
            if not _contract_required_evidence_resolves(contract, evidence_index):
                return (
                    False,
                    f"contract {contract['id']!r} has no resolving required-evidence",
                )
        if _any_evidence_failed(package):
            return False, "evidence with result fail present"
        return True, "all contracts have resolving evidence and no failures"

    if from_state == "assessed" and to_state == "authorized":
        findings = validate_package(package, now=now, keyring=keyring, root=root)
        errors = [f for f in findings if f.severity == "error" and f.level <= 5]
        if errors:
            return False, "errors remain at conformance levels 1-5"
        if not _has_approval_decision(package):
            return False, "no approval gate-decision found in decisions"
        fresh, reason = _all_required_evidence_fresh(package, now)
        if not fresh:
            return False, reason
        return True, "all authorization guards satisfied"

    if from_state == "authorized" and to_state == "degraded":
        if root is not None:
            from meaf.attest import has_attestation_drift

            if has_attestation_drift(package, root):
                return True, "bound artifact digest changed"
        elif _digest_changed(package, _bound_digests_from_history(package)):
            return True, "bound artifact digest changed"
        if _any_required_evidence_stale_or_invalidated(package, now):
            return True, "required evidence stale or invalidated"
        return False, "no degradation trigger detected"

    if to_state == "retired":
        return True, "retirement permitted"

    return True, "transition permitted"


def legal_next_states(
    package: dict[str, Any],
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> list[str]:
    state = current_state(package)
    allowed: list[str] = []
    for target in sorted(LEGAL_TRANSITIONS.get(state, frozenset())):
        granted, _ = check_transition_guard(
            package, state, target, now=now, keyring=keyring, root=root
        )
        if granted:
            allowed.append(target)
    return allowed


def attempt_transition(
    package: dict[str, Any],
    to_state: str,
    *,
    actor: str = "unknown",
    reason: str = "",
    now: datetime | None = None,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> tuple[TransitionResult, dict[str, Any]]:
    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    from_state = current_state(package)
    if to_state not in STATES:
        result = TransitionResult(
            granted=False,
            reason=f"unknown state {to_state!r}",
            from_state=from_state,
            to_state=to_state,
        )
        return result, package

    granted, guard_reason = check_transition_guard(
        package, from_state, to_state, now=now, keyring=keyring, root=root
    )
    if not granted:
        return (
            TransitionResult(
                granted=False,
                reason=guard_reason,
                from_state=from_state,
                to_state=to_state,
            ),
            package,
        )

    updated = copy.deepcopy(package)
    lifecycle = updated.get("lifecycle", {"state": "draft", "history": []})
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
        TransitionResult(
            granted=True,
            reason=guard_reason,
            from_state=from_state,
            to_state=to_state,
        ),
        updated,
    )


def format_status(package: dict[str, Any], *, now: datetime) -> str:
    state = current_state(package)
    next_states = legal_next_states(package, now=now)
    lines = [f"Current state: {state}", f"Legal next states: {', '.join(next_states) or '(none)'}"]
    return "\n".join(lines)
