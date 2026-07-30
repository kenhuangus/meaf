"""The conforming summary of manuscript A.5, and the adoption level of A.9.

A.5 is explicit about what a summary must and must not be:

    MEAF intentionally does not define a universal aggregate security score. A
    single number conceals whether weak assurance comes from missing threats,
    uncovered paths, stale evidence, failed tests, or accepted residual risk. A
    conforming summary reports at least: threat-model completeness,
    path-interruption coverage, control-test status, evidence freshness, open
    findings by severity, recovery readiness, probabilistic-evidence
    dependence, and exception age.

:func:`conformance_summary` reports those eight dimensions and nothing that
could be mistaken for a score. There is a test asserting that no key anywhere in
its output is named like one, because the pressure to add "overall: 84%" to a
security dashboard is considerable and the manuscript's reason for refusing it
is good.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from meaf.contract import (
    STATE_FAIL,
    STATE_INDETERMINATE,
    STATE_NOT_APPLICABLE,
    STATE_PASS,
    ContractState,
    evaluate_contracts,
)
from meaf.model import (
    TimestampError,
    component_digests,
    evidence_currency,
    objects,
    parse_date,
    parse_duration,
    subject_digests_for,
    unique_index,
)
from meaf.policy import Policy, default_policy


def _shortest(durations: list[str]) -> str | None:
    """The tightest freshness window among several, or None when there is none."""
    best: tuple[float, str] | None = None
    for value in durations:
        try:
            seconds = parse_duration(value)
        except TimestampError:
            continue
        if best is None or seconds < best[0]:
            best = (seconds, value)
    return best[1] if best else None

SEVERITIES = ("critical", "high", "medium", "low")
RECOVERY_FUNCTIONS = frozenset({"contain", "recover"})
RECOVERY_INTERRUPTION_TYPES = frozenset({"contains", "restores"})

SUMMARY_DIMENSIONS = (
    "threat-model-completeness",
    "path-interruption-coverage",
    "control-test-status",
    "evidence-freshness",
    "open-findings-by-severity",
    "recovery-readiness",
    "probabilistic-evidence-dependence",
    "exception-age",
)


def _threat_model_completeness(package: Any) -> dict[str, Any]:
    threats = objects(package, "threats")
    covered = {
        threat_id
        for contract in objects(package, "assurance-contracts")
        for threat_id in contract.get("threats", []) or []
        if isinstance(threat_id, str)
    }
    uncovered = sorted(
        str(threat.get("id"))
        for threat in threats
        if threat.get("id") not in covered
    )
    beyond_session = [
        str(threat.get("id"))
        for threat in threats
        if isinstance(threat.get("temporal-profile"), dict)
        and threat["temporal-profile"].get("persistence") != "session"
    ]
    return {
        "threats-declared": len(threats),
        "threats-with-contracts": len(threats) - len(uncovered),
        "threats-without-contracts": uncovered,
        "threats-persisting-beyond-session": sorted(beyond_session),
    }


def _path_interruption_coverage(package: Any, policy: Policy) -> dict[str, Any]:
    controls_by_path: dict[str, list[dict[str, Any]]] = {}
    for control in objects(package, "control-implementations"):
        for path_id in control.get("attack-paths", []) or []:
            if isinstance(path_id, str):
                controls_by_path.setdefault(path_id, []).append(control)

    by_path: list[dict[str, Any]] = []
    for attack_path in objects(package, "attack-paths"):
        path_id = str(attack_path.get("id"))
        impact = attack_path.get("impact", "critical")
        requirement = policy.interruption_requirement(impact)
        controls = controls_by_path.get(path_id, [])
        types = {control.get("interruption-type") for control in controls}
        by_path.append(
            {
                "path": path_id,
                "impact": impact,
                "controls": sorted(str(control.get("id")) for control in controls),
                "interruption-types": sorted(t for t in types if isinstance(t, str)),
                "before-outcome-satisfied": bool(
                    not requirement["require-before-outcome"]
                    or types & set(requirement["require-before-outcome"])
                ),
                "recovery-satisfied": bool(
                    not requirement["require-recovery"]
                    or types & set(requirement["require-recovery"])
                ),
            }
        )
    return {
        "paths-declared": len(by_path),
        "paths-fully-covered": sum(
            1
            for entry in by_path
            if entry["before-outcome-satisfied"] and entry["recovery-satisfied"]
        ),
        "by-path": by_path,
    }


def _control_test_status(states: list[ContractState]) -> dict[str, Any]:
    counts = {
        STATE_PASS: 0,
        STATE_FAIL: 0,
        STATE_INDETERMINATE: 0,
        STATE_NOT_APPLICABLE: 0,
    }
    for state in states:
        counts[state.state] = counts.get(state.state, 0) + 1
    return {
        "contracts-declared": len(states),
        "by-state": counts,
        "failing": sorted(s.contract_id for s in states if s.state == STATE_FAIL),
        "indeterminate": sorted(
            s.contract_id for s in states if s.state == STATE_INDETERMINATE
        ),
    }


def _evidence_freshness(package: Any, now: datetime) -> dict[str, Any]:
    """Freshness measured against the subject each contract actually claims about.

    An evidence item required by several contracts is measured against the
    strictest of them: the union of the subjects it has to cover, and the
    shortest freshness window any of them imposes. Taking one contract's
    requirement in isolation would report an item as current for a claim that
    another contract already considers stale.
    """
    required_digests: dict[str, set[str]] = {}
    overrides: dict[str, list[str]] = {}
    for contract in objects(package, "assurance-contracts"):
        digests = subject_digests_for(package, contract.get("subject"))
        override = contract.get("evidence-max-age")
        for evidence_id in contract.get("required-evidence", []) or []:
            if not isinstance(evidence_id, str):
                continue
            required_digests.setdefault(evidence_id, set()).update(digests)
            if isinstance(override, str):
                overrides.setdefault(evidence_id, []).append(override)

    deployed = component_digests(package)
    current: list[str] = []
    not_current: list[dict[str, Any]] = []
    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id"))
        currency = evidence_currency(
            evidence,
            now=now,
            required_digests=frozenset(required_digests.get(evidence_id, set())),
            deployed_digests=deployed,
            max_age_override=_shortest(overrides.get(evidence_id, [])),
        )
        if currency.current:
            current.append(evidence_id)
        else:
            not_current.append({"evidence": evidence_id, "reasons": list(currency.reasons)})

    return {
        "evidence-items": len(objects(package, "evidence")),
        "current": sorted(current),
        "not-current": sorted(not_current, key=lambda entry: entry["evidence"]),
        "gating-evidence-items": len(required_digests),
    }


def _open_findings_by_severity(package: Any) -> dict[str, Any]:
    counts = {severity: 0 for severity in SEVERITIES}
    open_ids: dict[str, list[str]] = {severity: [] for severity in SEVERITIES}
    for finding in objects(package, "findings"):
        if finding.get("status", "open") not in ("open", "in-progress"):
            continue
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
            open_ids[severity].append(str(finding.get("id")))
    return {
        "open-by-severity": counts,
        "open-ids-by-severity": {k: sorted(v) for k, v in open_ids.items()},
    }


def _recovery_readiness(package: Any, states: list[ContractState]) -> dict[str, Any]:
    by_id = {state.contract_id: state for state in states}
    control_index = unique_index(objects(package, "control-implementations"))

    recovery_controls = {
        str(control.get("id"))
        for control in control_index.values()
        if control.get("interruption-type") in RECOVERY_INTERRUPTION_TYPES
        or control.get("function") in RECOVERY_FUNCTIONS
    }
    verified: list[str] = []
    unverified: list[str] = []
    for contract in objects(package, "assurance-contracts"):
        if contract.get("control") not in recovery_controls:
            continue
        state = by_id.get(str(contract.get("id")))
        target = verified if state is not None and state.state == STATE_PASS else unverified
        target.append(str(contract.get("id")))

    paths_with_recovery = {
        path_id
        for control in control_index.values()
        if str(control.get("id")) in recovery_controls
        for path_id in control.get("attack-paths", []) or []
        if isinstance(path_id, str)
    }
    all_paths = {str(path.get("id")) for path in objects(package, "attack-paths")}

    return {
        "recovery-controls": sorted(recovery_controls),
        "verified-recovery-contracts": sorted(verified),
        "unverified-recovery-contracts": sorted(unverified),
        "paths-without-recovery-control": sorted(all_paths - paths_with_recovery),
    }


def _probabilistic_dependence(package: Any, states: list[ContractState]) -> dict[str, Any]:
    gating = [state for state in states if state.state != STATE_NOT_APPLICABLE]
    dependent = [state.contract_id for state in gating if state.depends_on_probabilistic]
    probabilistic_evidence = [
        str(evidence.get("id"))
        for evidence in objects(package, "evidence")
        if evidence.get("class") == "probabilistic-inference"
    ]
    return {
        "gating-contracts": len(gating),
        "gating-contracts-depending-on-inference": sorted(dependent),
        "probabilistic-evidence-items": sorted(probabilistic_evidence),
        "share-of-gating-contracts": (
            round(len(dependent) / len(gating), 4) if gating else 0.0
        ),
    }


def _exception_age(package: Any, now: datetime) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for decision in objects(package, "decisions"):
        if decision.get("decision-type") not in ("exception", "not-applicable"):
            continue
        try:
            expiry = parse_date(decision.get("expiry"))
        except TimestampError:
            entries.append(
                {
                    "decision": str(decision.get("id")),
                    "type": decision.get("decision-type"),
                    "expiry": decision.get("expiry"),
                    "days-remaining": None,
                    "expired": None,
                }
            )
            continue
        remaining = (expiry - now.date()).days
        entries.append(
            {
                "decision": str(decision.get("id")),
                "type": decision.get("decision-type"),
                "applies-to": sorted(decision.get("applies-to", []) or []),
                "decision-maker": decision.get("decision-maker"),
                "expiry": expiry.isoformat(),
                "days-remaining": remaining,
                "expired": remaining < 0,
            }
        )
    return {
        "exceptions": sorted(entries, key=lambda entry: entry["decision"]),
        "expired-exceptions": sorted(
            entry["decision"] for entry in entries if entry.get("expired")
        ),
    }


def conformance_summary(
    package: Any,
    *,
    now: datetime,
    policy: Policy | None = None,
    states: list[ContractState] | None = None,
) -> dict[str, Any]:
    """Report the eight dimensions A.5 requires. Deliberately no overall score."""
    if policy is None:
        policy = default_policy()
    if states is None:
        states = evaluate_contracts(package, now=now, policy=policy)

    return {
        "package-id": package.get("package-id") if isinstance(package, dict) else None,
        "evaluated-at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy": policy.name,
        "threat-model-completeness": _threat_model_completeness(package),
        "path-interruption-coverage": _path_interruption_coverage(package, policy),
        "control-test-status": _control_test_status(states),
        "evidence-freshness": _evidence_freshness(package, now),
        "open-findings-by-severity": _open_findings_by_severity(package),
        "recovery-readiness": _recovery_readiness(package, states),
        "probabilistic-evidence-dependence": _probabilistic_dependence(package, states),
        "exception-age": _exception_age(package, now),
    }


def format_summary(summary: dict[str, Any]) -> str:
    threat = summary["threat-model-completeness"]
    coverage = summary["path-interruption-coverage"]
    status = summary["control-test-status"]
    freshness = summary["evidence-freshness"]
    findings = summary["open-findings-by-severity"]["open-by-severity"]
    recovery = summary["recovery-readiness"]
    inference = summary["probabilistic-evidence-dependence"]
    exceptions = summary["exception-age"]

    lines = [
        f"Conformance summary for {summary['package-id']} "
        f"at {summary['evaluated-at']} under {summary['policy']}",
        "",
        f"Threat-model completeness       {threat['threats-with-contracts']}/"
        f"{threat['threats-declared']} threats have contracts",
        f"Path-interruption coverage      {coverage['paths-fully-covered']}/"
        f"{coverage['paths-declared']} paths meet their impact tier's requirements",
        "Control-test status             "
        + ", ".join(f"{count} {state}" for state, count in status["by-state"].items()),
        f"Evidence freshness              {len(freshness['current'])}/"
        f"{freshness['evidence-items']} evidence items current",
        "Open findings by severity       "
        + ", ".join(f"{count} {severity}" for severity, count in findings.items()),
        f"Recovery readiness              "
        f"{len(recovery['verified-recovery-contracts'])} verified, "
        f"{len(recovery['unverified-recovery-contracts'])} unverified recovery contracts",
        f"Probabilistic dependence        "
        f"{len(inference['gating-contracts-depending-on-inference'])}/"
        f"{inference['gating-contracts']} gating contracts rely on inference",
        f"Exception age                   {len(exceptions['exceptions'])} exception(s), "
        f"{len(exceptions['expired-exceptions'])} expired",
        "",
        "No aggregate score is reported. A single number would conceal which of the",
        "dimensions above is weak, which is the reason the framework refuses to define one.",
    ]
    for entry in coverage["by-path"]:
        if entry["before-outcome-satisfied"] and entry["recovery-satisfied"]:
            continue
        gaps = []
        if not entry["before-outcome-satisfied"]:
            gaps.append("no interruption before the harmful outcome")
        if not entry["recovery-satisfied"]:
            gaps.append("no recovery control")
        lines.append(f"  unresolved: {entry['path']} ({entry['impact']}): {'; '.join(gaps)}")
    for entry in freshness["not-current"]:
        lines.append(f"  unresolved: {entry['evidence']}: {entry['reasons'][0]}")
    for contract_id in status["failing"]:
        lines.append(f"  unresolved: {contract_id} is fail")
    for contract_id in status["indeterminate"]:
        lines.append(f"  unresolved: {contract_id} is indeterminate")
    return "\n".join(lines)


__all__ = [
    "SUMMARY_DIMENSIONS",
    "conformance_summary",
    "format_summary",
]
