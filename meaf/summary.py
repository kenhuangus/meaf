"""Conforming assurance summary per MEAF appendix A.5 (no aggregate score)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from meaf.contracts import evaluate_contracts
from meaf.lifecycle import current_state
from meaf.validator import (
    CONTAIN_TYPES,
    DETECT_TYPES,
    evidence_is_fresh,
    parse_datetime,
)

SUMMARY_KEYS = frozenset(
    {
        "threat-model-completeness",
        "path-interruption-coverage",
        "control-test-status",
        "evidence-freshness",
        "open-findings-by-severity",
        "recovery-readiness",
        "probabilistic-evidence-dependence",
        "exception-age",
    }
)


def _contracts_by_threat(package: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for contract in package.get("assurance-contracts", []):
        for threat_id in contract.get("threats", []):
            index.setdefault(threat_id, []).append(contract)
    return index


def _contracts_by_path(package: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_threat = _contracts_by_threat(package)
    by_path: dict[str, list[dict[str, Any]]] = {}
    for threat in package.get("threats", []):
        path_id = threat.get("path")
        if not path_id:
            continue
        for contract in by_threat.get(threat["id"], []):
            by_path.setdefault(path_id, []).append(contract)
    return by_path


def _path_has_detect_or_block(contracts: list[dict[str, Any]]) -> bool:
    return any(c.get("interruption-type") in DETECT_TYPES for c in contracts)


def _path_has_contain_or_restore(contracts: list[dict[str, Any]]) -> bool:
    return any(c.get("interruption-type") in CONTAIN_TYPES for c in contracts)


def _contract_evidence_current(
    contract: dict[str, Any],
    evidence_index: dict[str, dict[str, Any]],
    now: datetime,
) -> bool:
    required = contract.get("required-evidence", [])
    if not required:
        return False
    for evidence_id in required:
        evidence = evidence_index.get(evidence_id)
        if evidence is None:
            return False
        if evidence.get("invalidated-at") is not None:
            return False
        try:
            if not evidence_is_fresh(
                evidence["collected-at"],
                evidence["max-age"],
                evidence.get("invalidated-at"),
                now,
            ):
                return False
        except ValueError:
            return False
        if evidence.get("result") != "pass":
            return False
    return True


def _decision_oldest_timestamp(
    package: dict[str, Any],
    decision: dict[str, Any],
    evidence_index: dict[str, dict[str, Any]],
) -> datetime:
    contract_ids = set(decision.get("compensating-controls", []))
    timestamps: list[datetime] = []
    for contract in package.get("assurance-contracts", []):
        if contract["id"] not in contract_ids:
            continue
        for evidence_id in contract.get("required-evidence", []):
            evidence = evidence_index.get(evidence_id)
            if evidence is None:
                continue
            try:
                timestamps.append(parse_datetime(evidence["collected-at"]))
            except ValueError:
                continue
    expiry = decision.get("expiry")
    if expiry:
        try:
            expiry_dt = datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc)
            timestamps.append(expiry_dt)
        except ValueError:
            pass
    if not timestamps:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    return min(timestamps)


def build_summary(
    package: dict[str, Any],
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    now = now.astimezone(timezone.utc)
    evidence_index = {item["id"]: item for item in package.get("evidence", [])}
    threats = package.get("threats", [])
    contracts_by_threat = _contracts_by_threat(package)
    threats_with_contract = sum(
        1 for threat in threats if contracts_by_threat.get(threat["id"])
    )

    paths = package.get("attack-paths", [])
    contracts_by_path = _contracts_by_path(package)
    with_detect = 0
    with_contain = 0
    fully_covered = 0
    recovery_ready_paths = 0
    for path in paths:
        path_id = path["id"]
        path_contracts = contracts_by_path.get(path_id, [])
        has_detect = _path_has_detect_or_block(path_contracts)
        has_contain = _path_has_contain_or_restore(path_contracts)
        if has_detect:
            with_detect += 1
        if has_contain:
            with_contain += 1
        if has_detect and has_contain:
            fully_covered += 1
        containment_contracts = [
            c
            for c in path_contracts
            if c.get("interruption-type") in CONTAIN_TYPES
        ]
        if any(
            _contract_evidence_current(c, evidence_index, now)
            for c in containment_contracts
        ):
            recovery_ready_paths += 1

    evaluations = evaluate_contracts(package, now=now, keyring=keyring, root=root)
    control_status = Counter(evaluation["state"] for evaluation in evaluations)

    current_evidence = 0
    stale_evidence = 0
    invalidated_evidence = 0
    for evidence in package.get("evidence", []):
        if evidence.get("invalidated-at") is not None:
            invalidated_evidence += 1
            continue
        try:
            if evidence_is_fresh(
                evidence["collected-at"],
                evidence["max-age"],
                evidence.get("invalidated-at"),
                now,
            ):
                current_evidence += 1
            else:
                stale_evidence += 1
        except ValueError:
            stale_evidence += 1

    findings_by_severity: dict[str, int] = {}
    for finding in package.get("findings", []):
        severity = finding.get("severity", "unknown")
        findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

    probabilistic_ids = {
        item["id"]
        for item in package.get("evidence", [])
        if item.get("class") == "probabilistic-inference"
    }
    total_evidence = len(package.get("evidence", []))
    probabilistic_count = len(probabilistic_ids)
    contracts_with_prob = 0
    for contract in package.get("assurance-contracts", []):
        required = set(contract.get("required-evidence", []))
        if required & probabilistic_ids:
            contracts_with_prob += 1

    exception_entries: list[dict[str, Any]] = []
    for decision in package.get("decisions", []):
        expiry = decision.get("expiry", "")
        expired = False
        if expiry:
            try:
                expiry_date = datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc)
                expired = expiry_date.date() < now.date()
            except ValueError:
                expired = False
        oldest = _decision_oldest_timestamp(package, decision, evidence_index)
        age_days = max(0, int((now - oldest).total_seconds() // 86400))
        exception_entries.append(
            {
                "id": decision.get("id"),
                "expiry": expiry,
                "expired": expired,
                "age-days": age_days,
            }
        )

    fraction = (
        probabilistic_count / total_evidence if total_evidence else 0.0
    )

    return {
        "threat-model-completeness": {
            "total": len(threats),
            "with-contract": threats_with_contract,
            "lacking-contract": len(threats) - threats_with_contract,
        },
        "path-interruption-coverage": {
            "total": len(paths),
            "with-detect-or-block": with_detect,
            "with-contain-or-restore": with_contain,
            "fully-covered": fully_covered,
        },
        "control-test-status": {
            "not-applicable": control_status.get("not-applicable", 0),
            "fail": control_status.get("fail", 0),
            "indeterminate": control_status.get("indeterminate", 0),
            "pass": control_status.get("pass", 0),
        },
        "evidence-freshness": {
            "current": current_evidence,
            "stale": stale_evidence,
            "invalidated": invalidated_evidence,
        },
        "open-findings-by-severity": findings_by_severity,
        "recovery-readiness": {
            "paths-with-current-containment-evidence": recovery_ready_paths,
            "total-paths": len(paths),
            "lifecycle-state": current_state(package),
        },
        "probabilistic-evidence-dependence": {
            "probabilistic-evidence-count": probabilistic_count,
            "total-evidence-count": total_evidence,
            "fraction-probabilistic": fraction,
            "contracts-with-probabilistic-dependence": contracts_with_prob,
        },
        "exception-age": exception_entries,
    }
