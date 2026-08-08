"""Assurance-contract state evaluation per MEAF appendix A.5."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from meaf.testpack import _metric_rules
from meaf.validator import evidence_is_fresh

CONTRACT_STATES = frozenset({"not-applicable", "fail", "indeterminate", "pass"})


def _evidence_index(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in package.get("evidence", [])}


def _has_decision_rule(contract: dict[str, Any]) -> bool:
    return bool(_metric_rules(contract.get("decision-rule", {})))


def _resolve_evidence_status(
    evidence_id: str,
    evidence_index: dict[str, dict[str, Any]],
    contract: dict[str, Any],
    now: datetime,
) -> str:
    evidence = evidence_index.get(evidence_id)
    if evidence is None:
        return "missing"
    if evidence.get("invalidated-at") is not None:
        return "invalidated"
    try:
        fresh = evidence_is_fresh(
            evidence["collected-at"],
            evidence["max-age"],
            evidence.get("invalidated-at"),
            now,
        )
    except ValueError:
        return "stale"
    if not fresh:
        return "stale"
    result = evidence.get("result")
    if result == "fail":
        return "fail"
    if result == "indeterminate":
        return "indeterminate"
    if (
        evidence.get("class") == "probabilistic-inference"
        and not _has_decision_rule(contract)
    ):
        return "indeterminate"
    if result == "pass":
        return "pass"
    return "indeterminate"


def evaluate_contract(
    package: dict[str, Any],
    contract: dict[str, Any],
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """Return contract-id, state, reason, and per-evidence status list."""
    del keyring, root  # reserved for future L4-aware evaluation

    contract_id = contract["id"]
    evidence_index = _evidence_index(package)
    required = contract.get("required-evidence", [])
    evidence_status = [
        {
            "evidence-id": evidence_id,
            "status": _resolve_evidence_status(
                evidence_id, evidence_index, contract, now
            ),
        }
        for evidence_id in required
    ]

    if contract.get("applicability") is not None:
        return {
            "contract-id": contract_id,
            "state": "not-applicable",
            "reason": "contract marked not applicable by named authority",
            "evidence-status": evidence_status,
        }

    statuses = [item["status"] for item in evidence_status]
    if any(status == "fail" for status in statuses):
        return {
            "contract-id": contract_id,
            "state": "fail",
            "reason": "required evidence has result fail",
            "evidence-status": evidence_status,
        }

    indeterminate_statuses = frozenset(
        {"missing", "stale", "invalidated", "indeterminate"}
    )
    if any(status in indeterminate_statuses for status in statuses):
        # INVARIANT: indeterminate must never be silently coerced to pass or fail.
        return {
            "contract-id": contract_id,
            "state": "indeterminate",
            "reason": "required evidence missing, stale, invalidated, or indeterminate",
            "evidence-status": evidence_status,
        }

    return {
        "contract-id": contract_id,
        "state": "pass",
        "reason": "all required evidence current with result pass",
        "evidence-status": evidence_status,
    }


def evaluate_contracts(
    package: dict[str, Any],
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> list[dict[str, Any]]:
    return [
        evaluate_contract(package, contract, now=now, keyring=keyring, root=root)
        for contract in package.get("assurance-contracts", [])
    ]


def format_contract_evaluations(evaluations: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for evaluation in evaluations:
        lines.append(
            f"{evaluation['contract-id']}: {evaluation['state']} ({evaluation['reason']})"
        )
    return "\n".join(lines)


def contracts_exit_code(evaluations: list[dict[str, Any]]) -> int:
    if any(evaluation["state"] == "fail" for evaluation in evaluations):
        return 1
    return 0
