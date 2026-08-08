"""Test-pack execution and evidence emission."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from meaf.signing import private_key_from_pem, sign_evidence
from meaf.validator import parse_datetime

COLLECTOR = "meaf-testpack:1.0.0"


@dataclass
class ContractOutcome:
    contract_id: str
    result: str
    details: str


@dataclass
class TestRunResult:
    test_id: str
    runner_result: str
    metrics: dict[str, float]
    contract_outcomes: list[ContractOutcome]
    evidence: dict[str, Any]


def _metric_rules(decision_rule: dict[str, Any]) -> list[tuple[str, str, float]]:
    """Return (metric_name, comparison, threshold) for -max/-min rule keys."""
    rules: list[tuple[str, str, float]] = []
    for key, value in decision_rule.items():
        if key.endswith("-max") and isinstance(value, (int, float)):
            metric = key[: -len("-max")]
            rules.append((metric, "max", float(value)))
        elif key.endswith("-min") and isinstance(value, (int, float)):
            metric = key[: -len("-min")]
            rules.append((metric, "min", float(value)))
    return rules


def evaluate_decision_rule(
    decision_rule: dict[str, Any],
    metrics: dict[str, float],
) -> str:
    """Evaluate metrics against decision-rule; indeterminate if metric missing."""
    rules = _metric_rules(decision_rule)
    if not rules:
        return "indeterminate"
    outcome = "pass"
    for metric_name, comparison, threshold in rules:
        if metric_name not in metrics:
            return "indeterminate"
        value = metrics[metric_name]
        if comparison == "max" and value > threshold:
            return "fail"
        if comparison == "min" and value < threshold:
            return "fail"
    return outcome


def _contracts_for_test(package: dict[str, Any], test_id: str) -> list[dict[str, Any]]:
    return [
        contract
        for contract in package.get("assurance-contracts", [])
        if contract.get("test") == test_id
    ]


def _target_digests(package: dict[str, Any], target: str) -> list[str]:
    for component in package.get("components", []):
        if component.get("id") == target:
            return [component["digest"]]
    if target == package.get("system", {}).get("id"):
        return [component["digest"] for component in package.get("components", [])]
    return []


def _parse_metrics(raw_metrics: Any) -> dict[str, float]:
    if not isinstance(raw_metrics, dict):
        return {}
    metrics: dict[str, float] = {}
    for name, value in raw_metrics.items():
        if isinstance(value, (int, float)):
            metrics[name] = float(value)
    return metrics


def _parse_runner_output(
    stdout: str,
) -> tuple[str, dict[str, float], dict[str, float]]:
    try:
        payload = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return "indeterminate", {}, {}
    if not isinstance(payload, dict):
        return "indeterminate", {}, {}
    result = payload.get("result", "indeterminate")
    if result not in ("pass", "fail", "indeterminate"):
        result = "indeterminate"
    raw_metrics = payload.get("metrics", {})
    if not isinstance(raw_metrics, dict):
        return "indeterminate", {}, {}
    metrics = _parse_metrics(raw_metrics)
    utility_metrics = _parse_metrics(payload.get("utility-metrics", {}))
    return result, metrics, utility_metrics


def run_test_subprocess(
    runner: dict[str, Any],
    *,
    cwd: Path | None = None,
) -> tuple[str, dict[str, float], dict[str, float]]:
    command = runner.get("command", [])
    timeout = runner.get("timeout-seconds", 60)
    workdir = runner.get("working-directory")
    run_cwd = Path(workdir) if workdir else cwd
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=run_cwd,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "indeterminate", {}, {}
    if completed.returncode != 0:
        return "indeterminate", {}, {}
    return _parse_runner_output(completed.stdout)


def _combine_results(runner_result: str, contract_results: list[str]) -> str:
    results = [runner_result, *contract_results]
    if "fail" in results:
        return "fail"
    if "indeterminate" in results:
        return "indeterminate"
    return "pass"


def evaluate_contract_rules(
    contract: dict[str, Any],
    metrics: dict[str, float],
    utility_metrics: dict[str, float] | None,
) -> str:
    """Evaluate security and optional utility rules; fail beats indeterminate."""
    security_result = evaluate_decision_rule(contract.get("decision-rule", {}), metrics)
    utility_rule = contract.get("utility-rule")
    if utility_rule:
        utility_result = evaluate_decision_rule(
            utility_rule,
            utility_metrics or {},
        )
        return _combine_results("pass", [security_result, utility_result])
    return security_result


def build_evidence(
    package: dict[str, Any],
    test: dict[str, Any],
    result: str,
    *,
    now: datetime,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    test_id = test["id"]
    eid = evidence_id or f"ev-testpack-{test_id}-{now.strftime('%Y%m%dT%H%M%SZ')}"
    return {
        "id": eid,
        "class": "deterministic-observation",
        "subject-digests": _target_digests(package, test.get("target", "")),
        "method": "test-pack-execution",
        "collector": COLLECTOR,
        "collected-at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "max-age": test.get("evidence-max-age", "P30D"),
        "invalidated-at": None,
        "result": result,
    }


def execute_test(
    package: dict[str, Any],
    test: dict[str, Any],
    *,
    now: datetime | None = None,
    cwd: Path | None = None,
    sign_with: Any | None = None,
) -> TestRunResult:
    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    test_id = test["id"]
    runner = test.get("runner")
    if not runner:
        raise ValueError(f"test {test_id!r} has no runner")

    runner_result, metrics, utility_metrics = run_test_subprocess(runner, cwd=cwd)
    contract_outcomes: list[ContractOutcome] = []
    contract_results: list[str] = []
    for contract in _contracts_for_test(package, test_id):
        rule_result = evaluate_contract_rules(contract, metrics, utility_metrics)
        if runner_result == "indeterminate":
            combined = "indeterminate"
        elif runner_result == "fail":
            combined = "fail"
        else:
            combined = rule_result
        contract_results.append(combined)
        contract_outcomes.append(
            ContractOutcome(
                contract_id=contract["id"],
                result=combined,
                details=(
                    f"runner={runner_result}, metrics={metrics}, "
                    f"utility-metrics={utility_metrics}, rule={rule_result}"
                ),
            )
        )

    final_result = _combine_results(runner_result, contract_results)
    evidence = build_evidence(package, test, final_result, now=now)
    if sign_with is not None:
        evidence = sign_evidence(evidence, sign_with, key_id=COLLECTOR)

    return TestRunResult(
        test_id=test_id,
        runner_result=runner_result,
        metrics=metrics,
        contract_outcomes=contract_outcomes,
        evidence=evidence,
    )


def run_tests(
    package: dict[str, Any],
    *,
    test_id: str | None = None,
    sign_with: Any | None = None,
    now: datetime | None = None,
    cwd: Path | None = None,
) -> list[TestRunResult]:
    results: list[TestRunResult] = []
    for test in package.get("tests", []):
        tid = test.get("id")
        if test_id is not None and tid != test_id:
            continue
        if "runner" not in test:
            continue
        results.append(
            execute_test(package, test, now=now, cwd=cwd, sign_with=sign_with)
        )
    return results


def merge_evidence(
    package: dict[str, Any],
    new_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    updated = copy.deepcopy(package)
    by_id = {item["id"]: item for item in updated.get("evidence", [])}
    for evidence in new_evidence:
        by_id[evidence["id"]] = evidence
    updated["evidence"] = list(by_id.values())
    return updated


def load_signing_key(path: Path) -> Any:
    return private_key_from_pem(path.read_bytes())


def format_run_results(results: list[TestRunResult]) -> str:
    lines: list[str] = []
    for result in results:
        lines.append(f"Test {result.test_id}: runner={result.runner_result}")
        for outcome in result.contract_outcomes:
            lines.append(f"  Contract {outcome.contract_id}: {outcome.result}")
    return "\n".join(lines)
