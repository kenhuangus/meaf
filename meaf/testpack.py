"""Test-pack execution, decision-rule evaluation, and evidence emission.

Three rules shape this module.

*Indeterminate is not failure.* A runner that crashes, times out, or prints
something unparseable has told us nothing about the system. Reporting that as
``fail`` would be as wrong as reporting it as ``pass``; both invent an
observation that was never made.

*A decision rule that cannot be evaluated must say so.* An earlier version
recognised only keys ending ``-max`` or ``-min`` and silently discarded the
rest, so the manuscript's own ``minimum-paired-cases: 500`` was dropped without
a word. Every key is now either evaluated or reported as unevaluable.

*Security without utility is not a result.* Appendix A.7: "A control that
prevents all influence by refusing every contested topic ... has not
demonstrated acceptable resilient performance." An adversarial test that meets
its security thresholds while missing its utility thresholds fails.

Runners are arbitrary commands named by the package, so ``run-tests`` executes
code the package author chose. Only run test packs from packages you trust, on
a host you are willing to give that trust. The subprocess environment is
reduced to a minimal allow-list rather than inherited, but that is a hardening
measure, not a sandbox.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from meaf.contract import contract_impact
from meaf.model import objects, unique_index
from meaf.signing import private_key_from_pem, sign_evidence

COLLECTOR = "meaf-testpack:1.0.0"

RESULT_PASS = "pass"
RESULT_FAIL = "fail"
RESULT_INDETERMINATE = "indeterminate"
RESULTS = (RESULT_PASS, RESULT_FAIL, RESULT_INDETERMINATE)

#: Argument-vector heads rewritten to the interpreter running MEAF. A bare
#: "python" is absent from PATH on current macOS and Debian, which silently
#: turned every run into an indeterminate result.
INTERPRETER_ALIASES = frozenset({"python", "python3"})

#: Environment passed to runners. Everything else is dropped so that a runner
#: cannot pick up ambient credentials from the operator's shell.
ENVIRONMENT_ALLOW_LIST = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")

SAMPLING_PREFIX = "minimum-"
DEFAULT_REMEDIATION_DAYS = 30


@dataclass(frozen=True)
class RuleEvaluation:
    """Outcome of applying one decision rule or utility rule to reported metrics."""

    result: str
    reasons: tuple[str, ...] = field(default=())
    unevaluable_keys: tuple[str, ...] = field(default=())


@dataclass
class ContractOutcome:
    contract_id: str
    result: str
    reasons: list[str]


@dataclass
class RunnerOutput:
    result: str
    metrics: dict[str, float]
    utility_metrics: dict[str, float]
    predicates: dict[str, bool]
    model_metadata: dict[str, Any] | None
    diagnostics: str


@dataclass
class TestRunResult:
    test_id: str
    runner_result: str
    metrics: dict[str, float]
    utility_metrics: dict[str, float]
    contract_outcomes: list[ContractOutcome]
    evidence: dict[str, Any]
    diagnostics: str

    @property
    def result(self) -> str:
        return self.evidence.get("result", RESULT_INDETERMINATE)


def evaluate_rule(rule: Any, metrics: dict[str, float], predicates: dict[str, bool]) -> RuleEvaluation:
    """Evaluate a decision rule or utility rule against reported observations.

    Recognised key forms:

    ``<metric>-max`` / ``<metric>-min`` / ``<metric>-exact``
        numeric bound on the named metric
    ``minimum-<metric>``
        sampling adequacy: the named metric must reach the stated count
    ``<predicate>`` with a boolean value
        a deterministic policy predicate the runner reports in ``predicates``

    Anything else is reported as unevaluable and drives the result to
    ``indeterminate`` rather than being ignored.
    """
    if not isinstance(rule, dict) or not rule:
        return RuleEvaluation(
            RESULT_INDETERMINATE, ("rule states no condition to evaluate",)
        )

    reasons: list[str] = []
    unevaluable: list[str] = []
    failed = False
    missing = False

    for key in sorted(rule):
        value = rule[key]
        if isinstance(value, bool):
            observed = predicates.get(key)
            if observed is None:
                missing = True
                reasons.append(f"predicate {key!r} was not reported by the runner")
            elif observed != value:
                failed = True
                reasons.append(f"predicate {key!r} is {observed}, rule requires {value}")
            continue

        if not isinstance(value, (int, float)):
            unevaluable.append(key)
            continue

        if key.startswith(SAMPLING_PREFIX):
            metric_name = key[len(SAMPLING_PREFIX) :]
            comparison = "min"
        elif key.endswith("-max"):
            metric_name, comparison = key[: -len("-max")], "max"
        elif key.endswith("-min"):
            metric_name, comparison = key[: -len("-min")], "min"
        elif key.endswith("-exact"):
            metric_name, comparison = key[: -len("-exact")], "exact"
        else:
            unevaluable.append(key)
            continue

        if metric_name not in metrics:
            missing = True
            reasons.append(f"metric {metric_name!r} was not reported by the runner")
            continue

        observed_value = metrics[metric_name]
        if comparison == "max" and observed_value > value:
            failed = True
            reasons.append(f"{metric_name}={observed_value} exceeds maximum {value}")
        elif comparison == "min" and observed_value < value:
            failed = True
            reasons.append(f"{metric_name}={observed_value} is below minimum {value}")
        elif comparison == "exact" and observed_value != value:
            failed = True
            reasons.append(f"{metric_name}={observed_value} is not exactly {value}")

    for key in unevaluable:
        reasons.append(f"rule key {key!r} states no evaluable condition")

    if failed:
        result = RESULT_FAIL
    elif missing or unevaluable:
        result = RESULT_INDETERMINATE
    else:
        result = RESULT_PASS
        reasons.append("every stated condition holds")

    return RuleEvaluation(result, tuple(reasons), tuple(unevaluable))


def evaluate_decision_rule(decision_rule: Any, metrics: dict[str, float]) -> str:
    """Backwards-compatible shorthand returning only the result string."""
    return evaluate_rule(decision_rule, metrics, {}).result


def resolve_command(command: list[str]) -> list[str]:
    """Rewrite a leading interpreter alias to the interpreter running MEAF."""
    if not command:
        return command
    head = str(command[0])
    if head in INTERPRETER_ALIASES:
        return [sys.executable, *command[1:]]
    return list(command)


def _runner_environment() -> dict[str, str]:
    return {
        name: os.environ[name]
        for name in ENVIRONMENT_ALLOW_LIST
        if name in os.environ
    }


def _numeric_map(raw: Any) -> dict[str, float]:
    if not isinstance(raw, dict):
        return {}
    return {
        name: float(value)
        for name, value in raw.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


def _boolean_map(raw: Any) -> dict[str, bool]:
    if not isinstance(raw, dict):
        return {}
    return {name: value for name, value in raw.items() if isinstance(value, bool)}


def parse_runner_output(stdout: str) -> RunnerOutput:
    """Parse the runner stdout contract, defaulting to indeterminate."""
    try:
        payload = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return RunnerOutput(
            RESULT_INDETERMINATE, {}, {}, {}, None, "runner stdout is not valid JSON"
        )
    if not isinstance(payload, dict):
        return RunnerOutput(
            RESULT_INDETERMINATE, {}, {}, {}, None, "runner stdout is not a JSON object"
        )
    result = payload.get("result", RESULT_INDETERMINATE)
    if result not in RESULTS:
        return RunnerOutput(
            RESULT_INDETERMINATE,
            {},
            {},
            {},
            None,
            f"runner reported unknown result {result!r}",
        )
    model_metadata = payload.get("model-metadata")
    return RunnerOutput(
        result=result,
        metrics=_numeric_map(payload.get("metrics")),
        utility_metrics=_numeric_map(payload.get("utility-metrics")),
        predicates=_boolean_map(payload.get("predicates")),
        model_metadata=model_metadata if isinstance(model_metadata, dict) else None,
        diagnostics=str(payload.get("diagnostics", "")),
    )


def run_test_subprocess(runner: dict[str, Any], *, cwd: Path | None = None) -> RunnerOutput:
    """Execute a runner and return its parsed output, never raising."""
    command = resolve_command(runner.get("command", []) or [])
    if not command:
        return RunnerOutput(
            RESULT_INDETERMINATE, {}, {}, {}, None, "runner declares no command"
        )
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
            env=_runner_environment(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return RunnerOutput(
            RESULT_INDETERMINATE, {}, {}, {}, None, f"runner exceeded {timeout}s timeout"
        )
    except OSError as exc:
        return RunnerOutput(
            RESULT_INDETERMINATE, {}, {}, {}, None, f"runner could not be started: {exc}"
        )

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        return RunnerOutput(
            RESULT_INDETERMINATE,
            {},
            {},
            {},
            None,
            f"runner exited {completed.returncode}"
            + (f": {stderr.splitlines()[-1]}" if stderr else ""),
        )

    output = parse_runner_output(completed.stdout)
    if not output.diagnostics and completed.stderr.strip():
        output = RunnerOutput(
            output.result,
            output.metrics,
            output.utility_metrics,
            output.predicates,
            output.model_metadata,
            f"runner stderr: {completed.stderr.strip().splitlines()[-1]}",
        )
    return output


def _contracts_for_test(package: Any, test_id: str) -> list[dict[str, Any]]:
    return [
        contract
        for contract in objects(package, "assurance-contracts")
        if contract.get("test") == test_id
    ]


def _target_digests(package: Any, target: Any) -> list[str]:
    for component in objects(package, "components"):
        if component.get("id") == target and isinstance(component.get("digest"), str):
            return [component["digest"]]
    system = package.get("system") if isinstance(package, dict) else None
    if isinstance(system, dict) and system.get("id") == target:
        return [
            component["digest"]
            for component in objects(package, "components")
            if isinstance(component.get("digest"), str)
        ]
    return []


def build_evidence(
    package: Any,
    test: dict[str, Any],
    result: str,
    *,
    now: datetime,
    evidence_id: str | None = None,
    model_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the evidence object a test run produces.

    The evidence class comes from the test's declared ``evidence-class``. A test
    whose oracle is a model judgment produces probabilistic inference and must
    carry model metadata; labelling it as a deterministic observation would
    erase the distinction A.1 principle 2 exists to preserve.
    """
    test_id = test["id"]
    evidence_class = test.get("evidence-class", "deterministic-observation")
    evidence = {
        "id": evidence_id or f"ev-testpack-{test_id}-{now.strftime('%Y%m%dT%H%M%SZ')}",
        "class": evidence_class,
        "subject-digests": _target_digests(package, test.get("target")),
        "source": "meaf-testpack-run",
        "method": test.get("procedure", "test-pack-execution"),
        "collector": COLLECTOR,
        "collected-at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "max-age": test.get("evidence-max-age", "P30D"),
        "invalidated-at": None,
        "result": result,
    }
    if evidence_class == "probabilistic-inference" and model_metadata is not None:
        evidence["model-metadata"] = model_metadata
    return evidence


def _combine(runner_result: str, contract_results: list[str]) -> str:
    results = [runner_result, *contract_results]
    if RESULT_FAIL in results:
        return RESULT_FAIL
    if RESULT_INDETERMINATE in results:
        return RESULT_INDETERMINATE
    return RESULT_PASS


def execute_test(
    package: Any,
    test: dict[str, Any],
    *,
    now: datetime | None = None,
    cwd: Path | None = None,
    sign_with: Any | None = None,
) -> TestRunResult:
    """Run one test's runner and evaluate every contract that cites it."""
    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    test_id = test["id"]
    runner = test.get("runner")
    if not runner:
        raise ValueError(f"test {test_id!r} declares no runner")

    output = run_test_subprocess(runner, cwd=cwd)
    diagnostics = output.diagnostics

    utility = evaluate_rule(test.get("utility-thresholds"), output.utility_metrics, output.predicates)
    utility_applies = bool(test.get("adversarial")) and bool(test.get("utility-thresholds"))

    contract_outcomes: list[ContractOutcome] = []
    contract_results: list[str] = []
    for contract in _contracts_for_test(package, test_id):
        rule = evaluate_rule(contract.get("decision-rule"), output.metrics, output.predicates)
        reasons = [f"runner result: {output.result}"]
        reasons.extend(f"decision-rule: {reason}" for reason in rule.reasons)

        if output.result == RESULT_INDETERMINATE:
            combined = RESULT_INDETERMINATE
        elif output.result == RESULT_FAIL:
            combined = RESULT_FAIL
        else:
            combined = rule.result

        if utility_applies:
            reasons.extend(f"utility: {reason}" for reason in utility.reasons)
            if utility.result == RESULT_FAIL and combined == RESULT_PASS:
                combined = RESULT_FAIL
                reasons.append(
                    "security thresholds met but benign-task utility thresholds were not; "
                    "a control that refuses the task has not demonstrated resilience"
                )
            elif utility.result == RESULT_INDETERMINATE and combined == RESULT_PASS:
                combined = RESULT_INDETERMINATE

        contract_results.append(combined)
        contract_outcomes.append(
            ContractOutcome(contract_id=contract["id"], result=combined, reasons=reasons)
        )

    final_result = _combine(output.result, contract_results)
    evidence = build_evidence(
        package, test, final_result, now=now, model_metadata=output.model_metadata
    )
    if sign_with is not None:
        evidence = sign_evidence(evidence, sign_with, key_id=COLLECTOR)

    return TestRunResult(
        test_id=test_id,
        runner_result=output.result,
        metrics=output.metrics,
        utility_metrics=output.utility_metrics,
        contract_outcomes=contract_outcomes,
        evidence=evidence,
        diagnostics=diagnostics,
    )


def unrunnable_tests(package: Any, test_id: str | None = None) -> list[str]:
    """Tests selected for execution that declare no runner.

    Returned rather than skipped so the caller can report them: a test that was
    never executed must not look like a test that passed.
    """
    return [
        str(test.get("id"))
        for test in objects(package, "tests")
        if (test_id is None or test.get("id") == test_id) and "runner" not in test
    ]


def run_tests(
    package: Any,
    *,
    test_id: str | None = None,
    sign_with: Any | None = None,
    now: datetime | None = None,
    cwd: Path | None = None,
) -> list[TestRunResult]:
    """Execute every test with a runner, optionally narrowed to one test id."""
    results: list[TestRunResult] = []
    for test in objects(package, "tests"):
        if test_id is not None and test.get("id") != test_id:
            continue
        if "runner" not in test:
            continue
        results.append(execute_test(package, test, now=now, cwd=cwd, sign_with=sign_with))
    return results


def merge_evidence(package: Any, new_evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the package with new evidence merged in by id."""
    updated = copy.deepcopy(package)
    by_id = {item["id"]: item for item in updated.get("evidence", []) or []}
    for evidence in new_evidence:
        by_id[evidence["id"]] = evidence
    updated["evidence"] = list(by_id.values())
    return updated


def link_evidence_to_contracts(
    package: dict[str, Any],
    results: list[TestRunResult],
) -> dict[str, Any]:
    """Point each exercised contract's required-evidence at the run it produced.

    Without this the assurance loop never closes: a fresh run would emit
    evidence that no contract requires, leaving the contract to be evaluated
    against the run it superseded.

    Evidence from *earlier* runs of the same test is removed rather than kept
    alongside the new item. Appending would make a re-run strictly unable to
    return a contract to pass: the superseded run is still required, still
    ageing, and still bound to whatever was deployed when it ran.
    """
    updated = copy.deepcopy(package)
    evidence_by_test = {result.test_id: result.evidence["id"] for result in results}
    for contract in updated.get("assurance-contracts", []) or []:
        test_id = contract.get("test")
        new_evidence_id = evidence_by_test.get(test_id)
        if new_evidence_id is None:
            continue
        superseded_prefix = f"ev-testpack-{test_id}-"
        required = [
            evidence_id
            for evidence_id in contract.get("required-evidence", []) or []
            if not (
                isinstance(evidence_id, str)
                and evidence_id.startswith(superseded_prefix)
                and evidence_id != new_evidence_id
            )
        ]
        if new_evidence_id not in required:
            required.append(new_evidence_id)
        contract["required-evidence"] = required
    return updated


def _severity_for_impact(impact: str) -> str:
    return impact if impact in ("critical", "high", "medium", "low") else "high"


def findings_for_failures(
    package: Any,
    results: list[TestRunResult],
    *,
    now: datetime,
    remediation_days: int = DEFAULT_REMEDIATION_DAYS,
) -> list[dict[str, Any]]:
    """Build finding objects for every contract a run reported as fail.

    A.8 step 3 requires the assess activity to "create findings automatically
    for failed contracts, and record indeterminate results without coercion".
    Indeterminate outcomes deliberately produce no finding: there is nothing to
    remediate until somebody can say what happened.
    """
    contract_index = unique_index(objects(package, "assurance-contracts"))
    control_index = unique_index(objects(package, "control-implementations"))
    existing = {
        finding.get("failed-claim")
        for finding in objects(package, "findings")
        if finding.get("status", "open") in ("open", "in-progress")
    }

    created: list[dict[str, Any]] = []
    for result in results:
        for outcome in result.contract_outcomes:
            if outcome.result != RESULT_FAIL or outcome.contract_id in existing:
                continue
            contract = contract_index.get(outcome.contract_id, {})
            control = control_index.get(contract.get("control"), {})
            affected = [
                path_id
                for path_id in control.get("attack-paths", []) or []
                if isinstance(path_id, str)
            ]
            impact = contract_impact(package, contract) if contract else "high"
            created.append(
                {
                    "id": f"finding-{outcome.contract_id}-{now.strftime('%Y%m%dT%H%M%SZ')}",
                    "failed-claim": outcome.contract_id,
                    "severity": _severity_for_impact(impact),
                    "status": "open",
                    "detected-at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "affected-paths": affected or ["(unmapped)"],
                    "root-cause": "; ".join(outcome.reasons) or "contract evaluated to fail",
                    "corrective-action": contract.get(
                        "failure-action-detail",
                        contract.get("failure-action", "investigate and remediate"),
                    ),
                    "due-date": (now + timedelta(days=remediation_days)).date().isoformat(),
                    "retest-reference": result.test_id,
                }
            )
            existing.add(outcome.contract_id)
    return created


def merge_findings(package: dict[str, Any], new_findings: list[dict[str, Any]]) -> dict[str, Any]:
    updated = copy.deepcopy(package)
    updated["findings"] = [*(updated.get("findings") or []), *new_findings]
    return updated


def load_signing_key(path: Path) -> Any:
    return private_key_from_pem(path.read_bytes())


def run_exit_code(results: list[TestRunResult], unrunnable: list[str]) -> int:
    """0 only when every executed contract passed and nothing was left unrun."""
    if unrunnable:
        return 1
    for result in results:
        if result.result != RESULT_PASS:
            return 1
    return 0


def format_run_results(results: list[TestRunResult], unrunnable: list[str] | None = None) -> str:
    lines: list[str] = []
    for result in results:
        lines.append(f"Test {result.test_id}: runner={result.runner_result}")
        if result.diagnostics:
            lines.append(f"  diagnostics: {result.diagnostics}")
        for outcome in result.contract_outcomes:
            lines.append(f"  Contract {outcome.contract_id}: {outcome.result}")
            for reason in outcome.reasons:
                lines.append(f"    - {reason}")
        lines.append(f"  Evidence {result.evidence['id']}: {result.result}")
    for test_id in unrunnable or []:
        lines.append(f"Test {test_id}: not executed (no runner declared)")
    return "\n".join(lines)


__all__ = [
    "COLLECTOR",
    "ContractOutcome",
    "RESULTS",
    "RESULT_FAIL",
    "RESULT_INDETERMINATE",
    "RESULT_PASS",
    "RuleEvaluation",
    "RunnerOutput",
    "TestRunResult",
    "build_evidence",
    "evaluate_decision_rule",
    "evaluate_rule",
    "execute_test",
    "findings_for_failures",
    "format_run_results",
    "link_evidence_to_contracts",
    "load_signing_key",
    "merge_evidence",
    "merge_findings",
    "parse_runner_output",
    "resolve_command",
    "run_exit_code",
    "run_test_subprocess",
    "run_tests",
    "unrunnable_tests",
]
