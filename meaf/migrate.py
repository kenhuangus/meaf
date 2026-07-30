"""Migration from MEAF 1.0.0 packages to 2.0.0.

The 2.0.0 object model separates control implementations from assurance
contracts, and adds fields that 1.0.0 packages simply do not contain: the impact
of an attack path, the enforcement mode and failure behaviour of a control, the
evidence source, the benign-task utility thresholds of an adversarial test.

This module does the structural half of the migration and refuses to invent the
rest. Where a 2.0.0 field can be derived from 1.0.0 content it is derived. Where
it cannot, the field is **omitted** rather than filled with a plausible default,
so that level 1 validation names the exact gap and a human supplies the answer.
Every one of those gaps is a risk judgment: how bad is this path, does this
control fail open. Guessing them would put a number on somebody's risk register
that nobody chose.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from meaf.model import objects, parse_duration, unique_index

SOURCE_VERSION = "1.0.0"
TARGET_VERSION = "2.0.0"

#: 1.0.0 temporal-profile prose that maps unambiguously onto a 2.0.0 enum value.
PERSISTENCE_MAP = {
    "session": "session",
    "request": "session",
    "single-interaction": "session",
    "cross-session": "cross-session",
    "model-version": "model-version",
    "agent-identity": "agent-identity",
    "ecosystem": "ecosystem",
    "ecosystem-lifetime": "ecosystem",
}

COMPOUNDING_MAP = {
    "none": "none",
    "cumulative": "cumulative",
    "thresholded": "thresholded",
    "feedback-driven": "feedback-driven",
}

REVERSIBILITY_MAP = {
    "automatic": "automatic",
    "checkpoint-dependent": "checkpoint-dependent",
    "reconstruction-dependent": "reconstruction-dependent",
    "model-replacement": "model-replacement",
    "unknown": "unknown",
}

EXPOSURE_MAP = {
    "turn": "turn",
    "retrieval": "retrieval",
    "memory-write": "memory-write",
    "tool-call": "tool-call",
    "delegation": "delegation",
    "task": "task",
    "wall-clock-interval": "wall-clock-interval",
    "user-interaction": "turn",
}

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
}

GATE_DECISION_MAP = {
    "approve": "approve",
    "approved": "approve",
    "approve-with-conditions": "approve-with-conditions",
    "approve-with-monitoring": "approve-with-conditions",
    "deny": "deny",
    "denied": "deny",
    "defer": "defer",
}


@dataclass
class MigrationReport:
    """What the migration did, and what a human still has to decide."""

    derived: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.manual

    def to_dict(self) -> dict[str, Any]:
        return {"derived": list(self.derived), "requires-decision": list(self.manual)}


def _shortest_duration(values: list[str]) -> str | None:
    best: tuple[float, str] | None = None
    for value in values:
        try:
            seconds = parse_duration(value)
        except Exception:
            continue
        if best is None or seconds < best[0]:
            best = (seconds, value)
    return best[1] if best else None


def _control_id_for(contract_id: str) -> str:
    stem = contract_id[3:] if contract_id.startswith("ac-") else contract_id
    return f"ctl-{stem}"


def _derive_roles(package: Any, report: MigrationReport) -> list[dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}

    def add(value: Any) -> None:
        if isinstance(value, str) and value and value not in seen:
            seen[value] = {"id": value, "title": value.replace("-", " ")}

    system = package.get("system", {}) or {}
    add(system.get("owner"))
    for contract in objects(package, "assurance-contracts"):
        add(contract.get("owner"))
    for decision in objects(package, "decisions"):
        add(decision.get("decision-maker"))

    report.derived.append(
        f"system.responsible-roles derived from {len(seen)} distinct owner and "
        "decision-maker value(s); review the titles"
    )
    return [seen[key] for key in sorted(seen)]


def _migrate_temporal_profile(
    profile: Any, threat_id: str, report: MigrationReport
) -> dict[str, Any]:
    if not isinstance(profile, dict):
        return {}
    migrated: dict[str, Any] = {}

    for source_key, mapping in (
        ("persistence", PERSISTENCE_MAP),
        ("compounding-rule", COMPOUNDING_MAP),
        ("reversibility", REVERSIBILITY_MAP),
        ("exposure-unit", EXPOSURE_MAP),
    ):
        value = profile.get(source_key)
        mapped = mapping.get(str(value).lower()) if value is not None else None
        if mapped is not None:
            migrated[source_key] = mapped
        else:
            report.manual.append(
                f"threats/{threat_id}/temporal-profile/{source_key}: "
                f"{value!r} has no 2.0.0 enum equivalent; choose one"
            )

    latency = profile.get("activation-latency")
    if isinstance(latency, str) and latency in (
        "immediate",
        "trigger-conditional",
        "unbounded",
        "unknown",
    ):
        migrated["activation-latency"] = latency
    else:
        report.manual.append(
            f"threats/{threat_id}/temporal-profile/activation-latency: {latency!r} is not "
            "an ISO 8601 duration or a recognised qualifier"
        )

    dormancy = profile.get("dormancy")
    if isinstance(dormancy, str) and dormancy in (
        "none",
        "trigger-conditional",
        "condition-conditional",
        "unknown",
    ):
        migrated["dormancy"] = dormancy
    else:
        report.manual.append(
            f"threats/{threat_id}/temporal-profile/dormancy: {dormancy!r} must become one of "
            "none, trigger-conditional, condition-conditional, unknown, with a dormancy-trigger"
        )

    report.manual.append(
        f"threats/{threat_id}/temporal-profile/detection-horizon: 1.0.0 recorded "
        f"{profile.get('detection-horizon')!r} as prose; state minimum-observations "
        "and/or observation-period"
    )
    report.manual.append(
        f"threats/{threat_id}/temporal-profile/recovery-objective: 1.0.0 recorded "
        f"{profile.get('recovery-objective')!r} as prose; state max-containment-time "
        "and max-acceptable-loss"
    )
    return migrated


def migrate_package(package: Any) -> tuple[dict[str, Any], MigrationReport]:
    """Return the 2.0.0-shaped package and a report of what still needs deciding."""
    report = MigrationReport()
    if not isinstance(package, dict):
        raise ValueError("package is not a JSON object")
    version = package.get("meaf-version")
    if version != SOURCE_VERSION:
        raise ValueError(
            f"expected a {SOURCE_VERSION} package, found meaf-version {version!r}"
        )

    source = copy.deepcopy(package)
    migrated: dict[str, Any] = {
        "meaf-version": TARGET_VERSION,
        "package-id": source.get("package-id"),
        "policy-bundle": {"id": "meaf-default", "version": "2.0.0"},
    }
    report.derived.append("policy-bundle set to meaf-default:2.0.0; change it if you fork the policy")

    system = dict(source.get("system", {}) or {})
    system["responsible-roles"] = _derive_roles(source, report)
    migrated["system"] = system

    components: list[dict[str, Any]] = []
    for component in objects(source, "components"):
        entry = dict(component)
        entry.setdefault("dependencies", [])
        report.manual.append(
            f"components/{component.get('id')}/provider: name the supplying party"
        )
        if str(component.get("digest", "")).startswith("sha256:REPLACE_WITH"):
            report.manual.append(
                f"components/{component.get('id')}/digest: placeholder digests are no "
                "longer accepted; run `python -m meaf attest --update`"
            )
        if entry.get("artifact-path"):
            report.manual.append(
                f"components/{component.get('id')}/artifact-path: paths are now resolved "
                "relative to the package file, not the repository root"
            )
        components.append(entry)
    migrated["components"] = components

    threats: list[dict[str, Any]] = []
    for threat in objects(source, "threats"):
        entry = dict(threat)
        threat_id = str(threat.get("id"))
        entry["temporal-profile"] = _migrate_temporal_profile(
            threat.get("temporal-profile"), threat_id, report
        )
        report.manual.append(f"threats/{threat_id}/stage: name the lifecycle stage")
        report.manual.append(f"threats/{threat_id}/preconditions: list what must hold first")
        report.manual.append(f"threats/{threat_id}/target: name the affected asset")
        threats.append(entry)
    migrated["threats"] = threats

    paths: list[dict[str, Any]] = []
    for attack_path in objects(source, "attack-paths"):
        entry = dict(attack_path)
        report.manual.append(
            f"attack-paths/{attack_path.get('id')}/impact: rate the harmful outcome "
            "critical, high, medium or low; the policy bundle keys interruption "
            "requirements off it"
        )
        nodes = entry.get("nodes") or []
        edges = entry.get("edges") or []
        if len(edges) != max(len(nodes) - 1, 0):
            report.manual.append(
                f"attack-paths/{attack_path.get('id')}/edges: {len(nodes)} nodes now "
                f"require {max(len(nodes) - 1, 0)} edges, one per traversal step"
            )
        paths.append(entry)
    migrated["attack-paths"] = paths

    threat_index = unique_index(objects(source, "threats"))
    evidence_index = unique_index(objects(source, "evidence"))

    controls: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []
    for contract in objects(source, "assurance-contracts"):
        contract_id = str(contract.get("id"))
        control_id = _control_id_for(contract_id)

        path_ids = sorted(
            {
                threat_index[threat_id]["path"]
                for threat_id in contract.get("threats", []) or []
                if threat_id in threat_index
                and isinstance(threat_index[threat_id].get("path"), str)
            }
        )
        control: dict[str, Any] = {
            "id": control_id,
            "description": str(contract.get("claim", "")),
            "function": contract.get("function"),
            "owner": contract.get("owner"),
            "implementation-location": contract.get("interruption-point"),
            "dependencies": [],
            "attack-paths": path_ids,
            "interruption-point": contract.get("interruption-point"),
            "interruption-type": contract.get("interruption-type"),
        }
        controls.append({key: value for key, value in control.items() if value is not None})
        report.derived.append(
            f"control-implementations/{control_id} split out of {contract_id}"
        )
        report.manual.append(
            f"control-implementations/{control_id}/enforcement-mode: is it enforcing, "
            "monitoring or advisory?"
        )
        report.manual.append(
            f"control-implementations/{control_id}/failure-behavior: does it fail closed, "
            "fail open, degrade or alert only?"
        )
        report.manual.append(
            f"control-implementations/{control_id}/description: replace the copied claim "
            "with a description of the mechanism"
        )
        if not path_ids:
            report.manual.append(
                f"control-implementations/{control_id}/attack-paths: no path could be "
                "derived from the contract's threats"
            )

        migrated_contract = {
            key: value
            for key, value in contract.items()
            if key not in ("interruption-point", "interruption-type")
        }
        migrated_contract["control"] = control_id

        classes = sorted(
            {
                evidence_index[evidence_id]["class"]
                for evidence_id in contract.get("required-evidence", []) or []
                if evidence_id in evidence_index
                and isinstance(evidence_index[evidence_id].get("class"), str)
            }
        )
        if classes:
            migrated_contract["evidence-classes"] = classes
            report.derived.append(
                f"{contract_id}/evidence-classes derived from its required evidence"
            )
        else:
            report.manual.append(
                f"assurance-contracts/{contract_id}/evidence-classes: name the acceptable "
                "evidence classes"
            )

        max_age = _shortest_duration(
            [
                evidence_index[evidence_id]["max-age"]
                for evidence_id in contract.get("required-evidence", []) or []
                if evidence_id in evidence_index
                and isinstance(evidence_index[evidence_id].get("max-age"), str)
            ]
        )
        if max_age:
            migrated_contract["evidence-max-age"] = max_age
            report.derived.append(
                f"{contract_id}/evidence-max-age set to {max_age}, the shortest window "
                "among its required evidence"
            )
        else:
            report.manual.append(
                f"assurance-contracts/{contract_id}/evidence-max-age: state the freshness "
                "this contract requires"
            )

        if not isinstance(contract.get("failure-action"), str) or contract[
            "failure-action"
        ] not in (
            "alert",
            "degrade-privileges",
            "block-deployment",
            "suspend-autonomous-operation",
            "quarantine-memory",
            "invoke-recovery",
        ):
            migrated_contract["failure-action-detail"] = str(contract.get("failure-action", ""))
            migrated_contract.pop("failure-action", None)
            report.manual.append(
                f"assurance-contracts/{contract_id}/failure-action: the 1.0.0 prose moved "
                "to failure-action-detail; choose one of the six enumerated actions"
            )
        contracts.append(migrated_contract)

    migrated["control-implementations"] = controls
    migrated["assurance-contracts"] = contracts

    tests: list[dict[str, Any]] = []
    for test in objects(source, "tests"):
        entry = dict(test)
        test_id = str(test.get("id"))
        report.manual.append(
            f"tests/{test_id}/adversarial: does this test exercise attacker behaviour? "
            "adversarial tests must also state benign-task utility thresholds"
        )
        report.manual.append(
            f"tests/{test_id}/test-pack: cite one of the nine standard packs, or accept "
            "the warning that its coverage cannot be compared"
        )
        if "runner" in entry:
            report.manual.append(
                f"tests/{test_id}/evidence-class: a test with a runner must say whether it "
                "produces a deterministic observation or a probabilistic inference"
            )
            command = entry["runner"].get("command") or []
            if command:
                report.manual.append(
                    f"tests/{test_id}/runner/command: paths are now resolved relative to "
                    "the package file, not the repository root"
                )
        tests.append(entry)
    migrated["tests"] = tests

    evidence_items: list[dict[str, Any]] = []
    for evidence in objects(source, "evidence"):
        entry = dict(evidence)
        evidence_id = str(evidence.get("id"))
        report.manual.append(
            f"evidence/{evidence_id}/source: name the system of record it came from"
        )
        if evidence.get("class") == "probabilistic-inference":
            report.manual.append(
                f"evidence/{evidence_id}/model-metadata: add evaluator-prompt-digest, "
                "known-failure-modes and escalation-path"
            )
        if isinstance(entry.get("signature"), dict):
            report.manual.append(
                f"evidence/{evidence_id}/signature: the signed payload changed, so this "
                "evidence must be re-signed by its collector"
            )
        evidence_items.append(entry)
    migrated["evidence"] = evidence_items

    findings: list[dict[str, Any]] = []
    for finding in objects(source, "findings"):
        entry = dict(finding)
        severity = SEVERITY_MAP.get(str(finding.get("severity", "")).lower())
        if severity:
            entry["severity"] = severity
        else:
            entry.pop("severity", None)
            report.manual.append(
                f"findings/{finding.get('id')}/severity: {finding.get('severity')!r} must "
                "become critical, high, medium or low"
            )
        findings.append(entry)
    migrated["findings"] = findings

    decisions: list[dict[str, Any]] = []
    for decision in objects(source, "decisions"):
        entry = dict(decision)
        decision_id = str(decision.get("id"))
        gate = GATE_DECISION_MAP.get(str(decision.get("gate-decision", "")).lower())
        if gate:
            entry["gate-decision"] = gate
            entry["decision-type"] = "authorization"
            report.derived.append(
                f"decisions/{decision_id} typed as an authorization with verdict {gate}"
            )
        else:
            entry.pop("gate-decision", None)
            report.manual.append(
                f"decisions/{decision_id}/gate-decision: {decision.get('gate-decision')!r} "
                "must become approve, approve-with-conditions, deny or defer"
            )
            report.manual.append(
                f"decisions/{decision_id}/decision-type: authorization, exception or "
                "not-applicable?"
            )
        compensating = entry.get("compensating-controls") or []
        entry["compensating-controls"] = [
            _control_id_for(str(item)) if str(item).startswith("ac-") else item
            for item in compensating
        ]
        if compensating:
            report.derived.append(
                f"decisions/{decision_id}/compensating-controls repointed at the control "
                "implementations split out of the referenced contracts"
            )
        decisions.append(entry)
    migrated["decisions"] = decisions

    if "lifecycle" in source:
        migrated["lifecycle"] = source["lifecycle"]

    return migrated, report


def format_report(report: MigrationReport) -> str:
    lines = ["Derived automatically:", ""]
    lines.extend(f"  {item}" for item in report.derived)
    lines.extend(["", f"Requires a human decision ({len(report.manual)}):", ""])
    lines.extend(f"  {item}" for item in report.manual)
    lines.extend(
        [
            "",
            "Fields that could not be derived were omitted rather than guessed. Run"
            " `python -m meaf validate` on the migrated package: level 1 will name each"
            " missing field, and each one is a risk judgment only you can make.",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "MigrationReport",
    "SOURCE_VERSION",
    "TARGET_VERSION",
    "format_report",
    "migrate_package",
]
