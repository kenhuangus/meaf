"""Human-readable projections of a package (manuscript A.1 principle 6, A.8 step 2).

    Human-readable views are generated from the structured source. Narrative
    reports, diagrams, and dashboards are projections of the assurance package
    rather than separately maintained artifacts that can drift from it.

Everything this module emits is derived from the package and the evaluation
instant. Nothing here is authored by hand, so a report cannot describe coverage
the package does not have. Output is byte-deterministic for a fixed package,
policy and ``now``, which makes a generated report diffable in review and
committable next to the package it describes.

Diagrams are Mermaid, which renders inline on GitHub and in most Markdown
viewers without a build step or an external service.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from meaf.contract import (
    STATE_FAIL,
    STATE_INDETERMINATE,
    STATE_NOT_APPLICABLE,
    STATE_PASS,
    ContractState,
    evaluate_contracts,
    evaluate_gate,
)
from meaf.lifecycle import LEGAL_TRANSITIONS, current_state
from meaf.model import objects, unique_index
from meaf.policy import Policy, default_policy
from meaf.summary import conformance_summary

_SAFE_ID = re.compile(r"[^A-Za-z0-9]")

STATE_CLASSES = {
    STATE_PASS: "statePass",
    STATE_FAIL: "stateFail",
    STATE_INDETERMINATE: "stateIndeterminate",
    STATE_NOT_APPLICABLE: "stateNotApplicable",
}

CLASS_DEFS = [
    "classDef statePass stroke:#2e7d32,stroke-width:2px;",
    "classDef stateFail stroke:#c62828,stroke-width:2px;",
    "classDef stateIndeterminate stroke:#ef6c00,stroke-width:2px,stroke-dasharray:4 3;",
    "classDef stateNotApplicable stroke:#6a6a6a,stroke-width:1px,stroke-dasharray:2 3;",
    "classDef pathNode stroke:#37474f,stroke-width:1px;",
    "classDef outcomeNode stroke:#c62828,stroke-width:2px;",
]


def mermaid_id(prefix: str, value: str) -> str:
    """Mermaid-safe node identifier derived from a MEAF identifier."""
    return f"{prefix}_{_SAFE_ID.sub('_', value)}"


def _label(text: str) -> str:
    """Quote a label for Mermaid, which has no escape for a double quote."""
    return text.replace('"', "'").replace("\n", " ")


def attack_path_diagram(package: Any, attack_path: dict[str, Any]) -> str:
    """Flowchart of one attack path with each control drawn at the node it interrupts."""
    path_id = str(attack_path.get("id"))
    nodes = [node for node in attack_path.get("nodes", []) or [] if isinstance(node, str)]
    edges = [edge for edge in attack_path.get("edges", []) or [] if isinstance(edge, str)]

    lines = ["flowchart LR", *(f"    {definition}" for definition in CLASS_DEFS)]
    for index, node in enumerate(nodes):
        node_id = mermaid_id("n", f"{path_id}-{index}")
        lines.append(f'    {node_id}["{_label(node)}"]')
        style = "outcomeNode" if index == len(nodes) - 1 else "pathNode"
        lines.append(f"    class {node_id} {style};")

    for index in range(len(nodes) - 1):
        left = mermaid_id("n", f"{path_id}-{index}")
        right = mermaid_id("n", f"{path_id}-{index + 1}")
        edge_label = edges[index] if index < len(edges) else "?"
        lines.append(f"    {left} -->|{_label(edge_label)}| {right}")

    for control in objects(package, "control-implementations"):
        if path_id not in (control.get("attack-paths") or []):
            continue
        point = control.get("interruption-point")
        if point not in nodes:
            continue
        control_id = mermaid_id("c", str(control.get("id")))
        target = mermaid_id("n", f"{path_id}-{nodes.index(point)}")
        lines.append(
            f'    {control_id}{{{{"{_label(str(control.get("id")))}<br/>'
            f'{_label(str(control.get("interruption-type")))} · '
            f'{_label(str(control.get("enforcement-mode")))} · '
            f'{_label(str(control.get("failure-behavior")))}"}}}}'
        )
        lines.append(f"    {control_id} -.->|interrupts| {target}")

    return "\n".join(lines)


def assurance_chain_diagram(package: Any, states: list[ContractState]) -> str:
    """Threat to path to control to contract to test to evidence, coloured by state."""
    by_id = {state.contract_id: state for state in states}
    lines = ["flowchart TD", *(f"    {definition}" for definition in CLASS_DEFS)]
    seen: set[str] = set()

    def emit(node_id: str, shape: str) -> None:
        if node_id not in seen:
            lines.append(f"    {shape}")
            seen.add(node_id)

    for threat in objects(package, "threats"):
        threat_id = str(threat.get("id"))
        node = mermaid_id("t", threat_id)
        emit(node, f'{node}["threat<br/>{_label(threat_id)}"]')
        path_id = threat.get("path")
        if isinstance(path_id, str):
            path_node = mermaid_id("p", path_id)
            emit(path_node, f'{path_node}("path<br/>{_label(path_id)}")')
            lines.append(f"    {node} --> {path_node}")

    for control in objects(package, "control-implementations"):
        control_id = str(control.get("id"))
        control_node = mermaid_id("c", control_id)
        emit(
            control_node,
            f'{control_node}{{{{"control<br/>{_label(control_id)}<br/>'
            f'{_label(str(control.get("function")))} · {_label(str(control.get("interruption-type")))}"}}}}',
        )
        for path_id in control.get("attack-paths") or []:
            if isinstance(path_id, str):
                lines.append(f"    {mermaid_id('p', path_id)} --> {control_node}")

    for contract in objects(package, "assurance-contracts"):
        contract_id = str(contract.get("id"))
        contract_node = mermaid_id("a", contract_id)
        state = by_id.get(contract_id)
        state_name = state.state if state is not None else "unevaluated"
        emit(
            contract_node,
            f'{contract_node}["contract<br/>{_label(contract_id)}<br/>state: {state_name}"]',
        )
        if state is not None:
            lines.append(f"    class {contract_node} {STATE_CLASSES[state.state]};")
        control_id = contract.get("control")
        if isinstance(control_id, str):
            lines.append(f"    {mermaid_id('c', control_id)} --> {contract_node}")
        test_id = contract.get("test")
        if isinstance(test_id, str):
            test_node = mermaid_id("x", test_id)
            emit(test_node, f'{test_node}[/"test<br/>{_label(test_id)}"/]')
            lines.append(f"    {contract_node} --> {test_node}")
        for evidence_id in contract.get("required-evidence") or []:
            if not isinstance(evidence_id, str):
                continue
            evidence_node = mermaid_id("e", evidence_id)
            emit(evidence_node, f'{evidence_node}[("evidence<br/>{_label(evidence_id)}")]')
            lines.append(f"    {mermaid_id('x', str(test_id))} --> {evidence_node}")

    return "\n".join(lines)


def lifecycle_diagram(package: Any) -> str:
    """The A.8 state machine with the package's current state marked."""
    state = current_state(package)
    lines = ["stateDiagram-v2", "    [*] --> draft"]
    for source in sorted(LEGAL_TRANSITIONS):
        for target in sorted(LEGAL_TRANSITIONS[source]):
            lines.append(f"    {source} --> {target}")
    lines.append("    retired --> [*]")
    lines.append(f"    note right of {state}")
    lines.append("        current state of this package")
    lines.append("    end note")
    return "\n".join(lines)


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["_(none)_", ""]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    lines.append("")
    return lines


def build_report(
    package: Any,
    *,
    now: datetime,
    policy: Policy | None = None,
) -> str:
    """Render the full Markdown assurance report for a package."""
    if policy is None:
        policy = default_policy()

    states = evaluate_contracts(package, now=now, policy=policy)
    gate = evaluate_gate(package, now=now, policy=policy, states=states)
    summary = conformance_summary(package, now=now, policy=policy, states=states)
    by_contract = {state.contract_id: state for state in states}
    system = package.get("system", {}) if isinstance(package, dict) else {}
    control_index = unique_index(objects(package, "control-implementations"))

    lines: list[str] = [
        f"# Assurance report: {package.get('package-id')}",
        "",
        "Generated from the package by `python -m meaf report`. Do not edit by hand:",
        "every statement below is a projection of the package, and editing the report",
        "would break the property that makes it trustworthy.",
        "",
        f"- Evaluated at: `{summary['evaluated-at']}`",
        f"- Policy bundle: `{policy.name}`",
        f"- Lifecycle state: `{current_state(package)}`",
        f"- Gate decision: **{gate.decision}**",
        "",
        "## Gate",
        "",
    ]
    lines.extend(f"- {reason}" for reason in gate.reasons)
    lines.append("")

    lines.extend(
        [
            "## System boundary",
            "",
            f"- Identifier: `{system.get('id')}`",
            f"- Owner: `{system.get('owner')}`",
            f"- Deployment: {system.get('deployment')} ({system.get('environment')})",
            f"- Data classes: {', '.join(system.get('data-classes', []) or [])}",
            f"- Users: {', '.join(system.get('users', []) or [])}",
            f"- Trust boundaries: {', '.join(system.get('trust-boundaries', []) or [])}",
            f"- Critical outcomes: {', '.join(system.get('critical-outcomes', []) or [])}",
            "",
            "### Responsible roles",
            "",
        ]
    )
    lines.extend(
        _table(
            ["Role", "Title", "Party"],
            [
                [f"`{role.get('id')}`", str(role.get("title")), str(role.get("party", ""))]
                for role in system.get("responsible-roles", []) or []
            ],
        )
    )

    lines.extend(["## Component inventory", ""])
    lines.extend(
        _table(
            ["Component", "Type", "Provider", "Artifact", "Digest"],
            [
                [
                    f"`{component.get('id')}`",
                    str(component.get("type")),
                    str(component.get("provider")),
                    f"`{component.get('artifact-id')}`",
                    f"`{str(component.get('digest'))[:19]}…`",
                ]
                for component in objects(package, "components")
            ],
        )
    )

    lines.extend(["## Threat model", ""])
    for threat in objects(package, "threats"):
        profile = threat.get("temporal-profile", {}) or {}
        horizon = profile.get("detection-horizon", {}) or {}
        recovery = profile.get("recovery-objective", {}) or {}
        lines.extend(
            [
                f"### `{threat.get('id')}`",
                "",
                f"- Actor: {threat.get('actor')}",
                f"- Stage: {threat.get('stage')}",
                f"- Capabilities: {', '.join(threat.get('capabilities', []) or [])}",
                f"- Attack classes: {', '.join(threat.get('attack-classes', []) or [])}",
                f"- Objective: {threat.get('objective')}",
                f"- Entry layers: {', '.join(threat.get('entry-layers', []) or [])}",
                f"- Target: `{threat.get('target')}`",
                f"- Affected stakeholders: {', '.join(threat.get('affected-stakeholders', []) or [])}",
                f"- Outcomes: {', '.join(threat.get('outcomes', []) or [])}",
                "",
                "Preconditions:",
                "",
            ]
        )
        lines.extend(f"- {item}" for item in threat.get("preconditions", []) or [])
        lines.extend(
            [
                "",
                "Temporal profile:",
                "",
            ]
        )
        lines.extend(
            _table(
                ["Field", "Value"],
                [
                    ["Persistence", str(profile.get("persistence"))],
                    ["Activation latency", str(profile.get("activation-latency"))],
                    ["Exposure unit", str(profile.get("exposure-unit"))],
                    ["Compounding rule", str(profile.get("compounding-rule"))],
                    [
                        "Dormancy",
                        str(profile.get("dormancy"))
                        + (
                            f" ({profile['dormancy-trigger']})"
                            if profile.get("dormancy-trigger")
                            else ""
                        ),
                    ],
                    [
                        "Detection horizon",
                        ", ".join(
                            filter(
                                None,
                                [
                                    f"{horizon['minimum-observations']} observations"
                                    if horizon.get("minimum-observations")
                                    else "",
                                    f"over {horizon['observation-period']}"
                                    if horizon.get("observation-period")
                                    else "",
                                ],
                            )
                        ),
                    ],
                    ["Reversibility", str(profile.get("reversibility"))],
                    [
                        "Recovery objective",
                        f"contain within {recovery.get('max-containment-time')}; "
                        f"acceptable loss: {recovery.get('max-acceptable-loss')}",
                    ],
                ],
            )
        )

    lines.extend(["## Attack paths and interruption points", ""])
    for attack_path in objects(package, "attack-paths"):
        lines.extend(
            [
                f"### `{attack_path.get('id')}` ({attack_path.get('impact')} impact)",
                "",
            ]
        )
        if attack_path.get("description"):
            lines.extend([str(attack_path["description"]), ""])
        lines.extend(["```mermaid", attack_path_diagram(package, attack_path), "```", ""])

    lines.extend(
        [
            "## Control implementations and assurance contracts",
            "",
            "A control implementation states how and where a threat is interrupted.",
            "An assurance contract states what must be observed for that control to",
            "count as working. The two are separate objects because a control that",
            "nobody verifies is a claim, not a mitigation.",
            "",
        ]
    )
    lines.extend(
        _table(
            [
                "Control",
                "Function",
                "Interrupts",
                "As",
                "Runs at",
                "Mode",
                "On failure",
                "Owner",
            ],
            [
                [
                    f"`{control.get('id')}`",
                    str(control.get("function")),
                    ", ".join(control.get("attack-paths", []) or []),
                    f"{control.get('interruption-type')} at `{control.get('interruption-point')}`",
                    f"`{control.get('implementation-location')}`",
                    str(control.get("enforcement-mode")),
                    str(control.get("failure-behavior")),
                    f"`{control.get('owner')}`",
                ]
                for control in objects(package, "control-implementations")
            ],
        )
    )
    lines.extend(
        _table(
            ["Contract", "Verifies control", "Subject", "State", "Cadence", "On failure", "Owner"],
            [
                [
                    f"`{contract.get('id')}`",
                    f"`{contract.get('control')}`",
                    f"`{contract.get('subject')}`",
                    f"**{by_contract[str(contract.get('id'))].state}**"
                    if str(contract.get("id")) in by_contract
                    else "unevaluated",
                    str(contract.get("cadence")),
                    str(contract.get("failure-action")),
                    f"`{contract.get('owner')}`",
                ]
                for contract in objects(package, "assurance-contracts")
            ],
        )
    )

    lines.extend(["### Assurance chain", "", "```mermaid", assurance_chain_diagram(package, states), "```", ""])

    lines.extend(["### Contract state detail", ""])
    for state in states:
        lines.append(f"- `{state.contract_id}`: **{state.state}** ({state.impact} impact)")
        lines.extend(f"  - {reason}" for reason in state.reasons)
    lines.append("")

    lines.extend(["## Evidence", ""])
    lines.extend(
        _table(
            ["Evidence", "Class", "Result", "Collector", "Collected", "Max age", "Source"],
            [
                [
                    f"`{evidence.get('id')}`",
                    str(evidence.get("class")),
                    str(evidence.get("result")),
                    f"`{evidence.get('collector')}`",
                    str(evidence.get("collected-at")),
                    str(evidence.get("max-age")),
                    str(evidence.get("source")),
                ]
                for evidence in objects(package, "evidence")
            ],
        )
    )

    lines.extend(["## Findings", ""])
    lines.extend(
        _table(
            ["Finding", "Severity", "Status", "Failed claim", "Due", "Corrective action"],
            [
                [
                    f"`{finding.get('id')}`",
                    str(finding.get("severity")),
                    str(finding.get("status", "open")),
                    f"`{finding.get('failed-claim')}`",
                    str(finding.get("due-date")),
                    str(finding.get("corrective-action")),
                ]
                for finding in objects(package, "findings")
            ],
        )
    )

    lines.extend(["## Decisions and exceptions", ""])
    lines.extend(
        _table(
            ["Decision", "Type", "Verdict", "Decision maker", "Scope", "Expiry"],
            [
                [
                    f"`{decision.get('id')}`",
                    str(decision.get("decision-type")),
                    str(decision.get("gate-decision")),
                    f"`{decision.get('decision-maker')}`",
                    str(decision.get("scope")),
                    str(decision.get("expiry")),
                ]
                for decision in objects(package, "decisions")
            ],
        )
    )

    lines.extend(["## Unresolved coverage", ""])
    unresolved: list[str] = []
    for entry in summary["path-interruption-coverage"]["by-path"]:
        if not entry["before-outcome-satisfied"]:
            unresolved.append(
                f"`{entry['path']}` ({entry['impact']}) has no control interrupting "
                "before the harmful outcome"
            )
        if not entry["recovery-satisfied"]:
            unresolved.append(
                f"`{entry['path']}` ({entry['impact']}) has no containment or recovery control"
            )
    unresolved.extend(
        f"`{threat_id}` has no assurance contract"
        for threat_id in summary["threat-model-completeness"]["threats-without-contracts"]
    )
    unresolved.extend(
        f"`{entry['evidence']}` is not current: {entry['reasons'][0]}"
        for entry in summary["evidence-freshness"]["not-current"]
    )
    unresolved.extend(
        f"`{contract_id}` is fail" for contract_id in summary["control-test-status"]["failing"]
    )
    unresolved.extend(
        f"`{contract_id}` is indeterminate"
        for contract_id in summary["control-test-status"]["indeterminate"]
    )
    unresolved.extend(
        f"`{decision_id}` has expired" for decision_id in summary["exception-age"]["expired-exceptions"]
    )
    if unresolved:
        lines.extend(f"- {item}" for item in unresolved)
    else:
        lines.append("Nothing unresolved at this evaluation instant.")
    lines.append("")

    for control_id, control in sorted(control_index.items()):
        verified = any(
            contract.get("control") == control_id
            for contract in objects(package, "assurance-contracts")
        )
        if not verified:
            lines.append(f"- `{control_id}` is not paired with any assurance contract")

    lines.extend(
        [
            "## Conformance summary",
            "",
            "The eight dimensions appendix A.5 requires. No aggregate score is reported:",
            "a single number would conceal which dimension is weak.",
            "",
        ]
    )
    lines.extend(
        _table(
            ["Dimension", "Value"],
            [
                [
                    "Threat-model completeness",
                    f"{summary['threat-model-completeness']['threats-with-contracts']}/"
                    f"{summary['threat-model-completeness']['threats-declared']} threats have contracts",
                ],
                [
                    "Path-interruption coverage",
                    f"{summary['path-interruption-coverage']['paths-fully-covered']}/"
                    f"{summary['path-interruption-coverage']['paths-declared']} paths meet their tier",
                ],
                [
                    "Control-test status",
                    ", ".join(
                        f"{count} {state}"
                        for state, count in summary["control-test-status"]["by-state"].items()
                    ),
                ],
                [
                    "Evidence freshness",
                    f"{len(summary['evidence-freshness']['current'])}/"
                    f"{summary['evidence-freshness']['evidence-items']} current",
                ],
                [
                    "Open findings by severity",
                    ", ".join(
                        f"{count} {severity}"
                        for severity, count in summary["open-findings-by-severity"][
                            "open-by-severity"
                        ].items()
                    ),
                ],
                [
                    "Recovery readiness",
                    f"{len(summary['recovery-readiness']['verified-recovery-contracts'])} verified, "
                    f"{len(summary['recovery-readiness']['unverified-recovery-contracts'])} unverified",
                ],
                [
                    "Probabilistic-evidence dependence",
                    f"{len(summary['probabilistic-evidence-dependence']['gating-contracts-depending-on-inference'])}/"
                    f"{summary['probabilistic-evidence-dependence']['gating-contracts']} gating contracts",
                ],
                [
                    "Exception age",
                    f"{len(summary['exception-age']['exceptions'])} exception(s), "
                    f"{len(summary['exception-age']['expired-exceptions'])} expired",
                ],
            ],
        )
    )

    lines.extend(["## Lifecycle", "", "```mermaid", lifecycle_diagram(package), "```", ""])

    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "assurance_chain_diagram",
    "attack_path_diagram",
    "build_report",
    "lifecycle_diagram",
    "mermaid_id",
]
