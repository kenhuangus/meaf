"""OSCAL 1.1.2 export (manuscript A.4).

    MEAF should be implemented as an OSCAL-compatible extension rather than as a
    parallel compliance-document format.

The six-row mapping in A.4 is implemented literally:

    MAESTRO control catalog and external-framework mappings  ->  Catalog, Profile
    Component capabilities and reusable implementations      ->  Component Definition
    System boundary, inventory, implementation statements,
      and responsible roles                                  ->  System Security Plan
    Test plan, scope, methods, subjects, and schedule        ->  Assessment Plan
    Observations, risks, findings, collected evidence        ->  Assessment Results
    Open remediation items and milestones                    ->  POA&M

Two points worth stating plainly. First, control implementations become catalog
controls and *threats become Assessment Results risks*: a threat is not a
control, and an earlier version emitted both as catalog controls, which made the
catalog assert that "an attacker biases generation" was a security control.
Second, MAESTRO semantics travel as namespaced properties. OSCAL property names
are tokens and cannot contain a colon, so ``maestro:layer`` is encoded the way
OSCAL intends it: ``{"name": "layer", "ns": "https://.../maestro"}``.

Large evidence stays outside the package. Artifacts and evidence appear in
back-matter as content-addressed resources, so an authorization package remains
portable without embedding traces, corpora or model cards.

Exports are byte-deterministic: identifiers are UUIDv5 over the package id and a
collection-qualified object id, and no wall-clock time is read.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from meaf.contract import STATE_PASS, evaluate_contracts
from meaf.model import layer_number, objects, unique_index

OSCAL_VERSION = "1.1.2"
MAESTRO_NS = "https://cloudsecurityalliance.org/ns/maestro"

MAESTRO_LAYER_TITLES = {
    1: "L1 Foundation Models",
    2: "L2 Data Operations",
    3: "L3 Agent Frameworks",
    4: "L4 Deployment and Infrastructure",
    5: "L5 Evaluation and Observability",
    6: "L6 Security and Compliance",
    7: "L7 Agent Ecosystem",
}

CATALOG_FILE = "catalog.json"
PROFILE_FILE = "profile.json"
COMPONENT_DEFINITION_FILE = "component-definition.json"
SSP_FILE = "system-security-plan.json"
ASSESSMENT_PLAN_FILE = "assessment-plan.json"
ASSESSMENT_RESULTS_FILE = "assessment-results.json"
POAM_FILE = "plan-of-action-and-milestones.json"

#: OSCAL component types are a closed vocabulary; MEAF component types are not.
COMPONENT_TYPE_MAP = {
    "foundation-model-service": "service",
    "retrieval-collection": "software",
    "adapter": "software",
    "prompt": "software",
    "agent-graph": "software",
    "tool": "software",
    "dataset": "software",
    "policy": "policy",
    "memory-store": "software",
    "guardian-agent": "service",
}

DIGEST_ALGORITHM_NAMES = {
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def _package_namespace(package_id: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"meaf:{package_id}")


def meaf_uuid(package_id: str, collection: str, object_id: str = "") -> str:
    """Deterministic UUIDv5, qualified by collection.

    Qualification matters: without it a component and an assurance contract that
    happened to share an id string would derive the same UUID and collide across
    two OSCAL documents.
    """
    name = f"{collection}:{object_id}" if object_id else collection
    return str(uuid.uuid5(_package_namespace(package_id), name))


def _prop(name: str, value: str, ns: str | None = MAESTRO_NS) -> dict[str, str]:
    prop = {"name": name, "value": value}
    if ns:
        prop["ns"] = ns
    return prop


def _newest_evidence_timestamp(package: Any) -> str:
    """Package modification time taken from evidence, never from the wall clock."""
    newest: datetime | None = None
    for evidence in objects(package, "evidence"):
        raw = evidence.get("collected-at")
        if not isinstance(raw, str):
            continue
        try:
            collected = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        if newest is None or collected > newest:
            newest = collected
    if newest is None:
        newest = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return newest.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _roles(package: Any) -> list[dict[str, str]]:
    system = package.get("system", {}) if isinstance(package, dict) else {}
    return [
        {"id": str(role.get("id")), "title": str(role.get("title"))}
        for role in system.get("responsible-roles", []) or []
    ]


def _metadata(package: Any, title: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "title": title,
        "last-modified": _newest_evidence_timestamp(package),
        "version": str(package.get("meaf-version", "2.0.0")),
        "oscal-version": OSCAL_VERSION,
    }
    roles = _roles(package)
    if roles:
        metadata["roles"] = roles
    return metadata


def _hashes(digest: Any) -> list[dict[str, str]]:
    if not isinstance(digest, str) or ":" not in digest:
        return []
    algorithm, value = digest.split(":", 1)
    name = DIGEST_ALGORITHM_NAMES.get(algorithm)
    if name is None:
        return []
    return [{"algorithm": name, "value": value}]


def _back_matter(package: Any) -> dict[str, Any]:
    """Artifacts and evidence as content-addressed resources.

    A.4: "Large traces, model cards, dataset manifests, red-team corpora, and
    signed telemetry remain external resources addressed by digest and linked
    through OSCAL back matter."
    """
    package_id = str(package.get("package-id"))
    resources: list[dict[str, Any]] = []

    for component in objects(package, "components"):
        component_id = str(component.get("id"))
        rlink: dict[str, Any] = {
            "href": str(component.get("artifact-path") or component.get("artifact-id"))
        }
        hashes = _hashes(component.get("digest"))
        if hashes:
            rlink["hashes"] = hashes
        resources.append(
            {
                "uuid": meaf_uuid(package_id, "resource-component", component_id),
                "title": f"Artifact for {component_id}",
                "description": f"{component.get('type')} supplied by {component.get('provider')}",
                "props": [
                    _prop("artifact-binding", str(component.get("digest", ""))),
                    _prop("component-id", component_id),
                ],
                "rlinks": [rlink],
            }
        )

    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id"))
        props = [
            _prop("evidence-class", str(evidence.get("class", ""))),
            _prop("artifact-binding", ",".join(evidence.get("subject-digests", []) or [])),
            _prop("collector", str(evidence.get("collector", ""))),
        ]
        signature = evidence.get("signature")
        if isinstance(signature, dict):
            props.append(_prop("signature-key-id", str(signature.get("key-id", ""))))
        resources.append(
            {
                "uuid": meaf_uuid(package_id, "resource-evidence", evidence_id),
                "title": f"Evidence {evidence_id}",
                "description": (
                    f"{evidence.get('method')} collected by {evidence.get('collector')} "
                    f"from {evidence.get('source')}; retained in the evidence store, not in this package"
                ),
                "props": props,
            }
        )

    return {"resources": resources}


# --------------------------------------------------------------------------
# Catalog and profile
# --------------------------------------------------------------------------


def _control_from_implementation(
    package_id: str, control: dict[str, Any], contracts: list[dict[str, Any]]
) -> dict[str, Any]:
    control_id = str(control.get("id"))
    parts = [
        {
            "id": f"{control_id}_smt",
            "name": "statement",
            "prose": str(control.get("description", "")),
        }
    ]
    for contract in contracts:
        contract_id = str(contract.get("id"))
        parts.append(
            {
                "id": f"{contract_id}_obj",
                "name": "assessment-objective",
                "props": [
                    _prop("assurance-contract", contract_id),
                    _prop("cadence", str(contract.get("cadence", ""))),
                    _prop("failure-action", str(contract.get("failure-action", ""))),
                    _prop(
                        "decision-rule",
                        json.dumps(contract.get("decision-rule", {}), sort_keys=True),
                    ),
                ],
                "prose": str(contract.get("claim", "")),
            }
        )
    return {
        "id": control_id,
        "class": "maestro-control-implementation",
        "title": str(control.get("description", control_id))[:200],
        "props": [
            _prop("layer", str(control.get("interruption-point", "")).split(":")[0]),
            _prop("implementation-location", str(control.get("implementation-location", ""))),
            _prop("interruption-point", str(control.get("interruption-point", ""))),
            _prop("interruption-type", str(control.get("interruption-type", ""))),
            _prop("function", str(control.get("function", ""))),
            _prop("enforcement-mode", str(control.get("enforcement-mode", ""))),
            _prop("failure-behavior", str(control.get("failure-behavior", ""))),
            _prop("attack-path", ",".join(control.get("attack-paths", []) or [])),
        ],
        "parts": parts,
    }


def export_catalog(package: Any) -> dict[str, Any]:
    """Control implementations as an OSCAL catalog, grouped by MAESTRO layer."""
    package_id = str(package.get("package-id"))
    contracts_by_control: dict[str, list[dict[str, Any]]] = {}
    for contract in objects(package, "assurance-contracts"):
        control_id = contract.get("control")
        if isinstance(control_id, str):
            contracts_by_control.setdefault(control_id, []).append(contract)

    by_layer: dict[int, list[dict[str, Any]]] = {}
    ungrouped: list[dict[str, Any]] = []
    for control in objects(package, "control-implementations"):
        entry = _control_from_implementation(
            package_id, control, contracts_by_control.get(str(control.get("id")), [])
        )
        layer = layer_number(control.get("implementation-location"))
        if layer is None:
            ungrouped.append(entry)
        else:
            by_layer.setdefault(layer, []).append(entry)

    groups = [
        {
            "id": f"L{layer}",
            "title": MAESTRO_LAYER_TITLES[layer],
            "props": [_prop("layer", f"L{layer}")],
            "controls": by_layer[layer],
        }
        for layer in sorted(by_layer)
    ]

    catalog: dict[str, Any] = {
        "uuid": meaf_uuid(package_id, "catalog"),
        "metadata": _metadata(package, f"MEAF control catalog for {package_id}"),
    }
    if groups:
        catalog["groups"] = groups
    if ungrouped:
        catalog["controls"] = ungrouped
    catalog["back-matter"] = _back_matter(package)
    return {"catalog": catalog}


def export_profile(package: Any) -> dict[str, Any]:
    """Profile selecting every control implementation the package declares."""
    package_id = str(package.get("package-id"))
    control_ids = [str(control.get("id")) for control in objects(package, "control-implementations")]
    return {
        "profile": {
            "uuid": meaf_uuid(package_id, "profile"),
            "metadata": _metadata(package, f"MEAF profile for {package_id}"),
            "imports": [
                {
                    "href": f"./{CATALOG_FILE}",
                    "include-controls": [{"with-ids": control_ids}],
                }
            ],
            "merge": {"as-is": True},
        }
    }


# --------------------------------------------------------------------------
# Component definition
# --------------------------------------------------------------------------


def export_component_definition(package: Any) -> dict[str, Any]:
    """Components with the control implementations each one participates in."""
    package_id = str(package.get("package-id"))
    controls = objects(package, "control-implementations")

    components: list[dict[str, Any]] = []
    for component in objects(package, "components"):
        component_id = str(component.get("id"))
        implemented = [
            {
                "uuid": meaf_uuid(package_id, "cd-implemented", f"{component_id}:{control['id']}"),
                "control-id": str(control["id"]),
                "description": (
                    f"{component_id} is a declared dependency of {control['id']}, which "
                    f"{control.get('interruption-type')} at {control.get('interruption-point')}."
                ),
            }
            for control in controls
            if component_id in (control.get("dependencies") or [])
        ]
        entry: dict[str, Any] = {
            "uuid": meaf_uuid(package_id, "cd-component", component_id),
            "type": COMPONENT_TYPE_MAP.get(str(component.get("type")), "software"),
            "title": component_id,
            "description": (
                f"{component.get('type')} {component.get('artifact-id')} "
                f"supplied by {component.get('provider')}"
            ),
            "props": [
                _prop("artifact-binding", str(component.get("digest", ""))),
                _prop("meaf-component-type", str(component.get("type", ""))),
                _prop("provider", str(component.get("provider", ""))),
            ],
            "links": [
                {
                    "href": f"#{meaf_uuid(package_id, 'resource-component', component_id)}",
                    "rel": "artifact",
                }
            ],
        }
        if implemented:
            entry["control-implementations"] = [
                {
                    "uuid": meaf_uuid(package_id, "cd-control-impl", component_id),
                    "source": f"./{CATALOG_FILE}",
                    "description": (
                        f"Control implementations that depend on {component_id}."
                    ),
                    "implemented-requirements": implemented,
                }
            ]
        components.append(entry)

    return {
        "component-definition": {
            "uuid": meaf_uuid(package_id, "component-definition"),
            "metadata": _metadata(package, f"MEAF component definition for {package_id}"),
            "components": components,
            "back-matter": _back_matter(package),
        }
    }


# --------------------------------------------------------------------------
# System security plan
# --------------------------------------------------------------------------


def export_ssp(package: Any) -> dict[str, Any]:
    package_id = str(package.get("package-id"))
    system = package.get("system", {}) if isinstance(package, dict) else {}
    system_id = str(system.get("id", package_id))

    components = [
        {
            "uuid": meaf_uuid(package_id, "ssp-component", str(component.get("id"))),
            "type": COMPONENT_TYPE_MAP.get(str(component.get("type")), "software"),
            "title": str(component.get("id")),
            "description": (
                f"{component.get('type')} {component.get('artifact-id')} "
                f"supplied by {component.get('provider')}"
            ),
            "status": {"state": "operational"},
            "props": [
                _prop("artifact-binding", str(component.get("digest", ""))),
                _prop("meaf-component-type", str(component.get("type", ""))),
            ],
        }
        for component in objects(package, "components")
    ]

    users = [
        {
            "uuid": meaf_uuid(package_id, "ssp-user", user),
            "title": user,
            "role-ids": [role["id"] for role in _roles(package)],
        }
        for user in system.get("users", []) or []
    ]

    information_types = [
        {
            "uuid": meaf_uuid(package_id, "ssp-information-type", data_class),
            "title": data_class,
            "description": f"Data class declared in the MEAF system boundary: {data_class}",
        }
        for data_class in system.get("data-classes", []) or []
    ]

    control_index = unique_index(objects(package, "control-implementations"))
    implemented: list[dict[str, Any]] = []
    for control_id, control in control_index.items():
        contracts = [
            contract
            for contract in objects(package, "assurance-contracts")
            if contract.get("control") == control_id
        ]
        by_components = []
        for dependency in control.get("dependencies", []) or []:
            if dependency not in {str(c.get("id")) for c in objects(package, "components")}:
                continue
            by_components.append(
                {
                    "component-uuid": meaf_uuid(package_id, "ssp-component", dependency),
                    "uuid": meaf_uuid(
                        package_id, "ssp-by-component", f"{control_id}:{dependency}"
                    ),
                    "description": (
                        f"{dependency} participates in {control_id}, which "
                        f"{control.get('interruption-type')} at "
                        f"{control.get('interruption-point')}."
                    ),
                }
            )
        entry: dict[str, Any] = {
            "uuid": meaf_uuid(package_id, "ssp-implemented", control_id),
            "control-id": control_id,
            "props": [
                _prop("implementation-location", str(control.get("implementation-location", ""))),
                _prop("interruption-type", str(control.get("interruption-type", ""))),
                _prop("enforcement-mode", str(control.get("enforcement-mode", ""))),
                _prop("failure-behavior", str(control.get("failure-behavior", ""))),
            ],
            "responsible-roles": [{"role-id": str(control.get("owner"))}],
            "remarks": "\n".join(
                [
                    str(control.get("description", "")),
                    *[
                        f"Assurance contract {contract.get('id')}: {contract.get('claim')}"
                        for contract in contracts
                    ],
                ]
            ),
        }
        if by_components:
            entry["by-components"] = by_components
        implemented.append(entry)

    return {
        "system-security-plan": {
            "uuid": meaf_uuid(package_id, "ssp"),
            "metadata": _metadata(package, f"MEAF system security plan for {package_id}"),
            "import-profile": {"href": f"./{PROFILE_FILE}"},
            "system-characteristics": {
                "system-ids": [{"identifier-type": "https://meaf/package-id", "id": package_id}],
                "system-name": system_id,
                "description": (
                    f"{system.get('deployment')} operating in {system.get('environment')}. "
                    f"Critical outcomes: {', '.join(system.get('critical-outcomes', []) or [])}."
                ),
                "props": [
                    _prop("trust-boundary", boundary)
                    for boundary in system.get("trust-boundaries", []) or []
                ],
                "system-information": {"information-types": information_types},
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "Trust boundaries: "
                    + "; ".join(system.get("trust-boundaries", []) or [])
                },
            },
            "system-implementation": {"users": users, "components": components},
            "control-implementation": {
                "description": (
                    "Control implementations declared by the MEAF package, each paired "
                    "with one or more assurance contracts recorded as assessment objectives "
                    "in the catalog."
                ),
                "implemented-requirements": implemented,
            },
            "back-matter": _back_matter(package),
        }
    }


# --------------------------------------------------------------------------
# Assessment plan
# --------------------------------------------------------------------------


def _reviewed_controls(package: Any) -> dict[str, Any]:
    control_ids = [str(control.get("id")) for control in objects(package, "control-implementations")]
    return {
        "control-selections": [
            {
                "description": "Every control implementation declared by the MEAF package.",
                "include-controls": [{"control-id": control_id} for control_id in control_ids],
            }
        ]
    }


def _assessment_subject(package: Any, subject_id: Any) -> dict[str, Any]:
    """Resolve a contract subject to an OSCAL assessment subject.

    A contract's subject is either a component or the system as a whole. Only
    the first has an SSP component uuid to point at; emitting one for a
    system-wide subject would produce exactly the dangling reference that
    conformance level 2 exists to reject, committed by the export rather than by
    the package.
    """
    package_id = str(package.get("package-id"))
    component_ids = {str(component.get("id")) for component in objects(package, "components")}
    if isinstance(subject_id, str) and subject_id in component_ids:
        return {
            "type": "component",
            "description": f"Component {subject_id}.",
            "include-subjects": [
                {
                    "type": "component",
                    "subject-uuid": meaf_uuid(package_id, "ssp-component", subject_id),
                }
            ],
        }
    return {
        "type": "component",
        "description": (
            f"The system as a whole: the claim is about {subject_id}, which is a "
            "runtime boundary rather than a single component."
        ),
        "include-all": {},
    }


def export_assessment_plan(package: Any) -> dict[str, Any]:
    package_id = str(package.get("package-id"))
    contracts_by_test: dict[str, list[dict[str, Any]]] = {}
    for contract in objects(package, "assurance-contracts"):
        test_id = contract.get("test")
        if isinstance(test_id, str):
            contracts_by_test.setdefault(test_id, []).append(contract)

    activities: list[dict[str, Any]] = []
    tasks: list[dict[str, Any]] = []
    for test in objects(package, "tests"):
        test_id = str(test.get("id"))
        contracts = contracts_by_test.get(test_id, [])
        props = [
            _prop("test-pack", str(test.get("test-pack", ""))),
            _prop("test-pack-version", str(test.get("test-pack-version", ""))),
            _prop("oracle", str(test.get("oracle", ""))),
            _prop("sampling-plan", str(test.get("sampling-plan", ""))),
            _prop("adversarial", "true" if test.get("adversarial") else "false"),
            _prop("thresholds", json.dumps(test.get("thresholds", {}), sort_keys=True)),
        ]
        if test.get("utility-thresholds"):
            props.append(
                _prop(
                    "utility-thresholds",
                    json.dumps(test.get("utility-thresholds", {}), sort_keys=True),
                )
            )
        activities.append(
            {
                "uuid": meaf_uuid(package_id, "ap-activity", test_id),
                "title": test_id,
                "description": str(test.get("procedure", test_id)),
                "props": props,
                "steps": [
                    {
                        "uuid": meaf_uuid(package_id, "ap-step", test_id),
                        "title": f"Execute {test_id}",
                        "description": (
                            f"Run {test.get('procedure')} against {test.get('target')} "
                            f"using {test.get('sampling-plan')}, and evaluate against "
                            f"the oracle {test.get('oracle')}."
                        ),
                    }
                ],
                "related-controls": {
                    "control-selections": [
                        {
                            "description": f"Controls verified by {test_id}.",
                            "include-controls": [
                                {"control-id": str(contract.get("control"))}
                                for contract in contracts
                                if isinstance(contract.get("control"), str)
                            ],
                        }
                    ]
                }
                if contracts
                else {"control-selections": [{"include-all": {}}]},
            }
        )
        for contract in contracts:
            tasks.append(
                {
                    "uuid": meaf_uuid(
                        package_id, "ap-task", f"{test_id}:{contract.get('id')}"
                    ),
                    "type": "action",
                    "title": f"{contract.get('id')} reassessment cadence",
                    "description": (
                        f"Reassess {contract.get('id')} on the declared cadence: "
                        f"{contract.get('cadence')}."
                    ),
                    "props": [
                        _prop("cadence", str(contract.get("cadence", ""))),
                        _prop("assurance-contract", str(contract.get("id"))),
                    ],
                    "associated-activities": [
                        {
                            "uuid": meaf_uuid(
                                package_id, "ap-assoc", f"{test_id}:{contract.get('id')}"
                            ),
                            "activity-uuid": meaf_uuid(package_id, "ap-activity", test_id),
                            "subjects": [
                                _assessment_subject(package, contract.get("subject"))
                            ],
                        }
                    ],
                }
            )

    plan: dict[str, Any] = {
        "uuid": meaf_uuid(package_id, "assessment-plan"),
        "metadata": _metadata(package, f"MEAF assessment plan for {package_id}"),
        "import-ssp": {"href": f"./{SSP_FILE}"},
        "reviewed-controls": _reviewed_controls(package),
        "back-matter": _back_matter(package),
    }
    if activities:
        plan["local-definitions"] = {"activities": activities}
    if tasks:
        plan["tasks"] = tasks
    return {"assessment-plan": plan}


# --------------------------------------------------------------------------
# Assessment results
# --------------------------------------------------------------------------


#: A MEAF finding status mapped to an OSCAL objective status. A resolved or
#: risk-accepted finding is not an open "not-satisfied" objective; exporting it
#: as one would keep remediated work on the reviewer's desk forever.
FINDING_STATUS_MAP = {
    "open": ("not-satisfied", "fail"),
    "in-progress": ("not-satisfied", "remediation in progress"),
    "resolved": ("satisfied", "remediated and retested"),
    "risk-accepted": ("not-satisfied", "risk accepted under a recorded decision"),
}


def export_assessment_results(
    package: Any,
    *,
    now: datetime | None = None,
    policy: Any = None,
) -> dict[str, Any]:
    """Observations from evidence, risks from threats, findings from findings.

    When ``now`` is supplied, contracts currently in state ``pass`` are also
    emitted as findings with a *satisfied* objective. An assessment result that
    only ever says "not-satisfied" cannot distinguish a passing control from one
    nobody assessed. Without ``now`` the export carries only what the package
    itself records, so it stays a pure function of the file.
    """
    package_id = str(package.get("package-id"))
    start = _newest_evidence_timestamp(package)

    observations = [
        {
            "uuid": meaf_uuid(package_id, "ar-observation", str(evidence.get("id"))),
            "title": str(evidence.get("id")),
            "description": (
                f"{evidence.get('method')} collected by {evidence.get('collector')} "
                f"from {evidence.get('source')}; result {evidence.get('result')}."
            ),
            "methods": ["TEST" if evidence.get("class") == "probabilistic-inference" else "EXAMINE"],
            "types": ["control-objective"],
            "props": [
                _prop("evidence-class", str(evidence.get("class", ""))),
                _prop("result", str(evidence.get("result", ""))),
                _prop(
                    "artifact-binding",
                    ",".join(evidence.get("subject-digests", []) or []),
                ),
                _prop("max-age", str(evidence.get("max-age", ""))),
            ],
            "relevant-evidence": [
                {
                    "href": f"#{meaf_uuid(package_id, 'resource-evidence', str(evidence.get('id')))}",
                    "description": (
                        f"Evidence retained in {evidence.get('source')} and addressed by digest."
                    ),
                }
            ],
            "collected": str(evidence.get("collected-at")),
        }
        for evidence in objects(package, "evidence")
    ]

    risks = [
        {
            "uuid": meaf_uuid(package_id, "ar-risk", str(threat.get("id"))),
            "title": str(threat.get("id")),
            "description": (
                f"{threat.get('actor')} acting at the {threat.get('stage')} stage against "
                f"{threat.get('target')}."
            ),
            "statement": (
                f"Objective {threat.get('objective')} via attack classes "
                f"{', '.join(threat.get('attack-classes', []) or [])}, entering at "
                f"{', '.join(threat.get('entry-layers', []) or [])} and traversing "
                f"{threat.get('path')}. Outcomes: "
                f"{', '.join(threat.get('outcomes', []) or [])}."
            ),
            "status": "open",
            "props": [
                _prop("attack-path", str(threat.get("path", ""))),
                _prop("stage", str(threat.get("stage", ""))),
                _prop(
                    "temporal-profile",
                    json.dumps(threat.get("temporal-profile", {}), sort_keys=True),
                ),
            ],
            "threat-ids": [
                {"system": MAESTRO_NS, "id": attack_class}
                for attack_class in threat.get("attack-classes", []) or []
            ],
        }
        for threat in objects(package, "threats")
    ]

    contract_index = unique_index(objects(package, "assurance-contracts"))
    findings: list[dict[str, Any]] = []
    for finding in objects(package, "findings"):
        finding_id = str(finding.get("id"))
        contract_id = str(finding.get("failed-claim"))
        contract = contract_index.get(contract_id, {})
        status = str(finding.get("status", "open"))
        state, reason = FINDING_STATUS_MAP.get(status, ("not-satisfied", status))
        findings.append(
            {
                "uuid": meaf_uuid(package_id, "ar-finding", finding_id),
                "title": finding_id,
                "description": str(finding.get("root-cause", "")),
                "props": [
                    _prop("severity", str(finding.get("severity", ""))),
                    _prop("assurance-contract", contract_id),
                    _prop("due-date", str(finding.get("due-date", ""))),
                    _prop("finding-status", status),
                ],
                "target": {
                    "type": "objective-id",
                    "target-id": f"{contract_id}_obj",
                    "title": str(contract.get("claim", contract_id)),
                    "description": str(finding.get("corrective-action", "")),
                    "status": {"state": state, "reason": reason},
                },
                "related-observations": [
                    {
                        "observation-uuid": meaf_uuid(
                            package_id, "ar-observation", str(evidence_id)
                        )
                    }
                    for evidence_id in contract.get("required-evidence", []) or []
                ],
                "related-risks": [
                    {"risk-uuid": meaf_uuid(package_id, "ar-risk", str(threat_id))}
                    for threat_id in contract.get("threats", []) or []
                ],
            }
        )

    if now is not None:
        for state in evaluate_contracts(package, now=now, policy=policy):
            if state.state != STATE_PASS:
                continue
            contract = contract_index.get(state.contract_id, {})
            findings.append(
                {
                    "uuid": meaf_uuid(package_id, "ar-satisfied", state.contract_id),
                    "title": f"{state.contract_id} satisfied",
                    "description": str(contract.get("claim", "")),
                    "props": [
                        _prop("contract-state", state.state),
                        _prop("assurance-contract", state.contract_id),
                    ],
                    "target": {
                        "type": "objective-id",
                        "target-id": f"{state.contract_id}_obj",
                        "title": str(contract.get("claim", state.contract_id)),
                        "description": "; ".join(state.reasons),
                        "status": {"state": "satisfied"},
                    },
                }
            )

    result: dict[str, Any] = {
        "uuid": meaf_uuid(package_id, "ar-result"),
        "title": "MEAF assessment result",
        "description": (
            "Observations derived from MEAF evidence, risks from MEAF threats, and "
            "findings from failed assurance contracts."
        ),
        "start": start,
        "reviewed-controls": _reviewed_controls(package),
    }
    if observations:
        result["observations"] = observations
    if risks:
        result["risks"] = risks
    if findings:
        result["findings"] = findings

    return {
        "assessment-results": {
            "uuid": meaf_uuid(package_id, "assessment-results"),
            "metadata": _metadata(package, f"MEAF assessment results for {package_id}"),
            "import-ap": {"href": f"./{ASSESSMENT_PLAN_FILE}"},
            "results": [result],
            "back-matter": _back_matter(package),
        }
    }


# --------------------------------------------------------------------------
# Plan of action and milestones
# --------------------------------------------------------------------------


def export_poam(package: Any) -> dict[str, Any]:
    package_id = str(package.get("package-id"))
    items: list[dict[str, Any]] = []
    for finding in objects(package, "findings"):
        if finding.get("status", "open") not in ("open", "in-progress"):
            continue
        finding_id = str(finding.get("id"))
        items.append(
            {
                "uuid": meaf_uuid(package_id, "poam-item", finding_id),
                "title": finding_id,
                "description": str(finding.get("corrective-action", "")),
                "props": [
                    _prop("severity", str(finding.get("severity", ""))),
                    _prop("status", str(finding.get("status", "open"))),
                    _prop("due-date", str(finding.get("due-date", ""))),
                    _prop("retest-reference", str(finding.get("retest-reference", ""))),
                ],
                "related-findings": [
                    {"finding-uuid": meaf_uuid(package_id, "ar-finding", finding_id)}
                ],
            }
        )

    for decision in objects(package, "decisions"):
        if decision.get("decision-type") not in ("exception", "not-applicable"):
            continue
        decision_id = str(decision.get("id"))
        items.append(
            {
                "uuid": meaf_uuid(package_id, "poam-exception", decision_id),
                "title": f"{decision_id} expires {decision.get('expiry')}",
                "description": (
                    f"{decision.get('decision-type')} approved by "
                    f"{decision.get('decision-maker')}: {decision.get('justification')}"
                ),
                "props": [
                    _prop("decision-type", str(decision.get("decision-type", ""))),
                    _prop("expiry", str(decision.get("expiry", ""))),
                    _prop("residual-risk", str(decision.get("residual-risk", ""))),
                    *[
                        _prop("applies-to", str(contract_id))
                        for contract_id in decision.get("applies-to", []) or []
                    ],
                ],
            }
        )

    poam: dict[str, Any] = {
        "uuid": meaf_uuid(package_id, "poam"),
        "metadata": _metadata(package, f"MEAF plan of action and milestones for {package_id}"),
        "import-ssp": {"href": f"./{SSP_FILE}"},
        "system-id": {"identifier-type": "https://meaf/package-id", "id": package_id},
        "poam-items": items
        or [
            {
                "uuid": meaf_uuid(package_id, "poam-item", "none"),
                "title": "No open remediation items",
                "description": (
                    "Every declared finding is resolved or risk-accepted and no exception "
                    "is outstanding at export time."
                ),
            }
        ],
        "back-matter": _back_matter(package),
    }
    return {"plan-of-action-and-milestones": poam}


EXPORT_FILES = {
    CATALOG_FILE: export_catalog,
    PROFILE_FILE: export_profile,
    COMPONENT_DEFINITION_FILE: export_component_definition,
    SSP_FILE: export_ssp,
    ASSESSMENT_PLAN_FILE: export_assessment_plan,
    ASSESSMENT_RESULTS_FILE: export_assessment_results,
    POAM_FILE: export_poam,
}


def export_oscal(
    package: Any,
    out_dir: Path,
    *,
    now: datetime | None = None,
    policy: Any = None,
) -> list[Path]:
    """Write all seven OSCAL documents; returns the paths written, in order.

    ``now`` is passed to the assessment-results export so that currently passing
    contracts appear as satisfied objectives. Fix it and the export stays
    byte-deterministic.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, exporter in EXPORT_FILES.items():
        path = out_dir / filename
        if exporter is export_assessment_results:
            payload = exporter(package, now=now, policy=policy)
        else:
            payload = exporter(package)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written.append(path)
    return written


__all__ = [
    "EXPORT_FILES",
    "MAESTRO_NS",
    "OSCAL_VERSION",
    "export_assessment_plan",
    "export_assessment_results",
    "export_catalog",
    "export_component_definition",
    "export_oscal",
    "export_poam",
    "export_profile",
    "export_ssp",
    "meaf_uuid",
]
