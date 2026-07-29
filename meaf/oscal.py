"""OSCAL 1.1.2 export from MEAF packages."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OSCAL_VERSION = "1.1.2"
MAESTRO_NS = "https://cloudsecurityalliance.org/maestro"


def _package_namespace(package_id: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"meaf:{package_id}")


def meaf_uuid(package_id: str, object_id: str) -> str:
    return str(uuid.uuid5(_package_namespace(package_id), object_id))


def _newest_evidence_timestamp(package: dict[str, Any]) -> str:
    newest: datetime | None = None
    for evidence in package.get("evidence", []):
        try:
            collected = datetime.fromisoformat(
                evidence["collected-at"].replace("Z", "+00:00")
            )
        except (KeyError, ValueError):
            continue
        if collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        if newest is None or collected > newest:
            newest = collected
    if newest is None:
        newest = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return newest.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _metadata(package: dict[str, Any], title: str) -> dict[str, Any]:
    return {
        "title": title,
        "last-modified": _newest_evidence_timestamp(package),
        "version": package.get("meaf-version", "1.0.0"),
        "oscal-version": OSCAL_VERSION,
    }


def _maestro_prop(name: str, value: str) -> dict[str, str]:
    return {"name": name, "ns": MAESTRO_NS, "value": value}


def export_catalog(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    controls: list[dict[str, Any]] = []
    for contract in package.get("assurance-contracts", []):
        controls.append(
            {
                "id": contract["id"],
                "title": contract.get("claim", contract["id"]),
                "props": [
                    _maestro_prop("layer", contract.get("interruption-point", "")),
                    _maestro_prop("interruption-type", contract.get("interruption-type", "")),
                ],
                "parts": [
                    {
                        "id": f"{contract['id']}-claim",
                        "name": "statement",
                        "prose": contract.get("claim", ""),
                    }
                ],
            }
        )
    for threat in package.get("threats", []):
        controls.append(
            {
                "id": threat["id"],
                "title": threat.get("objective", threat["id"]),
                "props": [
                    _maestro_prop("attack-path", threat.get("path", "")),
                    _maestro_prop(
                        "temporal-profile",
                        json.dumps(threat.get("temporal-profile", {}), sort_keys=True),
                    ),
                ],
                "parts": [
                    {
                        "id": f"{threat['id']}-objective",
                        "name": "statement",
                        "prose": threat.get("objective", ""),
                    }
                ],
            }
        )
    return {
        "catalog": {
            "uuid": meaf_uuid(package_id, "catalog"),
            "metadata": _metadata(package, f"MEAF Catalog — {package_id}"),
            "controls": {"control": controls},
        }
    }


def export_profile(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    imports = [
        {
            "href": f"#{meaf_uuid(package_id, 'catalog')}",
            "include-controls": {
                "with-ids": [
                    *[c["id"] for c in package.get("assurance-contracts", [])],
                    *[t["id"] for t in package.get("threats", [])],
                ]
            },
        }
    ]
    return {
        "profile": {
            "uuid": meaf_uuid(package_id, "profile"),
            "metadata": _metadata(package, f"MEAF Profile — {package_id}"),
            "imports": imports,
        }
    }


def export_component_definition(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    components: list[dict[str, Any]] = []
    for component in package.get("components", []):
        components.append(
            {
                "uuid": meaf_uuid(package_id, component["id"]),
                "type": "software",
                "title": component["id"],
                "description": component.get("type", ""),
                "props": [
                    _maestro_prop("artifact-binding", component.get("digest", "")),
                ],
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "value": component.get("digest", "").replace("sha256:", ""),
                    }
                ],
            }
        )
    return {
        "component-definition": {
            "uuid": meaf_uuid(package_id, "component-definition"),
            "metadata": _metadata(package, f"MEAF Component Definition — {package_id}"),
            "components": {"component": components},
        }
    }


def export_ssp(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    system = package.get("system", {})
    components: list[dict[str, Any]] = []
    for component in package.get("components", []):
        components.append(
            {
                "uuid": meaf_uuid(package_id, f"ssp-component-{component['id']}"),
                "type": component.get("type", "software"),
                "title": component["id"],
                "status": {"state": "operational"},
                "props": [
                    _maestro_prop("artifact-binding", component.get("digest", "")),
                ],
            }
        )
    implementation_statements: list[dict[str, Any]] = []
    for contract in package.get("assurance-contracts", []):
        implementation_statements.append(
            {
                "uuid": meaf_uuid(package_id, f"ssp-impl-{contract['id']}"),
                "control-id": contract["id"],
                "description": contract.get("claim", ""),
                "props": [
                    _maestro_prop("layer", contract.get("interruption-point", "")),
                    _maestro_prop("interruption-type", contract.get("interruption-type", "")),
                ],
            }
        )
    return {
        "system-security-plan": {
            "uuid": meaf_uuid(package_id, "ssp"),
            "metadata": _metadata(package, f"MEAF SSP — {package_id}"),
            "import-profile": {"href": f"#{meaf_uuid(package_id, 'profile')}"},
            "system-characteristics": {
                "system-ids": [{"identifier-type": "meaf-package", "id": package_id}],
                "system-name": system.get("id", package_id),
                "description": system.get("deployment", ""),
            },
            "system-implementation": {"components": components},
            "control-implementation": {
                "implemented-requirements": implementation_statements
            },
        }
    }


def export_assessment_plan(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    activities: list[dict[str, Any]] = []
    for test in package.get("tests", []):
        activities.append(
            {
                "uuid": meaf_uuid(package_id, f"ap-activity-{test['id']}"),
                "title": test["id"],
                "description": test.get("procedure", ""),
                "props": [
                    _maestro_prop("layer", test.get("target", "")),
                ],
                "methods": ["EXAMINE", "TEST"],
                "subjects": [{"type": "component", "title": test.get("target", "")}],
            }
        )
    return {
        "assessment-plan": {
            "uuid": meaf_uuid(package_id, "assessment-plan"),
            "metadata": _metadata(package, f"MEAF Assessment Plan — {package_id}"),
            "import-ssp": {"href": f"#{meaf_uuid(package_id, 'ssp')}"},
            "local-definitions": {
                "activities": activities,
            },
        }
    }


def export_assessment_results(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    observations: list[dict[str, Any]] = []
    for evidence in package.get("evidence", []):
        props = [
            _maestro_prop("evidence-class", evidence.get("class", "")),
            _maestro_prop(
                "artifact-binding",
                ",".join(evidence.get("subject-digests", [])),
            ),
        ]
        observations.append(
            {
                "uuid": meaf_uuid(package_id, f"ar-obs-{evidence['id']}"),
                "title": evidence["id"],
                "description": evidence.get("method", ""),
                "methods": ["EXAMINE"],
                "collected": evidence.get("collected-at"),
                "props": props,
            }
        )
    findings: list[dict[str, Any]] = []
    for finding in package.get("findings", []):
        findings.append(
            {
                "uuid": meaf_uuid(package_id, f"ar-finding-{finding['id']}"),
                "title": finding["id"],
                "description": finding.get("root-cause", ""),
            }
        )
    risks: list[dict[str, Any]] = []
    for threat in package.get("threats", []):
        risks.append(
            {
                "uuid": meaf_uuid(package_id, f"ar-risk-{threat['id']}"),
                "title": threat["id"],
                "description": threat.get("objective", ""),
                "props": [
                    _maestro_prop("attack-path", threat.get("path", "")),
                ],
            }
        )
    return {
        "assessment-results": {
            "uuid": meaf_uuid(package_id, "assessment-results"),
            "metadata": _metadata(package, f"MEAF Assessment Results — {package_id}"),
            "import-ap": {"href": f"#{meaf_uuid(package_id, 'assessment-plan')}"},
            "results": [
                {
                    "uuid": meaf_uuid(package_id, "assessment-result-root"),
                    "title": "MEAF assessment results",
                    "start": _newest_evidence_timestamp(package),
                    "observations": observations,
                    "findings": findings,
                    "risks": risks,
                }
            ],
        }
    }


def export_poam(package: dict[str, Any]) -> dict[str, Any]:
    package_id = package["package-id"]
    items: list[dict[str, Any]] = []
    for finding in package.get("findings", []):
        items.append(
            {
                "uuid": meaf_uuid(package_id, f"poam-{finding['id']}"),
                "title": finding["id"],
                "description": finding.get("corrective-action", ""),
                "props": [
                    _maestro_prop("severity", finding.get("severity", "")),
                ],
            }
        )
    return {
        "plan-of-action-and-milestones": {
            "uuid": meaf_uuid(package_id, "poam"),
            "metadata": _metadata(package, f"MEAF POA&M — {package_id}"),
            "import-ssp": {"href": f"#{meaf_uuid(package_id, 'ssp')}"},
            "poam-items": items,
        }
    }


EXPORT_FILES = {
    "catalog.json": export_catalog,
    "profile.json": export_profile,
    "component-definition.json": export_component_definition,
    "system-security-plan.json": export_ssp,
    "assessment-plan.json": export_assessment_plan,
    "assessment-results.json": export_assessment_results,
    "plan-of-action-and-milestones.json": export_poam,
}


def export_oscal(package: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, exporter in EXPORT_FILES.items():
        path = out_dir / filename
        payload = exporter(package)
        content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written
