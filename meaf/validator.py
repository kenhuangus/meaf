"""MEAF package validator — conformance levels 1 through 6."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator

LAYER_NODE_RE = re.compile(r"^L([1-7]):[a-z0-9][a-z0-9-]*$")
SESSION_PERSISTENCE = frozenset({"session", "request", "single-interaction"})

DETECT_TYPES = frozenset({"blocks", "detects"})
CONTAIN_TYPES = frozenset({"contains", "restores"})
COLLECTOR_VERSION_RE = re.compile(r".*:[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass
class Finding:
    level: int
    severity: str
    object_id: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_schema() -> dict[str, Any]:
    schema_path = Path(__file__).parent / "schema" / "meaf-1.1.0.schema.json"
    with schema_path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_package(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_duration(duration: str) -> float:
    """Parse ISO 8601 duration to seconds (days/hours/minutes/seconds only)."""
    match = re.fullmatch(
        r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$",
        duration,
    )
    if not match:
        raise ValueError(f"unsupported duration: {duration}")
    days, hours, minutes, seconds = match.groups()
    total = 0.0
    if days:
        total += int(days) * 86400
    if hours:
        total += int(hours) * 3600
    if minutes:
        total += int(minutes) * 60
    if seconds:
        total += float(seconds)
    return total


def evidence_is_fresh(
    collected_at: str,
    max_age: str,
    invalidated_at: str | None,
    now: datetime,
) -> bool:
    """Freshness predicate: within max-age and not invalidated."""
    if invalidated_at is not None:
        return False
    collected = parse_datetime(collected_at)
    age_seconds = (now - collected).total_seconds()
    return age_seconds <= parse_duration(max_age)


def _index_by_id(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        index.setdefault(item["id"], []).append(item)
    return index


def validate_l1_syntactic(package: dict[str, Any], schema: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    validator = Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(package), key=lambda e: list(e.path)):
        path = "/".join(str(part) for part in error.absolute_path) or "(root)"
        findings.append(
            Finding(
                level=1,
                severity="error",
                object_id=path,
                message=error.message,
            )
        )
    return findings


def _check_ref(
    findings: list[Finding],
    ref_value: str,
    indices: dict[str, dict[str, list[dict[str, Any]]]],
    collection: str,
    object_id: str,
    field: str,
) -> None:
    matches = indices[collection].get(ref_value, [])
    if not matches:
        findings.append(
            Finding(
                level=2,
                severity="error",
                object_id=object_id,
                message=f"dangling reference {field}={ref_value!r} (no {collection} with that id)",
            )
        )
    elif len(matches) > 1:
        findings.append(
            Finding(
                level=2,
                severity="error",
                object_id=object_id,
                message=f"duplicate id {ref_value!r} in {collection} ({len(matches)} objects)",
            )
        )


def validate_l2_referential(package: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    collections = {
        "threats": package.get("threats", []),
        "attack-paths": package.get("attack-paths", []),
        "assurance-contracts": package.get("assurance-contracts", []),
        "tests": package.get("tests", []),
        "evidence": package.get("evidence", []),
    }
    indices = {name: _index_by_id(items) for name, items in collections.items()}

    for collection_name in collections:
        for object_id, matches in indices[collection_name].items():
            if len(matches) > 1:
                findings.append(
                    Finding(
                        level=2,
                        severity="error",
                        object_id=object_id,
                        message=f"duplicate id in {collection_name} ({len(matches)} objects)",
                    )
                )

    for threat in package.get("threats", []):
        _check_ref(
            findings,
            threat["path"],
            indices,
            "attack-paths",
            threat["id"],
            "path",
        )

    for contract in package.get("assurance-contracts", []):
        _check_ref(
            findings,
            contract["test"],
            indices,
            "tests",
            contract["id"],
            "test",
        )
        for threat_id in contract.get("threats", []):
            _check_ref(
                findings,
                threat_id,
                indices,
                "threats",
                contract["id"],
                "threats[]",
            )
        for evidence_id in contract.get("required-evidence", []):
            _check_ref(
                findings,
                evidence_id,
                indices,
                "evidence",
                contract["id"],
                "required-evidence[]",
            )

    for component in package.get("components", []):
        _check_ref(
            findings,
            component["provenance-evidence"],
            indices,
            "evidence",
            component["id"],
            "provenance-evidence",
        )

    for finding in package.get("findings", []):
        _check_ref(
            findings,
            finding["failed-claim"],
            indices,
            "assurance-contracts",
            finding["id"],
            "failed-claim",
        )
        _check_ref(
            findings,
            finding["retest-reference"],
            indices,
            "tests",
            finding["id"],
            "retest-reference",
        )
        for path_id in finding.get("affected-paths", []):
            _check_ref(
                findings,
                path_id,
                indices,
                "attack-paths",
                finding["id"],
                "affected-paths[]",
            )

    return findings


def _layer_number(node: str) -> int | None:
    match = LAYER_NODE_RE.match(node)
    if not match:
        return None
    return int(match.group(1))


def persistence_beyond_session(persistence: str) -> bool:
    return persistence.lower() not in SESSION_PERSISTENCE


def validate_l3_semantic(package: dict[str, Any], now: datetime) -> list[Finding]:
    findings: list[Finding] = []

    path_index = _index_by_id(package.get("attack-paths", []))
    threat_index = _index_by_id(package.get("threats", []))
    contracts = package.get("assurance-contracts", [])

    for attack_path in package.get("attack-paths", []):
        path_id = attack_path["id"]
        prev_layer: int | None = None
        for node in attack_path.get("nodes", []):
            layer = _layer_number(node)
            if layer is None:
                findings.append(
                    Finding(
                        level=3,
                        severity="error",
                        object_id=path_id,
                        message=f"invalid attack-path node {node!r}; expected L1-L7:<label>",
                    )
                )
                continue
            if prev_layer is not None and layer < prev_layer:
                findings.append(
                    Finding(
                        level=3,
                        severity="error",
                        object_id=path_id,
                        message=(
                            f"attack-path nodes not layer-ordered: {node!r} "
                            f"precedes a higher layer"
                        ),
                    )
                )
            prev_layer = layer

    for evidence in package.get("evidence", []):
        evidence_id = evidence["id"]
        try:
            collected = parse_datetime(evidence["collected-at"])
        except ValueError:
            findings.append(
                Finding(
                    level=3,
                    severity="error",
                    object_id=evidence_id,
                    message="invalid collected-at timestamp",
                )
            )
            continue

        if collected > now:
            findings.append(
                Finding(
                    level=3,
                    severity="error",
                    object_id=evidence_id,
                    message="collected-at is in the future",
                )
            )

        invalidated_at = evidence.get("invalidated-at")
        if invalidated_at is not None:
            try:
                invalidated = parse_datetime(invalidated_at)
            except ValueError:
                findings.append(
                    Finding(
                        level=3,
                        severity="error",
                        object_id=evidence_id,
                        message="invalid invalidated-at timestamp",
                    )
                )
                continue
            if invalidated < collected:
                findings.append(
                    Finding(
                        level=3,
                        severity="error",
                        object_id=evidence_id,
                        message="invalidated-at is before collected-at",
                    )
                )

        try:
            fresh = evidence_is_fresh(
                evidence["collected-at"],
                evidence["max-age"],
                invalidated_at,
                now,
            )
        except ValueError:
            findings.append(
                Finding(
                    level=3,
                    severity="error",
                    object_id=evidence_id,
                    message="invalid max-age duration",
                )
            )
            continue

        if not fresh:
            findings.append(
                Finding(
                    level=3,
                    severity="warning",
                    object_id=evidence_id,
                    message="evidence is stale at evaluation time",
                )
            )

    contracts_by_threat: dict[str, list[dict[str, Any]]] = {}
    for contract in contracts:
        for threat_id in contract.get("threats", []):
            contracts_by_threat.setdefault(threat_id, []).append(contract)

    for threat in package.get("threats", []):
        threat_id = threat["id"]
        profile = threat.get("temporal-profile", {})
        persistence = profile.get("persistence", "")
        if persistence_beyond_session(persistence):
            linked = contracts_by_threat.get(threat_id, [])
            if not linked:
                findings.append(
                    Finding(
                        level=3,
                        severity="error",
                        object_id=threat_id,
                        message=(
                            "threat with persistence beyond session lacks "
                            "assurance-contract reference"
                        ),
                    )
                )

    contracts_by_path: dict[str, list[dict[str, Any]]] = {}
    for threat in package.get("threats", []):
        path_id = threat.get("path")
        if path_id and path_id in path_index:
            for contract in contracts_by_threat.get(threat["id"], []):
                contracts_by_path.setdefault(path_id, []).append(contract)

    referenced_paths = {threat["path"] for threat in package.get("threats", [])}
    for path_id in referenced_paths:
        if path_id not in path_index:
            continue
        path_contracts = contracts_by_path.get(path_id, [])
        has_detect = any(
            c.get("interruption-type") in DETECT_TYPES for c in path_contracts
        )
        has_contain = any(
            c.get("interruption-type") in CONTAIN_TYPES for c in path_contracts
        )
        if not has_detect:
            findings.append(
                Finding(
                    level=3,
                    severity="error",
                    object_id=path_id,
                    message=(
                        "attack-path lacks assurance-contract with "
                        "interruption-type blocks or detects"
                    ),
                )
            )
        if not has_contain:
            findings.append(
                Finding(
                    level=3,
                    severity="error",
                    object_id=path_id,
                    message=(
                        "attack-path lacks assurance-contract with "
                        "interruption-type contains or restores"
                    ),
                )
            )

    return findings


def validate_l5_policy(package: dict[str, Any], now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    evidence_index = {item["id"]: item for item in package.get("evidence", [])}

    contracts_by_threat: dict[str, list[dict[str, Any]]] = {}
    for contract in package.get("assurance-contracts", []):
        for threat_id in contract.get("threats", []):
            contracts_by_threat.setdefault(threat_id, []).append(contract)

    for threat in package.get("threats", []):
        threat_id = threat["id"]
        if not contracts_by_threat.get(threat_id):
            findings.append(
                Finding(
                    level=5,
                    severity="error",
                    object_id=threat_id,
                    message="threat lacks assurance-contract reference",
                )
            )

    for evidence in package.get("evidence", []):
        if evidence.get("result") != "fail":
            continue
        evidence_id = evidence["id"]
        linked_contracts = {
            contract["id"]
            for contract in package.get("assurance-contracts", [])
            if evidence_id in contract.get("required-evidence", [])
        }
        finding_refs = [
            finding
            for finding in package.get("findings", [])
            if finding.get("failed-claim") in linked_contracts
        ]
        if not finding_refs:
            findings.append(
                Finding(
                    level=5,
                    severity="error",
                    object_id=evidence_id,
                    message="failed evidence lacks findings object referencing its contract",
                )
            )

    for decision in package.get("decisions", []):
        decision_id = decision.get("id", "(unknown)")
        expiry = decision.get("expiry")
        if not expiry:
            continue
        try:
            expiry_date = datetime.fromisoformat(expiry).replace(tzinfo=timezone.utc)
        except ValueError:
            findings.append(
                Finding(
                    level=5,
                    severity="error",
                    object_id=decision_id,
                    message="decision has invalid expiry date",
                )
            )
            continue
        if expiry_date.date() < now.date():
            findings.append(
                Finding(
                    level=5,
                    severity="error",
                    object_id=decision_id,
                    message="decision or exception expiry is in the past",
                )
            )

    for contract in package.get("assurance-contracts", []):
        contract_id = contract["id"]
        required = contract.get("required-evidence", [])
        if not required:
            continue
        all_stale = True
        for evidence_id in required:
            evidence = evidence_index.get(evidence_id)
            if evidence is None:
                all_stale = False
                break
            try:
                fresh = evidence_is_fresh(
                    evidence["collected-at"],
                    evidence["max-age"],
                    evidence.get("invalidated-at"),
                    now,
                )
            except ValueError:
                all_stale = False
                break
            if fresh:
                all_stale = False
                break
        if all_stale:
            findings.append(
                Finding(
                    level=5,
                    severity="error",
                    object_id=contract_id,
                    message=(
                        "contract policy violation: all required-evidence items "
                        "are stale at evaluation time"
                    ),
                )
            )

    from meaf.contracts import evaluate_contracts

    finding_contract_ids = {
        finding.get("failed-claim")
        for finding in package.get("findings", [])
    }
    for evaluation in evaluate_contracts(package, now=now):
        contract_id = evaluation["contract-id"]
        if evaluation["state"] != "fail":
            continue
        if contract_id not in finding_contract_ids:
            findings.append(
                Finding(
                    level=5,
                    severity="error",
                    object_id=contract_id,
                    message=(
                        "failed assurance-contract lacks findings object "
                        "referencing its claim"
                    ),
                )
            )

    for contract in package.get("assurance-contracts", []):
        contract_id = contract["id"]
        function = contract.get("function", "")
        if function not in ("prevent", "detect"):
            continue
        if contract.get("decision-rule") and not contract.get("utility-rule"):
            findings.append(
                Finding(
                    level=5,
                    severity="warning",
                    object_id=contract_id,
                    message=(
                        "security threshold declared without a utility threshold"
                    ),
                )
            )

    return findings


def validate_l6_reproducibility(package: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for evidence in package.get("evidence", []):
        evidence_id = evidence.get("id", "(unknown)")
        collector = evidence.get("collector", "")
        if not COLLECTOR_VERSION_RE.match(collector):
            findings.append(
                Finding(
                    level=6,
                    severity="error",
                    object_id=evidence_id,
                    message=(
                        "evidence collector lacks explicit version "
                        "(expected name:major.minor.patch)"
                    ),
                )
            )
    return findings


def validate_package(
    package: dict[str, Any],
    *,
    now: datetime | None = None,
    schema: dict[str, Any] | None = None,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> list[Finding]:
    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    if schema is None:
        schema = load_schema()

    findings: list[Finding] = []
    findings.extend(validate_l1_syntactic(package, schema))

    # L2/L3 require parseable structure; skip if L1 failed badly on root type.
    if not isinstance(package, dict):
        return findings

    findings.extend(validate_l2_referential(package))
    findings.extend(validate_l3_semantic(package, now))

    from meaf.signing import validate_l4_evidence

    findings.extend(validate_l4_evidence(package, keyring=keyring, root=root))
    findings.extend(validate_l5_policy(package, now))
    findings.extend(validate_l6_reproducibility(package))
    return findings


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == "error" for f in findings)


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "Validation passed (0 errors, 0 warnings)."
    lines: list[str] = []
    for level in (1, 2, 3, 4, 5, 6):
        level_findings = [f for f in findings if f.level == level]
        if not level_findings:
            continue
        lines.append(f"L{level}:")
        for finding in level_findings:
            obj = finding.object_id or "(unknown)"
            lines.append(f"  [{finding.severity}] {obj}: {finding.message}")
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    lines.append(f"Summary: {errors} error(s), {warnings} warning(s).")
    return "\n".join(lines)
