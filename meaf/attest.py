"""Artifact attestation — digest computation and package binding checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

AttestationStatus = str  # match | drift | missing-file | no-artifact-path


def compute_digest(path: Path) -> str:
    """Return sha256:<hex> over raw file bytes with CRLF normalized to LF."""
    raw = path.read_bytes()
    # Windows git autocrlf converts LF to CRLF on checkout; normalize so clones
    # on CRLF platforms do not spuriously report digest drift.
    normalized = raw.replace(b"\r\n", b"\n")
    digest = hashlib.sha256(normalized).hexdigest()
    return f"sha256:{digest}"


def check_attestation(package: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    """Return per-component attestation records for the package."""
    records: list[dict[str, Any]] = []
    root = root.resolve()

    for component in package.get("components", []):
        component_id = component.get("id", "(unknown)")
        artifact_path = component.get("artifact-path")
        recorded_digest = component.get("digest")

        if not artifact_path:
            records.append(
                {
                    "component-id": component_id,
                    "artifact-path": None,
                    "recorded-digest": recorded_digest,
                    "computed-digest": None,
                    "status": "no-artifact-path",
                }
            )
            continue

        full_path = root / Path(artifact_path.replace("\\", "/"))
        if not full_path.is_file():
            records.append(
                {
                    "component-id": component_id,
                    "artifact-path": artifact_path,
                    "recorded-digest": recorded_digest,
                    "computed-digest": None,
                    "status": "missing-file",
                }
            )
            continue

        computed_digest = compute_digest(full_path)
        status: AttestationStatus = (
            "match" if computed_digest == recorded_digest else "drift"
        )
        records.append(
            {
                "component-id": component_id,
                "artifact-path": artifact_path,
                "recorded-digest": recorded_digest,
                "computed-digest": computed_digest,
                "status": status,
            }
        )

    return records


def has_attestation_drift(package: dict[str, Any], root: Path) -> bool:
    """True when any component with artifact-path has digest drift."""
    return any(record["status"] == "drift" for record in check_attestation(package, root))


def _replace_digest_in_evidence(
    package: dict[str, Any],
    old_digest: str,
    new_digest: str,
) -> int:
    replacements = 0
    for evidence in package.get("evidence", []):
        subject_digests = evidence.get("subject-digests", [])
        for index, digest in enumerate(subject_digests):
            if digest == old_digest:
                subject_digests[index] = new_digest
                replacements += 1
    return replacements


def update_attestation(
    package: dict[str, Any],
    root: Path,
) -> tuple[dict[str, Any], list[str]]:
    """Rewrite recorded digests from computed values; return updated package and change log."""
    updated = json.loads(json.dumps(package))
    changes: list[str] = []
    records = check_attestation(updated, root)

    component_index = {component["id"]: component for component in updated.get("components", [])}

    for record in records:
        if record["status"] not in ("drift", "match"):
            continue
        component_id = record["component-id"]
        old_digest = record["recorded-digest"]
        new_digest = record["computed-digest"]
        if old_digest == new_digest:
            continue

        component = component_index.get(component_id)
        if component is None:
            continue

        component["digest"] = new_digest
        evidence_updates = _replace_digest_in_evidence(updated, old_digest, new_digest)
        changes.append(
            f"{component_id}: {old_digest} -> {new_digest} "
            f"({evidence_updates} evidence subject-digest(s) updated)"
        )

    return updated, changes


def default_root_for_package(package_path: Path) -> Path:
    """Return repo root for a package under meaf/examples/."""
    return package_path.resolve().parent.parent.parent


def format_attestation_records(records: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in records:
        component_id = record["component-id"]
        status = record["status"]
        artifact_path = record.get("artifact-path") or "(none)"
        recorded = record.get("recorded-digest") or "(none)"
        computed = record.get("computed-digest") or "(none)"
        lines.append(
            f"{component_id}: {status} "
            f"(artifact-path={artifact_path}, recorded={recorded}, computed={computed})"
        )
    return "\n".join(lines)


def attestation_exit_code(records: list[dict[str, Any]]) -> int:
    for record in records:
        if record["status"] in ("drift", "missing-file"):
            return 1
    return 0
