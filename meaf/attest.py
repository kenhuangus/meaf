"""Artifact attestation — digest computation and package binding checks.

"Assurance follows the deployed artifact" (A.1 principle 3) only means anything
if the digest in the package is the digest of the file on disk. This module
computes the second and compares it to the first.

Two deliberate choices:

* Digests are the plain hash of the file's bytes. An earlier version normalised
  CRLF to LF before hashing, which made ``sha256:<hex>`` not the SHA-256 of the
  artifact and let two different files share one digest. The repository pins
  line endings in ``.gitattributes`` instead, which fixes the checkout problem
  without lying about what the digest is.
* ``artifact-path`` is resolved relative to the package file's own directory and
  must stay inside it. A package that could name ``/etc/shadow`` or
  ``../../secrets`` would let an assurance document read arbitrary files on
  whatever machine validates it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

#: match | drift | missing-file | outside-root | no-artifact-path
AttestationStatus = str

STATUS_MATCH = "match"
STATUS_DRIFT = "drift"
STATUS_MISSING_FILE = "missing-file"
STATUS_OUTSIDE_ROOT = "outside-root"
STATUS_NO_ARTIFACT_PATH = "no-artifact-path"

FAILING_STATUSES = frozenset({STATUS_DRIFT, STATUS_MISSING_FILE, STATUS_OUTSIDE_ROOT})

_HASHERS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


class ArtifactPathError(ValueError):
    """Raised when an artifact-path escapes the attestation root."""


def compute_digest(path: Path, algorithm: str = "sha256") -> str:
    """Return ``<algorithm>:<hex>`` over the file's bytes."""
    hasher = _HASHERS.get(algorithm)
    if hasher is None:
        raise ValueError(f"unsupported digest algorithm: {algorithm!r}")
    digest = hasher()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"{algorithm}:{digest.hexdigest()}"


def digest_algorithm_of(digest: Any, default: str = "sha256") -> str:
    """Algorithm named by a recorded digest, so verification uses the same one."""
    if isinstance(digest, str) and ":" in digest:
        candidate = digest.split(":", 1)[0]
        if candidate in _HASHERS:
            return candidate
    return default


def resolve_artifact_path(root: Path, artifact_path: str) -> Path:
    """Resolve ``artifact_path`` under ``root``, refusing to escape it."""
    candidate = Path(artifact_path.replace("\\", "/"))
    if candidate.is_absolute():
        raise ArtifactPathError(f"artifact-path {artifact_path!r} is absolute")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ArtifactPathError(
            f"artifact-path {artifact_path!r} resolves outside the attestation root"
        )
    return resolved


def check_attestation(package: Any, root: Path) -> list[dict[str, Any]]:
    """Return one attestation record per component, in package order."""
    records: list[dict[str, Any]] = []
    if not isinstance(package, dict):
        return records

    for component in package.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        component_id = component.get("id", "(unknown)")
        artifact_path = component.get("artifact-path")
        recorded_digest = component.get("digest")

        record: dict[str, Any] = {
            "component-id": component_id,
            "artifact-path": artifact_path,
            "recorded-digest": recorded_digest,
            "computed-digest": None,
            "status": STATUS_NO_ARTIFACT_PATH,
        }

        if not artifact_path:
            records.append(record)
            continue

        try:
            full_path = resolve_artifact_path(root, str(artifact_path))
        except ArtifactPathError:
            record["status"] = STATUS_OUTSIDE_ROOT
            records.append(record)
            continue

        if not full_path.is_file():
            record["status"] = STATUS_MISSING_FILE
            records.append(record)
            continue

        computed = compute_digest(full_path, digest_algorithm_of(recorded_digest))
        record["computed-digest"] = computed
        record["status"] = STATUS_MATCH if computed == recorded_digest else STATUS_DRIFT
        records.append(record)

    return records


def has_attestation_drift(package: Any, root: Path) -> bool:
    """True when any component with an artifact-path no longer matches its digest."""
    return any(record["status"] == STATUS_DRIFT for record in check_attestation(package, root))


def unbound_evidence(package: Any, digests: set[str]) -> list[str]:
    """Evidence ids still bound to digests that are no longer deployed."""
    stale: list[str] = []
    if not isinstance(package, dict):
        return stale
    for evidence in package.get("evidence", []) or []:
        if not isinstance(evidence, dict):
            continue
        subject_digests = evidence.get("subject-digests") or []
        if any(digest in digests for digest in subject_digests):
            stale.append(str(evidence.get("id")))
    return stale


def update_attestation(package: Any, root: Path) -> tuple[dict[str, Any], list[str]]:
    """Rebind component digests to what is on disk and report the fallout.

    Component digests are rewritten. Evidence ``subject-digests`` are *not*.
    Rewriting them would forge the one relationship the framework exists to
    protect: evidence collected against the old artifact would silently claim to
    be about the new one, which inverts "artifact binding takes precedence over
    calendar freshness" (A.5). The evidence that has become unbound is listed in
    the change log so the operator can re-collect it.
    """
    import copy

    updated = copy.deepcopy(package)
    changes: list[str] = []
    records = check_attestation(updated, root)
    component_index = {
        component["id"]: component
        for component in updated.get("components", []) or []
        if isinstance(component, dict) and "id" in component
    }

    for record in records:
        if record["status"] not in (STATUS_DRIFT, STATUS_MATCH):
            continue
        old_digest = record["recorded-digest"]
        new_digest = record["computed-digest"]
        if old_digest == new_digest:
            continue
        component = component_index.get(record["component-id"])
        if component is None:
            continue
        component["digest"] = new_digest
        orphaned = unbound_evidence(updated, {old_digest})
        changes.append(
            f"{record['component-id']}: {old_digest} -> {new_digest}"
            + (
                f"; evidence now unbound and requiring re-collection: {', '.join(orphaned)}"
                if orphaned
                else "; no evidence was bound to the previous digest"
            )
        )

    return updated, changes


def default_root_for_package(package_path: Path) -> Path:
    """Attestation root for a package: the directory the package file lives in."""
    return package_path.resolve().parent


def format_attestation_records(records: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in records:
        lines.append(
            f"{record['component-id']}: {record['status']} "
            f"(artifact-path={record.get('artifact-path') or '(none)'}, "
            f"recorded={record.get('recorded-digest') or '(none)'}, "
            f"computed={record.get('computed-digest') or '(none)'})"
        )
    return "\n".join(lines)


def attestation_exit_code(records: list[dict[str, Any]]) -> int:
    return 1 if any(record["status"] in FAILING_STATUSES for record in records) else 0


__all__ = [
    "ArtifactPathError",
    "FAILING_STATUSES",
    "STATUS_DRIFT",
    "STATUS_MATCH",
    "STATUS_MISSING_FILE",
    "STATUS_NO_ARTIFACT_PATH",
    "STATUS_OUTSIDE_ROOT",
    "attestation_exit_code",
    "check_attestation",
    "compute_digest",
    "default_root_for_package",
    "format_attestation_records",
    "has_attestation_drift",
    "resolve_artifact_path",
    "unbound_evidence",
    "update_attestation",
]
