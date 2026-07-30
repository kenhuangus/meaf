"""Shared package primitives: findings, indexes, time, and evidence currency.

This module is the bottom of the dependency stack. It imports nothing else from
``meaf`` so that the validator, the contract evaluator, the signer and the
lifecycle can all build on the same definitions without a cycle.

The one non-obvious thing here is :func:`evidence_currency`. Appendix A.5 states
the predicate as

    current(e, t) = (t - e.collected_at <= e.max_age) AND (e.invalidated_at is null)

but qualifies it in the sentence immediately before: evidence is current "only
when its subject digest matches the deployed subject", and in the sentence
immediately after: "Artifact binding takes precedence over calendar freshness.
Evidence collected one minute ago against a superseded prompt, adapter, model
endpoint, graph, policy, or retrieval snapshot is stale." Artifact binding is
therefore a conjunct of currency, not a separate check, and this module
implements it that way.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Iterable

MAESTRO_NODE_RE = re.compile(r"^L([1-7]):[a-z0-9][a-z0-9-]*$")
COLLECTOR_VERSION_RE = re.compile(r"^[^:]+(?::[^:]+)*:[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_RE = re.compile(r"^(sha256|sha384|sha512):([a-f0-9]+)$")
DURATION_RE = re.compile(
    r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$"
)

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"

#: Collections that carry identified objects, in package order.
OBJECT_COLLECTIONS = (
    "components",
    "threats",
    "attack-paths",
    "control-implementations",
    "assurance-contracts",
    "tests",
    "evidence",
    "findings",
    "decisions",
)

#: Appendix A.3 pairs each control function with the interruption types that can
#: honestly express it. The mapping is what stops "a logging control from being
#: counted as prevention or a detector from being credited as containment".
FUNCTION_INTERRUPTION_TYPES: dict[str, frozenset[str]] = {
    "prevent": frozenset({"blocks", "limits"}),
    "detect": frozenset({"detects", "supports-investigation"}),
    "contain": frozenset({"contains", "limits"}),
    "recover": frozenset({"restores"}),
}


@dataclass
class Finding:
    """One conformance observation at one conformance level."""

    level: int
    severity: str
    object_id: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Currency:
    """Result of the appendix A.5 currency predicate for one evidence item."""

    current: bool
    binding_matches: bool
    within_max_age: bool
    not_invalidated: bool
    reasons: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        return {
            "current": self.current,
            "binding-matches": self.binding_matches,
            "within-max-age": self.within_max_age,
            "not-invalidated": self.not_invalidated,
            "reasons": list(self.reasons),
        }


class TimestampError(ValueError):
    """Raised when a package timestamp or duration cannot be parsed."""


def parse_datetime(value: str) -> datetime:
    """Parse an RFC 3339 timestamp into an aware UTC datetime."""
    if not isinstance(value, str):
        raise TimestampError(f"timestamp is not a string: {value!r}")
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise TimestampError(f"unparseable timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_date(value: str) -> date:
    """Parse a calendar date, rejecting anything with a time component."""
    if not isinstance(value, str):
        raise TimestampError(f"date is not a string: {value!r}")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise TimestampError(f"unparseable date {value!r}") from exc


def parse_duration(duration: str) -> float:
    """Parse an ISO 8601 duration to seconds (days, hours, minutes, seconds)."""
    if not isinstance(duration, str):
        raise TimestampError(f"duration is not a string: {duration!r}")
    match = DURATION_RE.fullmatch(duration)
    if not match or duration in ("P", "PT"):
        raise TimestampError(f"unsupported duration: {duration!r}")
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


def layer_number(node: str) -> int | None:
    """Return the MAESTRO layer number of a node label, or None if malformed."""
    if not isinstance(node, str):
        return None
    match = MAESTRO_NODE_RE.match(node)
    return int(match.group(1)) if match else None


def digest_algorithm(digest: str) -> str | None:
    """Return the algorithm prefix of a digest, or None if malformed."""
    if not isinstance(digest, str):
        return None
    match = DIGEST_RE.match(digest)
    return match.group(1) if match else None


def objects(package: Any, collection: str) -> list[dict[str, Any]]:
    """Return the dict-shaped members of a package collection.

    Non-dict members are dropped rather than raising: level 1 already reported
    them, and every later level must keep running so that one malformed object
    does not hide the rest of the package's problems.
    """
    if not isinstance(package, dict):
        return []
    raw = package.get(collection)
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def index_by_id(items: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group objects by identifier, keeping duplicates visible."""
    index: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        object_id = item.get("id")
        if isinstance(object_id, str):
            index.setdefault(object_id, []).append(item)
    return index


def unique_index(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index objects by identifier, first occurrence wins."""
    index: dict[str, dict[str, Any]] = {}
    for item in items:
        object_id = item.get("id")
        if isinstance(object_id, str) and object_id not in index:
            index[object_id] = item
    return index


def role_ids(package: Any) -> frozenset[str]:
    system = package.get("system") if isinstance(package, dict) else None
    if not isinstance(system, dict):
        return frozenset()
    roles = system.get("responsible-roles")
    if not isinstance(roles, list):
        return frozenset()
    return frozenset(
        role["id"]
        for role in roles
        if isinstance(role, dict) and isinstance(role.get("id"), str)
    )


def component_digests(package: Any) -> frozenset[str]:
    return frozenset(
        component["digest"]
        for component in objects(package, "components")
        if isinstance(component.get("digest"), str)
    )


def subject_digests_for(package: Any, subject_id: str | None) -> frozenset[str]:
    """Digests the deployed subject of a claim currently resolves to.

    A claim about a single component binds to that component's digest. A claim
    about the system as a whole binds to every component digest, because a
    system-level assertion made before a component changed is an assertion about
    a system that no longer exists. An unresolvable subject binds to nothing;
    level 2 reports the dangling reference rather than this function guessing.
    """
    if not isinstance(subject_id, str):
        return frozenset()
    for component in objects(package, "components"):
        if component.get("id") == subject_id and isinstance(component.get("digest"), str):
            return frozenset({component["digest"]})
    system = package.get("system") if isinstance(package, dict) else None
    if isinstance(system, dict) and system.get("id") == subject_id:
        return component_digests(package)
    return frozenset()


def evidence_is_fresh(
    collected_at: str,
    max_age: str,
    invalidated_at: str | None,
    now: datetime,
) -> bool:
    """Calendar half of the currency predicate: within max-age and not invalidated.

    Kept separate from :func:`evidence_currency` because it is exactly the part
    of currency that can be answered without knowing what is deployed. Callers
    deciding whether evidence may support a claim want
    :func:`evidence_currency`, which also enforces artifact binding.
    """
    if invalidated_at is not None:
        return False
    collected = parse_datetime(collected_at)
    age_seconds = (now - collected).total_seconds()
    return age_seconds <= parse_duration(max_age)


def evidence_currency(
    evidence: dict[str, Any],
    *,
    now: datetime,
    required_digests: frozenset[str] | None = None,
    deployed_digests: frozenset[str] | None = None,
    max_age_override: str | None = None,
) -> Currency:
    """Evaluate the appendix A.5 currency predicate for one evidence item.

    Artifact binding has two halves, and both are conjuncts of currency.

    ``required_digests`` is the digest set of the deployed subject the evidence
    is being asked to support. Every one of those digests must appear in the
    evidence's ``subject-digests``: evidence about an earlier version of the
    subject is stale however recently it was collected.

    ``deployed_digests`` is everything currently in the component inventory.
    Every digest the evidence *declares* must still be there. An observation
    made against a model that is still deployed but a retrieval corpus that has
    since been replaced is an observation of a system that no longer exists —
    A.5 lists "prompt, adapter, model endpoint, graph, policy, or retrieval
    snapshot" precisely because any one of them supersedes the result.

    ``max_age_override`` lets a contract impose freshness stricter than the
    evidence item declares for itself. The stricter of the two always wins; a
    contract can tighten freshness but an evidence item cannot loosen it.
    """
    reasons: list[str] = []

    actual = evidence.get("subject-digests")
    actual_set = frozenset(actual) if isinstance(actual, list) else frozenset()

    binding_matches = True
    if required_digests:
        missing = sorted(required_digests - actual_set)
        if missing:
            binding_matches = False
            reasons.append(
                "evidence is not bound to the deployed subject; missing digest(s): "
                + ", ".join(missing)
            )
    if deployed_digests is not None:
        superseded = sorted(actual_set - deployed_digests)
        if superseded:
            binding_matches = False
            reasons.append(
                "evidence was collected against artifact(s) that are no longer "
                "deployed: " + ", ".join(superseded)
            )

    not_invalidated = evidence.get("invalidated-at") is None
    if not not_invalidated:
        reasons.append(
            f"evidence was invalidated at {evidence.get('invalidated-at')}"
        )

    within_max_age = False
    try:
        collected = parse_datetime(evidence.get("collected-at"))
        declared = evidence.get("max-age")
        limit = parse_duration(declared)
        if max_age_override is not None:
            limit = min(limit, parse_duration(max_age_override))
        age_seconds = (now - collected).total_seconds()
        within_max_age = age_seconds <= limit
        if not within_max_age:
            reasons.append(
                f"evidence is {age_seconds / 86400:.1f} days old, beyond the "
                f"{limit / 86400:.1f} day limit in force"
            )
    except TimestampError as exc:
        reasons.append(str(exc))

    return Currency(
        current=binding_matches and not_invalidated and within_max_age,
        binding_matches=binding_matches,
        within_max_age=within_max_age,
        not_invalidated=not_invalidated,
        reasons=tuple(reasons),
    )


def has_errors(findings: Iterable[Finding]) -> bool:
    return any(finding.severity == SEVERITY_ERROR for finding in findings)


__all__ = [
    "COLLECTOR_VERSION_RE",
    "Currency",
    "DIGEST_RE",
    "FUNCTION_INTERRUPTION_TYPES",
    "Finding",
    "MAESTRO_NODE_RE",
    "OBJECT_COLLECTIONS",
    "SEVERITY_ERROR",
    "SEVERITY_WARNING",
    "TimestampError",
    "component_digests",
    "digest_algorithm",
    "evidence_currency",
    "evidence_is_fresh",
    "has_errors",
    "index_by_id",
    "layer_number",
    "objects",
    "parse_date",
    "parse_datetime",
    "parse_duration",
    "role_ids",
    "subject_digests_for",
    "unique_index",
]
