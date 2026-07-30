"""Policy bundle loading and accessors.

Appendix A.4 asks an implementation to publish three versioned artifacts: an
OSCAL profile, a JSON Schema for the extension fields, and "a policy bundle that
expresses cross-object conformance rules that JSON Schema alone cannot enforce".

This module is that third artifact's loader. Every organisational risk choice
lives in the bundle, not in Python: which digest algorithms are acceptable,
which evidence-collection methods are approved, what interruption coverage each
impact tier requires, and what the gate does with an indeterminate contract.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

POLICY_SCHEMA_FILE = "meaf-policy-2.0.0.schema.json"
DEFAULT_POLICY_FILE = "meaf-default-2.0.0.json"

IMPACT_TIERS = ("critical", "high", "medium", "low")
IMPACT_ORDER = {tier: index for index, tier in enumerate(IMPACT_TIERS)}

INDETERMINATE_FAIL_CLOSED = "fail-closed"
INDETERMINATE_REQUIRE_REVIEW = "require-review"
INDETERMINATE_PERMIT = "permit"


class PolicyError(ValueError):
    """Raised when a policy bundle is unreadable or does not conform."""


def load_policy_schema() -> dict[str, Any]:
    path = Path(__file__).parent / "schema" / POLICY_SCHEMA_FILE
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def default_policy_path() -> Path:
    return Path(__file__).parent / "policies" / DEFAULT_POLICY_FILE


@dataclass(frozen=True)
class Policy:
    """A validated policy bundle.

    Constructed only through :func:`load_policy` or :func:`default_policy` so
    that an unvalidated bundle can never reach the gate.
    """

    raw: dict[str, Any]

    @property
    def policy_id(self) -> str:
        return self.raw["policy-id"]

    @property
    def policy_version(self) -> str:
        return self.raw["policy-version"]

    @property
    def name(self) -> str:
        return f"{self.policy_id}:{self.policy_version}"

    @property
    def permitted_digest_algorithms(self) -> frozenset[str]:
        return frozenset(self.raw["permitted-digest-algorithms"])

    @property
    def approved_evidence_methods(self) -> frozenset[str]:
        return frozenset(self.raw["approved-evidence-methods"])

    @property
    def method_policy_in_force(self) -> bool:
        return bool(self.raw["approved-evidence-methods"])

    @property
    def maximum_exception_age_days(self) -> int:
        return self.raw["maximum-exception-age-days"]

    @property
    def blocking_finding_severities(self) -> frozenset[str]:
        return frozenset(self.raw["block-gate-on-open-finding-severity"])

    @property
    def require_authorization_decision(self) -> bool:
        return self.raw["require-authorization-decision"]

    @property
    def probabilistic_permitted_for_gate(self) -> bool:
        return self.raw["probabilistic-evidence"]["permitted-for-gate"]

    @property
    def probabilistic_requires_decision_rule(self) -> bool:
        return self.raw["probabilistic-evidence"]["require-decision-rule"]

    @property
    def maximum_probabilistic_gating_share(self) -> float | None:
        return self.raw["probabilistic-evidence"].get("maximum-gating-share")

    def interruption_requirement(self, impact: str) -> dict[str, Any]:
        """Return the interruption requirement for an impact tier.

        Unknown tiers fall back to the strictest declared tier rather than to
        no requirement, so a typo in a package cannot silently drop coverage.
        """
        requirements = self.raw["interruption-requirements"]
        if impact in requirements:
            return requirements[impact]
        return requirements["critical"]

    def indeterminate_handling(self, impact: str) -> str:
        handling = self.raw["indeterminate-handling"]
        if impact in handling:
            return handling[impact]
        return handling["critical"]


def validate_policy_document(document: Any) -> list[str]:
    """Return conformance error messages for a candidate policy bundle."""
    validator = Draft202012Validator(load_policy_schema())
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '(root)'}: {error.message}"
        for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    ]


def policy_from_document(document: Any) -> Policy:
    errors = validate_policy_document(document)
    if errors:
        joined = "; ".join(errors)
        raise PolicyError(f"policy bundle does not conform: {joined}")
    return Policy(raw=document)


def load_policy(path: Path) -> Policy:
    """Load and validate a policy bundle from disk."""
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        raise PolicyError(f"cannot read policy bundle {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy bundle {path} is not valid JSON: {exc}") from exc
    return policy_from_document(document)


def default_policy() -> Policy:
    """Load the policy bundle shipped with this distribution."""
    return load_policy(default_policy_path())


def resolve_policy(path: Path | None) -> Policy:
    """Load ``path`` when given, otherwise the shipped default bundle."""
    if path is None:
        return default_policy()
    return load_policy(path)


def strictest_impact(impacts: list[str]) -> str:
    """Return the most severe impact tier in ``impacts``.

    An empty list yields ``low``: a contract that covers no path constrains
    nothing, so it must not inherit critical-tier handling by accident.
    """
    if not impacts:
        return "low"
    return min(impacts, key=lambda tier: IMPACT_ORDER.get(tier, 0))


__all__ = [
    "IMPACT_TIERS",
    "INDETERMINATE_FAIL_CLOSED",
    "INDETERMINATE_PERMIT",
    "INDETERMINATE_REQUIRE_REVIEW",
    "Policy",
    "PolicyError",
    "default_policy",
    "default_policy_path",
    "load_policy",
    "load_policy_schema",
    "policy_from_document",
    "resolve_policy",
    "strictest_impact",
    "validate_policy_document",
]
