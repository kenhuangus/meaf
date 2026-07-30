"""Adoption-level assessment for the sequence in manuscript A.9.

A.9 sketches "a practical adoption sequence [that] avoids waiting for a complete
universal standard", from level 1 (structured) to level 5 (exchangeable). The
manuscript frames this as guidance for organisations, not as a conformance
requirement on a package, and this module is non-normative in the same way: it
tells a team where they currently are and what the next level would take. It is
not part of the six-level conformance model, and reaching level 5 is not a claim
that a system is secure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from meaf.model import objects
from meaf.policy import Policy, default_policy
from meaf.validator import validate_package

LEVEL_TITLES = {
    1: "structured",
    2: "test-linked",
    3: "evidence-bound",
    4: "continuous",
    5: "exchangeable",
}


@dataclass(frozen=True)
class LevelCriterion:
    level: int
    description: str
    met: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "description": self.description,
            "met": self.met,
            "detail": self.detail,
        }


def _errors_at(findings: list[Any], levels: set[int]) -> list[Any]:
    return [f for f in findings if f.severity == "error" and f.level in levels]


def assess_adoption(
    package: Any,
    *,
    now: datetime,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
) -> tuple[int, list[LevelCriterion]]:
    """Return the highest fully met level and the criterion-by-criterion detail."""
    if policy is None:
        policy = default_policy()

    findings = validate_package(
        package, now=now, keyring=keyring, root=root, policy=policy
    )
    criteria: list[LevelCriterion] = []

    # Level 1, structured.
    structural = _errors_at(findings, {1, 2})
    criteria.append(
        LevelCriterion(
            1,
            "boundary, inventory, threats, paths, controls and owners in a schema-valid package",
            not structural,
            "no schema or reference errors"
            if not structural
            else f"{len(structural)} error(s), first: {structural[0].message}",
        )
    )

    # Level 2, test-linked.
    contracts = objects(package, "assurance-contracts")
    tests_by_id = {str(test.get("id")) for test in objects(package, "tests")}
    contracts_with_tests = [c for c in contracts if c.get("test") in tests_by_id]
    semantic = _errors_at(findings, {3, 5})
    level2_met = bool(contracts) and len(contracts_with_tests) == len(contracts) and not semantic
    criteria.append(
        LevelCriterion(
            2,
            "every high-impact path carries a contract and a reproducible test, and failures produce findings",
            level2_met,
            f"{len(contracts_with_tests)}/{len(contracts)} contracts resolve a test; "
            + (
                "no semantic or policy errors"
                if not semantic
                else f"{len(semantic)} semantic or policy error(s)"
            ),
        )
    )

    # Level 3, evidence-bound.
    evidence = objects(package, "evidence")
    signed = [item for item in evidence if isinstance(item.get("signature"), dict)]
    bound = [item for item in evidence if item.get("subject-digests")]
    evidence_errors = _errors_at(findings, {4})
    level3_met = (
        bool(evidence)
        and len(signed) == len(evidence)
        and len(bound) == len(evidence)
        and not evidence_errors
    )
    criteria.append(
        LevelCriterion(
            3,
            "evidence is signed, bound to artifact digests, and freshness is enforced",
            level3_met,
            f"{len(signed)}/{len(evidence)} signed, {len(bound)}/{len(evidence)} digest-bound"
            + (
                ""
                if not evidence_errors
                else f", {len(evidence_errors)} evidence error(s)"
            ),
        )
    )

    # Level 4, continuous.
    attestable = [c for c in objects(package, "components") if c.get("artifact-path")]
    components = objects(package, "components")
    lifecycle = package.get("lifecycle") if isinstance(package, dict) else None
    has_history = isinstance(lifecycle, dict) and bool(lifecycle.get("history"))
    cadenced = [c for c in contracts if c.get("cadence")]
    level4_met = (
        bool(components)
        and len(attestable) == len(components)
        and has_history
        and len(cadenced) == len(contracts)
    )
    criteria.append(
        LevelCriterion(
            4,
            "material changes invalidate dependent claims and invoke a gate",
            level4_met,
            f"{len(attestable)}/{len(components)} components are attestable on disk, "
            f"{len(cadenced)}/{len(contracts)} contracts declare a cadence, "
            + ("lifecycle history present" if has_history else "no lifecycle history recorded"),
        )
    )

    # Level 5, exchangeable.
    reproducibility = _errors_at(findings, {6})
    declares_policy = isinstance(package.get("policy-bundle"), dict) if isinstance(package, dict) else False
    supplier_attested = any(
        component.get("provider") and component.get("provenance-evidence")
        for component in components
    )
    level5_met = not reproducibility and declares_policy and supplier_attested
    criteria.append(
        LevelCriterion(
            5,
            "independent reproduction, package exchange and supplier attestations are supported",
            level5_met,
            (
                "reproducibility checks pass"
                if not reproducibility
                else f"{len(reproducibility)} reproducibility error(s)"
            )
            + (
                ", policy bundle declared"
                if declares_policy
                else ", no policy bundle declared"
            )
            + (
                ", supplier provenance recorded"
                if supplier_attested
                else ", no supplier provenance recorded"
            ),
        )
    )

    reached = 0
    for criterion in criteria:
        if not criterion.met:
            break
        reached = criterion.level

    return reached, criteria


def format_adoption(reached: int, criteria: list[LevelCriterion]) -> str:
    title = LEVEL_TITLES.get(reached, "not yet structured")
    lines = [
        f"Adoption level reached: {reached} ({title})",
        "This is the non-normative adoption sequence of appendix A.9, not a conformance level.",
        "",
    ]
    for criterion in criteria:
        mark = "met" if criterion.met else "not met"
        lines.append(
            f"Level {criterion.level} {LEVEL_TITLES[criterion.level]}: {mark}"
        )
        lines.append(f"  {criterion.description}")
        lines.append(f"  {criterion.detail}")
    return "\n".join(lines)


__all__ = ["LEVEL_TITLES", "LevelCriterion", "assess_adoption", "format_adoption"]
