"""Standard test-pack registry (manuscript appendix A.7).

The registry answers one question a package cannot answer about itself: does the
test cited by an assurance contract belong to a pack whose required evaluations
are known, or is it a bespoke test whose coverage nobody outside the authoring
team can reason about? Both are legitimate; only one of them is checkable, so
MEAF records which it is rather than assuming.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

REGISTRY_FILE = "registry-2.0.0.json"


@dataclass(frozen=True)
class TestPack:
    id: str
    title: str
    primary_layers: tuple[str, ...]
    adversarial: bool
    required_evaluation: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "primary-layers": list(self.primary_layers),
            "adversarial": self.adversarial,
            "required-evaluation": list(self.required_evaluation),
        }


def registry_path() -> Path:
    return Path(__file__).parent / "testpacks" / REGISTRY_FILE


@lru_cache(maxsize=1)
def load_registry() -> dict[str, TestPack]:
    """Return the registered standard test packs keyed by identifier."""
    with registry_path().open(encoding="utf-8") as handle:
        raw = json.load(handle)
    packs: dict[str, TestPack] = {}
    for entry in raw["packs"]:
        packs[entry["id"]] = TestPack(
            id=entry["id"],
            title=entry["title"],
            primary_layers=tuple(entry["primary-layers"]),
            adversarial=entry["adversarial"],
            required_evaluation=tuple(entry["required-evaluation"]),
        )
    return packs


def known_pack_ids() -> frozenset[str]:
    return frozenset(load_registry())


def get_pack(pack_id: str) -> TestPack | None:
    return load_registry().get(pack_id)


def format_registry() -> str:
    lines: list[str] = []
    for pack in load_registry().values():
        layers = ", ".join(pack.primary_layers)
        kind = "adversarial" if pack.adversarial else "operational"
        lines.append(f"{pack.id}  [{kind}]  layers: {layers}")
        lines.append(f"  {pack.title}")
        for requirement in pack.required_evaluation:
            lines.append(f"    - {requirement}")
    return "\n".join(lines)


__all__ = [
    "TestPack",
    "format_registry",
    "get_pack",
    "known_pack_ids",
    "load_registry",
    "registry_path",
]
