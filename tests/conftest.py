"""Shared fixtures.

Two rules the whole suite obeys.

*Time is injected.* Every test that touches freshness, expiry or currency uses
:data:`FROZEN_NOW`. A test whose outcome changes when the calendar does is not a
test, and this codebase is about the difference between an observation and an
assumption.

*The shipped examples are never mutated.* Fixtures hand out deep copies, and
tests that need to write files copy the example tree into ``tmp_path`` first.
``test_examples.py`` asserts at the end that the tree on disk is exactly what
the regeneration script produces, which catches any test that breaks this rule.
"""

from __future__ import annotations

import copy
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from meaf.policy import Policy, load_policy
from meaf.signing import load_keyring

#: The evaluation instant used across the suite. Chosen so that the shipped
#: examples' evidence is current: the counterfactual run is 13 days old against
#: a 30 day window, the attestations are 27 days old against 90.
FROZEN_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)

#: Far enough past FROZEN_NOW that every example's evidence has aged out.
STALE_NOW = datetime(2026, 12, 1, 0, 0, 0, tzinfo=timezone.utc)

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "meaf" / "examples"


def _load(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture(scope="session")
def _covert_source() -> Any:
    return _load(EXAMPLES / "covert-influence.json")


@pytest.fixture(scope="session")
def _memory_source() -> Any:
    return _load(EXAMPLES / "memory-poisoning.json")


@pytest.fixture(scope="session")
def _broken_source() -> Any:
    return _load(EXAMPLES / "broken.json")


@pytest.fixture
def covert(_covert_source: Any) -> dict[str, Any]:
    """The clean reference package: every contract passes, the gate allows."""
    return copy.deepcopy(_covert_source)


@pytest.fixture
def memory(_memory_source: Any) -> dict[str, Any]:
    """A package under remediation: one failing contract under a live exception."""
    return copy.deepcopy(_memory_source)


@pytest.fixture
def broken(_broken_source: Any) -> dict[str, Any]:
    """A package with a deliberate error at every conformance level."""
    return copy.deepcopy(_broken_source)


@pytest.fixture(scope="session")
def keyring() -> dict[str, bytes]:
    return load_keyring(EXAMPLES / "keyring.json")


@pytest.fixture(scope="session")
def policy() -> Policy:
    from meaf.policy import default_policy

    return default_policy()


@pytest.fixture(scope="session")
def strict_policy() -> Policy:
    return load_policy(EXAMPLES / "policy-strict.json")


@pytest.fixture
def example_tree(tmp_path: Path) -> Path:
    """A writable copy of ``meaf/examples`` for tests that mutate files."""
    destination = tmp_path / "examples"
    shutil.copytree(EXAMPLES, destination)
    return destination


@pytest.fixture
def covert_path(example_tree: Path) -> Path:
    return example_tree / "covert-influence.json"


def write_package(path: Path, package: Any) -> Path:
    path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    return path
