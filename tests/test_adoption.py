"""The A.9 adoption sequence must stay separable from the A.5 conformance model.

A.9 offers organisations a route in that "avoids waiting for a complete
universal standard". It is advice, not a requirement, and the two ladders are
easy to confuse because both are numbered one to five or six. These tests pin
the levels to the criteria the manuscript states, and pin the output to saying
out loud which ladder it is reporting on, so that "we are at level 4" can never
be read as a conformance claim.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from meaf.adoption import LEVEL_TITLES, assess_adoption, format_adoption
from tests.conftest import FROZEN_NOW

#: A package that has been through the A.8 gate at least once. The reference
#: example ships without one because it is a first authorization; level 4 is
#: about the *continuous* half of the lifecycle, which needs a history.
AUTHORIZED_LIFECYCLE = {
    "state": "authorized",
    "history": [
        {
            "from": "assessed",
            "to": "authorized",
            "at": "2026-07-20T00:00:00Z",
            "actor": "ai-assurance-review-board",
            "reason": "gate allowed under meaf-default:2.0.0",
        }
    ],
}


@pytest.fixture
def continuous(covert: dict[str, Any]) -> dict[str, Any]:
    """The reference package with the lifecycle history level 4 asks for."""
    package = copy.deepcopy(covert)
    package["lifecycle"] = copy.deepcopy(AUTHORIZED_LIFECYCLE)
    return package


def assess(
    package: Any, keyring: dict[str, bytes], root: Path
) -> tuple[int, dict[int, bool]]:
    reached, criteria = assess_adoption(
        package, now=FROZEN_NOW, keyring=keyring, root=root
    )
    return reached, {criterion.level: criterion.met for criterion in criteria}


def test_the_five_levels_are_the_ones_the_manuscript_names():
    # A.9: "Level 1, structured ... Level 2, test-linked ... Level 3,
    # evidence-bound ... Level 4, continuous ... Level 5, exchangeable."
    assert LEVEL_TITLES == {
        1: "structured",
        2: "test-linked",
        3: "evidence-bound",
        4: "continuous",
        5: "exchangeable",
    }


def test_the_reference_package_is_at_least_evidence_bound(covert, keyring, examples_dir):
    # A.9 level 3: "sign evidence, bind it to artifact digests, enforce
    # freshness, and generate human-readable reports from the package."
    reached, met = assess(covert, keyring, examples_dir)

    assert reached >= 3
    assert met[1] and met[2] and met[3]


def test_levels_are_cumulative_so_a_gap_caps_the_result(covert, keyring, examples_dir):
    """The reached level is the highest N with levels 1..N all met.

    A.9 is a sequence, not a menu. The reference package satisfies level 5's
    criteria — it declares a policy bundle, records supplier provenance and
    reproduces deterministically — but records no lifecycle history, so it has
    not integrated change events and cannot be reported above level 3.
    """
    reached, met = assess(covert, keyring, examples_dir)

    assert met[5] is True
    assert met[4] is False
    assert reached == 3


def test_a_package_with_lifecycle_history_completes_the_sequence(
    continuous, keyring, examples_dir
):
    reached, met = assess(continuous, keyring, examples_dir)

    assert all(met.values())
    assert reached == 5


def test_unsigned_evidence_is_not_evidence_bound(covert, keyring, examples_dir):
    # A.9 level 3 begins "sign evidence"; an unsigned observation is not
    # attributable to the collector that claims to have made it.
    for evidence in covert["evidence"]:
        evidence.pop("signature", None)

    reached, met = assess(covert, keyring, examples_dir)

    assert met[3] is False
    assert reached < 3


def test_components_without_artifact_paths_are_not_continuously_attestable(
    continuous, keyring, examples_dir
):
    """A.9 level 4 needs change events, and a change event needs something to hash.

    A component whose artifact the tooling cannot locate cannot be re-attested,
    so a drift in it is invisible and no dependent claim is ever invalidated.
    """
    for component in continuous["components"]:
        component.pop("artifact-path", None)

    reached, met = assess(continuous, keyring, examples_dir)

    assert met[4] is False
    assert reached < 4


def test_a_package_without_a_policy_bundle_is_not_exchangeable(
    continuous, keyring, examples_dir
):
    """A.9 level 5 is about a second organisation reaching the same answer.

    A.4 puts the cross-object rules in the policy bundle, so a package that does
    not name the bundle it was authored against cannot be evaluated elsewhere
    and get a comparable result.
    """
    continuous.pop("policy-bundle")

    reached, met = assess(continuous, keyring, examples_dir)

    assert met[5] is False
    assert reached < 5


def test_a_package_without_supplier_provenance_is_not_exchangeable(
    continuous, keyring, examples_dir
):
    # A.9 level 5: "support ... cross-organization package exchange, supplier
    # attestations".
    for component in continuous["components"]:
        component.pop("provenance-evidence", None)

    _, met = assess(continuous, keyring, examples_dir)

    assert met[5] is False


def test_a_structurally_broken_package_reaches_no_level(broken, keyring, examples_dir):
    reached, met = assess(broken, keyring, examples_dir)

    assert met[1] is False
    assert reached == 0


def test_format_adoption_states_that_this_is_not_a_conformance_level(
    covert, keyring, examples_dir
):
    """The one sentence that stops an adoption level being quoted as assurance.

    A.9's own framing is a "practical adoption sequence"; the module docstring
    adds that "reaching level 5 is not a claim that a system is secure".
    """
    reached, criteria = assess_adoption(
        covert, now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )

    text = format_adoption(reached, criteria)

    assert "non-normative" in text
    assert "appendix A.9" in text
    assert "not a conformance level" in text
    assert f"Adoption level reached: {reached} ({LEVEL_TITLES[reached]})" in text


def test_format_adoption_reports_every_level_including_the_unmet_ones(
    covert, keyring, examples_dir
):
    """A level list that stopped at the first gap would hide what is already done.

    The point of the sequence is to tell a team what the next level costs, which
    requires showing the levels beyond the current one.
    """
    reached, criteria = assess_adoption(
        covert, now=FROZEN_NOW, keyring=keyring, root=examples_dir
    )

    text = format_adoption(reached, criteria)

    for criterion in criteria:
        assert f"Level {criterion.level} {LEVEL_TITLES[criterion.level]}:" in text
        assert criterion.detail in text
    assert "not met" in text
