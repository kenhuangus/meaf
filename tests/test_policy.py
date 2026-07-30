"""The policy bundle is where the organisation's risk choices live, not Python.

Appendix A.4 asks for "a policy bundle that expresses cross-object conformance
rules that JSON Schema alone cannot enforce". The point of putting those rules
in data is that two organisations can disagree about acceptable risk while
running the same validator, and that a reader of a gate result can see which
part of the answer was framework and which part was choice. That only holds if
the loader refuses a bundle it cannot fully understand, and if every lookup that
misses falls towards more coverage rather than less.

These tests therefore concentrate on two things: that an invalid bundle never
reaches the gate, and that a typo in an impact tier cannot quietly turn a
critical-tier requirement into no requirement at all.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from meaf.policy import (
    IMPACT_TIERS,
    INDETERMINATE_FAIL_CLOSED,
    INDETERMINATE_PERMIT,
    INDETERMINATE_REQUIRE_REVIEW,
    Policy,
    PolicyError,
    default_policy,
    default_policy_path,
    load_policy,
    load_policy_schema,
    policy_from_document,
    resolve_policy,
    strictest_impact,
    validate_policy_document,
)

from tests.conftest import EXAMPLES

STRICT_POLICY_PATH = EXAMPLES / "policy-strict.json"


@pytest.fixture
def default_document() -> dict:
    """A mutable copy of the shipped bundle, for building negative cases."""
    with default_policy_path().open(encoding="utf-8") as handle:
        return json.load(handle)


# --------------------------------------------------------------------------
# The shipped bundles
# --------------------------------------------------------------------------


def test_the_shipped_default_bundle_loads(policy: Policy):
    assert policy.policy_id == "meaf-default"
    assert policy.policy_version == "2.0.0"
    assert policy.name == "meaf-default:2.0.0"


def test_the_shipped_default_bundle_conforms_to_its_own_schema(policy: Policy):
    # A.4 asks the implementation to publish the schema alongside the bundle; a
    # published bundle that its own published schema rejects is worse than no
    # schema at all.
    assert validate_policy_document(policy.raw) == []


def test_the_strict_example_bundle_loads_and_conforms(strict_policy: Policy):
    assert strict_policy.name == "meaf-example-strict:2.0.0"
    assert validate_policy_document(strict_policy.raw) == []


def test_the_two_shipped_bundles_declare_the_same_policy_schema_version(
    policy: Policy, strict_policy: Policy
):
    assert policy.policy_version == strict_policy.policy_version


def test_resolve_policy_falls_back_to_the_shipped_bundle(policy: Policy):
    assert resolve_policy(None).raw == policy.raw


def test_resolve_policy_loads_the_bundle_it_is_given(strict_policy: Policy):
    assert resolve_policy(STRICT_POLICY_PATH).raw == strict_policy.raw


def test_the_default_bundle_reads_back_the_choices_it_declares(policy: Policy):
    assert policy.permitted_digest_algorithms == frozenset({"sha256", "sha384", "sha512"})
    assert policy.maximum_exception_age_days == 180
    assert policy.blocking_finding_severities == frozenset({"critical", "high"})
    assert policy.require_authorization_decision is True
    assert policy.probabilistic_permitted_for_gate is True
    assert policy.probabilistic_requires_decision_rule is True
    assert policy.maximum_probabilistic_gating_share == 0.5


def test_the_strict_bundle_is_strictly_tighter_where_it_differs(strict_policy: Policy):
    """The example exists to show how much of a gate result is a policy choice.

    It is only convincing if every difference from the default moves in the
    restrictive direction.
    """
    assert strict_policy.permitted_digest_algorithms == frozenset({"sha256"})
    assert strict_policy.maximum_exception_age_days == 90
    assert strict_policy.probabilistic_permitted_for_gate is False
    assert all(
        strict_policy.indeterminate_handling(tier) == INDETERMINATE_FAIL_CLOSED
        for tier in IMPACT_TIERS
    )


# --------------------------------------------------------------------------
# Refusing a bundle the loader cannot fully understand
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "member",
    [
        "policy-id",
        "policy-version",
        "permitted-digest-algorithms",
        "approved-evidence-methods",
        "interruption-requirements",
        "indeterminate-handling",
        "maximum-exception-age-days",
        "block-gate-on-open-finding-severity",
        "require-authorization-decision",
        "probabilistic-evidence",
    ],
)
def test_a_bundle_missing_a_required_member_is_refused(default_document, member):
    document = copy.deepcopy(default_document)
    del document[member]
    with pytest.raises(PolicyError) as raised:
        policy_from_document(document)
    # The message has to name the member, otherwise the operator is left
    # diffing two JSON files by eye.
    assert member in str(raised.value)


@pytest.mark.parametrize("tier", IMPACT_TIERS)
def test_a_bundle_missing_an_impact_tier_is_refused(default_document, tier):
    # Every tier must be declared: a bundle that is silent about one tier would
    # otherwise be resolved by the fallback, which is a guess the organisation
    # never made.
    document = copy.deepcopy(default_document)
    del document["indeterminate-handling"][tier]
    with pytest.raises(PolicyError) as raised:
        policy_from_document(document)
    message = str(raised.value)
    assert "indeterminate-handling" in message
    assert tier in message


@pytest.mark.parametrize(
    ("mutate", "expected_path"),
    [
        (
            lambda doc: doc["permitted-digest-algorithms"].append("md5"),
            "permitted-digest-algorithms/3",
        ),
        (
            lambda doc: doc.__setitem__("indeterminate-handling", {**doc["indeterminate-handling"], "critical": "ignore"}),
            "indeterminate-handling/critical",
        ),
        (
            lambda doc: doc["interruption-requirements"]["critical"]["require-recovery"].append("prevents"),
            "interruption-requirements/critical/require-recovery/2",
        ),
        (
            lambda doc: doc["block-gate-on-open-finding-severity"].append("catastrophic"),
            "block-gate-on-open-finding-severity/2",
        ),
        (
            lambda doc: doc.__setitem__("maximum-exception-age-days", 0),
            "maximum-exception-age-days",
        ),
        (
            lambda doc: doc["probabilistic-evidence"].__setitem__("maximum-gating-share", 1.5),
            "probabilistic-evidence/maximum-gating-share",
        ),
    ],
    ids=[
        "digest-algorithm",
        "indeterminate-handling",
        "interruption-type",
        "finding-severity",
        "exception-age",
        "gating-share",
    ],
)
def test_an_out_of_vocabulary_value_is_refused_and_the_path_is_named(
    default_document, mutate, expected_path
):
    document = copy.deepcopy(default_document)
    mutate(document)
    with pytest.raises(PolicyError) as raised:
        policy_from_document(document)
    assert expected_path in str(raised.value)


def test_an_unknown_member_is_refused(default_document):
    # Closed vocabularies both ways: a bundle carrying a rule this validator
    # does not implement would be enforced less strictly than its author
    # believes, and silence about that is the failure mode A.5 level 6 rules out.
    document = copy.deepcopy(default_document)
    document["require-two-person-approval"] = True
    with pytest.raises(PolicyError) as raised:
        policy_from_document(document)
    assert "require-two-person-approval" in str(raised.value)


@pytest.mark.parametrize("document", [None, [], "policy", 7])
def test_a_bundle_that_is_not_an_object_is_refused(document):
    with pytest.raises(PolicyError):
        policy_from_document(document)


def test_a_root_level_error_is_reported_against_the_root(default_document):
    document = copy.deepcopy(default_document)
    del document["policy-id"]
    errors = validate_policy_document(document)
    assert any(error.startswith("(root): ") for error in errors)


def test_a_conforming_document_produces_no_errors(default_document):
    assert validate_policy_document(default_document) == []


def test_an_unreadable_path_raises_policy_error(tmp_path: Path):
    missing = tmp_path / "no-such-policy.json"
    with pytest.raises(PolicyError) as raised:
        load_policy(missing)
    assert str(missing) in str(raised.value)


def test_a_directory_in_place_of_a_bundle_raises_policy_error(tmp_path: Path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_malformed_json_raises_policy_error(tmp_path: Path):
    path = tmp_path / "policy-broken.json"
    path.write_text('{"policy-id": "x",}', encoding="utf-8")
    with pytest.raises(PolicyError) as raised:
        load_policy(path)
    assert "not valid JSON" in str(raised.value)


def test_a_non_conforming_bundle_on_disk_raises_policy_error(tmp_path: Path, default_document):
    document = copy.deepcopy(default_document)
    del document["probabilistic-evidence"]
    path = tmp_path / "policy-incomplete.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_the_policy_schema_is_itself_loadable_and_closed():
    schema = load_policy_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) <= set(schema["properties"])


# --------------------------------------------------------------------------
# Lookups that miss must fall towards more coverage, not less
# --------------------------------------------------------------------------


@pytest.mark.parametrize("impact", ["", "criticial", "CRITICAL", "severe", "unknown"])
def test_an_unknown_impact_tier_inherits_the_strictest_interruption_requirement(
    policy: Policy, impact
):
    # A typo in a package's impact rating must not silently drop coverage; the
    # requirement it resolves to is the one the strictest tier declares.
    assert policy.interruption_requirement(impact) == policy.interruption_requirement(
        "critical"
    )


@pytest.mark.parametrize("tier", IMPACT_TIERS)
def test_a_known_impact_tier_gets_its_own_interruption_requirement(policy: Policy, tier):
    assert policy.interruption_requirement(tier) == policy.raw["interruption-requirements"][tier]


def test_the_default_interruption_requirements_weaken_monotonically(policy: Policy):
    # Only the critical tier demands that the covering control's contract has
    # actually passed; below that a declared control is accepted.
    assert policy.interruption_requirement("critical")["require-contract-pass"] is True
    assert policy.interruption_requirement("low")["require-before-outcome"] == []


@pytest.mark.parametrize("impact", ["", "criticial", "CRITICAL", "severe", "unknown"])
def test_an_unknown_impact_tier_inherits_the_strictest_indeterminate_handling(
    policy: Policy, impact
):
    assert policy.indeterminate_handling(impact) == policy.indeterminate_handling("critical")
    assert policy.indeterminate_handling(impact) == INDETERMINATE_FAIL_CLOSED


@pytest.mark.parametrize(
    ("tier", "expected"),
    [
        ("critical", INDETERMINATE_FAIL_CLOSED),
        ("high", INDETERMINATE_FAIL_CLOSED),
        ("medium", INDETERMINATE_REQUIRE_REVIEW),
        ("low", INDETERMINATE_REQUIRE_REVIEW),
    ],
)
def test_the_default_bundle_states_an_explicit_choice_for_every_tier(
    policy: Policy, tier, expected
):
    # A.5: indeterminate "must not be silently coerced to pass". The default
    # bundle never answers "permit", so the shipped configuration cannot do so
    # by accident.
    assert policy.indeterminate_handling(tier) == expected
    assert policy.indeterminate_handling(tier) != INDETERMINATE_PERMIT


# --------------------------------------------------------------------------
# strictest_impact
# --------------------------------------------------------------------------


def test_the_impact_tiers_are_declared_from_most_to_least_severe():
    assert IMPACT_TIERS == ("critical", "high", "medium", "low")


@pytest.mark.parametrize(
    ("impacts", "expected"),
    [
        (["critical"], "critical"),
        (["low"], "low"),
        (["low", "critical"], "critical"),
        (["critical", "low"], "critical"),
        (["medium", "high"], "high"),
        (["low", "medium"], "medium"),
        (["low", "low", "medium", "low"], "medium"),
        (["critical", "high", "medium", "low"], "critical"),
    ],
)
def test_strictest_impact_returns_the_most_severe_tier_present(impacts, expected):
    # A contract covering several paths is only as permissive as its worst path.
    assert strictest_impact(impacts) == expected


def test_a_contract_covering_no_path_is_treated_as_low_impact():
    """A contract that covers no path constrains nothing.

    The empty case is the one place where falling towards the strictest tier
    would be wrong: inheriting critical handling for an empty list would make
    every unmapped contract able to fail the gate closed, which punishes the
    package for a coverage gap that level 5 already reports directly.
    """
    assert strictest_impact([]) == "low"


def test_an_unrecognised_impact_string_is_not_treated_as_the_mildest_tier():
    # Same reasoning as the tier lookups: a typo must not read as "low". The
    # unknown value is carried out so that the requirement lookup then resolves
    # it to the critical-tier requirement.
    assert strictest_impact(["severe", "low"]) == "severe"


# --------------------------------------------------------------------------
# Whether a method policy is in force at all
# --------------------------------------------------------------------------


def test_the_default_bundle_declares_no_evidence_method_policy(policy: Policy):
    # A.5 level 4 asks that evidence be "collected by an approved method". The
    # shipped default cannot name approved methods on an adopter's behalf, so it
    # declares an empty list, which the validator reports as a warning rather
    # than treating the check as passed.
    assert policy.approved_evidence_methods == frozenset()
    assert policy.method_policy_in_force is False


def test_the_strict_bundle_puts_a_method_policy_in_force(strict_policy: Policy):
    assert strict_policy.method_policy_in_force is True
    assert "paired-counterfactual-longitudinal-evaluation" in (
        strict_policy.approved_evidence_methods
    )


def test_the_strict_bundle_approves_the_methods_the_examples_actually_use(
    strict_policy: Policy, covert, memory
):
    """Otherwise the worked strict-policy run would fail for a bookkeeping
    reason rather than for the policy choices it is meant to demonstrate."""
    used = {
        item["method"]
        for package in (covert, memory)
        for item in package["evidence"]
        if isinstance(item.get("method"), str)
    }
    assert used <= strict_policy.approved_evidence_methods


def test_default_policy_and_a_direct_load_of_the_shipped_file_agree():
    assert default_policy().raw == load_policy(default_policy_path()).raw
