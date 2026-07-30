"""The validator is the only thing standing between a package and a false pass.

Manuscript A.5 defines six progressively stronger checks, and the whole point of
the appendix is that "machine-readable is not the same as machine-verifiable".
Two properties therefore matter more than any individual rule. First, a check
that fires on a defect must actually fire: a validator that reports nothing on
``broken.json`` is worse than no validator, because it manufactures confidence.
Second, a check that cannot run must not look like a check that passed, and the
validator must survive input bad enough that later levels cannot be evaluated at
all -- level 1 has already reported that, and stopping there would hide every
other problem from the person trying to fix the package.

Everything below injects ``FROZEN_NOW``. A conformance result that changes with
the calendar is exactly the "second conforming evaluator reaches the same
deterministic gate result" property of level 6 being violated by the test suite.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from meaf.model import SEVERITY_ERROR, SEVERITY_WARNING, Finding
from meaf.policy import policy_from_document
from meaf.validator import (
    load_schema,
    validate_l1_syntactic,
    validate_l2_referential,
    validate_l3_semantic,
    validate_l5_policy,
    validate_l6_reproducibility,
    validate_package,
)
from tests.conftest import FROZEN_NOW

SCHEMA = load_schema()

#: Package collection to the schema definition that constrains its members.
COLLECTION_DEFINITIONS = {
    "components": "component",
    "threats": "threat",
    "attack-paths": "attack-path",
    "control-implementations": "control-implementation",
    "assurance-contracts": "assurance-contract",
    "tests": "test",
    "evidence": "evidence",
    "findings": "finding",
    "decisions": "decision",
}

#: One (collection, required field) case per required field of every object
#: type, plus the system boundary, which is a singleton rather than a list.
REQUIRED_FIELD_CASES = [
    (collection, field)
    for collection, definition in COLLECTION_DEFINITIONS.items()
    for field in sorted(SCHEMA["$defs"][definition]["required"])
] + [("system", field) for field in sorted(SCHEMA["$defs"]["system"]["required"])]

TOP_LEVEL_REQUIRED = sorted(SCHEMA["required"])


def errors_at(findings: list[Finding], level: int) -> list[Finding]:
    return [f for f in findings if f.level == level and f.severity == SEVERITY_ERROR]


def warnings_at(findings: list[Finding], level: int) -> list[Finding]:
    return [f for f in findings if f.level == level and f.severity == SEVERITY_WARNING]


def messages_for(findings: list[Finding], object_id: str) -> list[str]:
    return [f.message for f in findings if f.object_id == object_id]


def package_for(collection: str, covert: Any, memory: Any) -> Any:
    """The example package that actually populates ``collection``.

    ``covert-influence.json`` is the clean reference package and carries no
    findings, because nothing in it has failed. Finding-shaped cases therefore
    run against ``memory-poisoning.json``, which is the package under
    remediation.
    """
    return memory if collection == "findings" else covert


# --------------------------------------------------------------------------
# The shipped examples
# --------------------------------------------------------------------------


@pytest.mark.parametrize("example", ["covert", "memory"])
def test_the_shipped_examples_validate_with_no_errors_at_the_frozen_instant(
    example, covert, memory, keyring, examples_dir, policy
):
    """Both reference packages are conformant, including the failing one.

    ``memory-poisoning.json`` has a failing contract, but a failing contract is
    a conformant statement about a system: A.5 level 5 requires that "failed
    tests produce findings", and that package produces one. Conformance is about
    whether the package tells the truth, not about whether the news is good.
    """
    package = covert if example == "covert" else memory
    findings = validate_package(
        package,
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
        policy=policy,
    )
    assert [f for f in findings if f.severity == SEVERITY_ERROR] == []


def test_an_unsupplied_keyring_warns_rather_than_silently_passing(covert, examples_dir, policy):
    """A check that cannot run is a warning and never a silent pass.

    Without a keyring nothing verifies attribution, and an evaluator reading
    "0 errors" would otherwise have no way to tell that level 4's signature
    check never executed.
    """
    findings = validate_package(
        covert, now=FROZEN_NOW, keyring=None, root=examples_dir, policy=policy
    )
    assert any(
        f.severity == SEVERITY_WARNING and "no keyring was supplied" in f.message
        for f in findings
    )


@pytest.mark.parametrize("level", [1, 2, 3, 4, 5, 6])
def test_the_broken_example_produces_an_error_at_every_conformance_level(
    level, broken, keyring, examples_dir, policy
):
    # broken.json exists to prove each level's checks are wired in at all. If a
    # level ever reports nothing here, that level has stopped running.
    findings = validate_package(
        broken, now=FROZEN_NOW, keyring=keyring, root=examples_dir, policy=policy
    )
    assert errors_at(findings, level) != []


# --------------------------------------------------------------------------
# Robustness: structurally invalid input must never raise
# --------------------------------------------------------------------------


def assert_returns_findings(result: Any) -> list[Finding]:
    assert isinstance(result, list)
    assert all(isinstance(item, Finding) for item in result)
    return result


def test_a_package_that_is_not_an_object_is_reported_rather_than_crashing(
    keyring, examples_dir, policy
):
    findings = validate_package(
        [{"meaf-version": "2.0.0"}],
        now=FROZEN_NOW,
        keyring=keyring,
        root=examples_dir,
        policy=policy,
    )
    assert errors_at(assert_returns_findings(findings), 1) != []


def test_an_empty_package_reports_every_missing_top_level_member(
    keyring, examples_dir, policy
):
    findings = validate_package(
        {}, now=FROZEN_NOW, keyring=keyring, root=examples_dir, policy=policy
    )
    assert_returns_findings(findings)
    reported = " ".join(f.message for f in errors_at(findings, 1))
    for member in TOP_LEVEL_REQUIRED:
        assert repr(member) in reported


def test_collections_of_the_wrong_type_do_not_stop_the_later_levels(
    keyring, examples_dir, policy
):
    """Levels 2 to 6 tolerate input level 1 has already rejected.

    A validator that raises on the first malformed collection tells its user
    about one problem and hides the rest, which makes the package take as many
    fix-and-revalidate rounds as it has defects.
    """
    package = {
        "meaf-version": "2.0.0",
        "package-id": "pkg-wrong-types",
        "system": "not-an-object",
        "components": "not-a-list",
        "threats": {"id": "not-a-list-either"},
        "attack-paths": 7,
        "control-implementations": None,
        "assurance-contracts": ["not-an-object"],
        "tests": [None],
        "evidence": [[]],
        "findings": True,
        "decisions": "no",
    }
    findings = validate_package(
        package, now=FROZEN_NOW, keyring=keyring, root=examples_dir, policy=policy
    )
    assert errors_at(assert_returns_findings(findings), 1) != []


@pytest.mark.parametrize(
    ("collection", "field"),
    REQUIRED_FIELD_CASES,
    ids=[f"{collection}.{field}" for collection, field in REQUIRED_FIELD_CASES],
)
def test_deleting_any_required_field_yields_findings_rather_than_an_exception(
    collection, field, covert, memory, keyring, examples_dir, policy
):
    package = copy.deepcopy(package_for(collection, covert, memory))
    if collection == "system":
        del package["system"][field]
    else:
        del package[collection][0][field]

    findings = validate_package(
        package, now=FROZEN_NOW, keyring=keyring, root=examples_dir, policy=policy
    )
    assert_returns_findings(findings)
    # Every field in this parametrisation is schema-required, so level 1 owes
    # the reader an explanation for each one.
    assert any(repr(field) in f.message for f in errors_at(findings, 1))


@pytest.mark.parametrize("member", TOP_LEVEL_REQUIRED)
def test_deleting_any_required_top_level_member_yields_findings(
    member, covert, keyring, examples_dir, policy
):
    package = copy.deepcopy(covert)
    del package[member]
    findings = validate_package(
        package, now=FROZEN_NOW, keyring=keyring, root=examples_dir, policy=policy
    )
    assert_returns_findings(findings)
    assert any(repr(member) in f.message for f in errors_at(findings, 1))


# --------------------------------------------------------------------------
# Level 1: syntactic validity
# --------------------------------------------------------------------------


def test_a_malformed_timestamp_is_a_level_one_error(memory):
    """``format`` is inert in jsonschema unless a checker is supplied.

    This is the check that silently passed before a FormatChecker was wired in,
    which meant a package could declare ``"collected-at": "not-a-date"`` and
    still be called syntactically valid.
    """
    memory["evidence"][0]["collected-at"] = "not-a-date"
    findings = validate_l1_syntactic(memory, SCHEMA)
    assert any(f.object_id == "evidence/0/collected-at" for f in errors_at(findings, 1))


def test_a_malformed_due_date_is_a_level_one_error(memory):
    memory["findings"][0]["due-date"] = "banana"
    findings = validate_l1_syntactic(memory, SCHEMA)
    assert any(f.object_id == "findings/0/due-date" for f in errors_at(findings, 1))


def test_a_malformed_lifecycle_timestamp_is_a_level_one_error(covert):
    covert["lifecycle"] = {
        "state": "validated",
        "history": [
            {
                "from": "draft",
                "to": "validated",
                "at": "yesterday",
                "actor": "role-system-owner",
                "reason": "",
            }
        ],
    }
    findings = validate_l1_syntactic(covert, SCHEMA)
    assert any(
        f.object_id == "lifecycle/history/0/at" for f in errors_at(findings, 1)
    )


def test_a_well_formed_package_produces_no_level_one_errors(covert):
    assert validate_l1_syntactic(covert, SCHEMA) == []


# --------------------------------------------------------------------------
# Level 2: referential integrity
# --------------------------------------------------------------------------


def test_the_clean_package_has_no_referential_errors(covert):
    assert validate_l2_referential(covert) == []


def test_a_duplicated_identifier_is_reported_once_not_once_per_referrer(covert):
    """A.5 level 2: every reference "resolves to exactly one object".

    Both assurance contracts in the clean package reference this threat, so a
    report emitted per referring object would be two findings about one defect.
    The duplicate belongs to the collection that holds it, and is reported there.
    """
    covert["threats"].append(copy.deepcopy(covert["threats"][0]))
    findings = errors_at(validate_l2_referential(covert), 2)
    duplicate_reports = [f for f in findings if "duplicate id" in f.message]
    assert len(duplicate_reports) == 1
    assert duplicate_reports[0].object_id == "thr-covert-influence-001"


#: (collection, field, replacement value). Every reference kind the package
#: model admits, so that no edge of the object graph is left unchecked.
DANGLING_REFERENCE_CASES = [
    ("assurance-contracts", "control", "ctl-not-declared"),
    ("assurance-contracts", "test", "test-not-declared"),
    ("assurance-contracts", "threats", ["thr-not-declared"]),
    ("assurance-contracts", "required-evidence", ["ev-not-declared"]),
    ("assurance-contracts", "subject", "cmp-not-declared"),
    ("tests", "target", "cmp-not-declared"),
    ("components", "provenance-evidence", "ev-not-declared"),
    ("components", "dependencies", ["cmp-not-declared"]),
    ("control-implementations", "attack-paths", ["path-not-declared"]),
    ("control-implementations", "dependencies", ["cmp-not-declared"]),
    ("threats", "path", "path-not-declared"),
    ("findings", "failed-claim", "ac-not-declared"),
    ("findings", "retest-reference", "test-not-declared"),
    ("findings", "affected-paths", ["path-not-declared"]),
    ("decisions", "applies-to", ["ac-not-declared"]),
    ("decisions", "compensating-controls", ["ctl-not-declared"]),
]


@pytest.mark.parametrize(
    ("collection", "field", "replacement"),
    DANGLING_REFERENCE_CASES,
    ids=[f"{collection}.{field}" for collection, field, _ in DANGLING_REFERENCE_CASES],
)
def test_every_kind_of_dangling_reference_is_reported(
    collection, field, replacement, covert, memory
):
    package = copy.deepcopy(package_for(collection, covert, memory))
    package[collection][0][field] = replacement

    findings = errors_at(validate_l2_referential(package), 2)
    assert len(findings) == 1
    message = findings[0].message
    assert field in message
    expected_id = replacement[0] if isinstance(replacement, list) else replacement
    assert expected_id in message


def test_a_contract_subject_may_be_the_system_itself(covert):
    # The containment contract's subject is the system id rather than a
    # component, and that must resolve: a claim about the whole boundary is
    # exactly what "runtime boundary" in the A.3 tuple means.
    subjects = {contract["subject"] for contract in covert["assurance-contracts"]}
    assert covert["system"]["id"] in subjects
    assert validate_l2_referential(covert) == []


def test_a_control_dependency_may_name_another_control(covert):
    # The recommendation hold depends on the symmetry monitor, not on a
    # component. Controls compose, so resolving control dependencies against
    # components alone would report a false dangling reference.
    dependencies = covert["control-implementations"][1]["dependencies"]
    assert "ctl-counterfactual-symmetry-monitor" in dependencies
    assert validate_l2_referential(covert) == []


# --------------------------------------------------------------------------
# Level 3: semantic validity
# --------------------------------------------------------------------------


def test_the_clean_package_has_no_semantic_errors(covert, policy):
    assert validate_l3_semantic(covert, FROZEN_NOW, policy) == []


@pytest.mark.parametrize("edges", [["data-flow"], ["data-flow"] * 4])
def test_an_attack_path_must_carry_one_edge_per_traversal_step(edges, covert, policy):
    # A.2: an attack path is "ordered MAESTRO nodes and typed edges", so with
    # four nodes there are exactly three steps to type.
    covert["attack-paths"][0]["edges"] = edges
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any("expected 3 edges" in f.message for f in findings)


def test_a_path_whose_layer_numbers_descend_is_legal(covert, policy):
    """Layers locate a step; they do not order it.

    The manuscript's own chains traverse downwards and sideways -- section A.7
    lists packs spanning "L2, L1, L3" and "L5, L6" -- so a rule requiring layer
    numbers to ascend would reject the framework's own worked examples.
    """
    path = covert["attack-paths"][0]
    path["nodes"] = [
        "L3:response-planning",
        "L2:memory-retrieval",
        "L5:locally-benign-evaluation",
        "L6:recommendation-gateway",
    ]
    findings = validate_l3_semantic(covert, FROZEN_NOW, policy)
    assert [f for f in findings if f.object_id == path["id"]] == []


def test_a_path_that_repeats_a_node_consecutively_is_an_error(covert, policy):
    path = covert["attack-paths"][0]
    path["nodes"][1] = path["nodes"][0]
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any("consecutively" in f.message for f in findings)


def test_a_malformed_node_label_is_an_error(covert, policy):
    covert["attack-paths"][0]["nodes"][1] = "layer-three"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any("L1-L7" in f.message for f in findings)


@pytest.mark.parametrize(
    ("function", "interruption_type"),
    [
        ("detect", "contains"),
        ("detect", "blocks"),
        ("prevent", "detects"),
        ("contain", "restores"),
        ("recover", "limits"),
    ],
)
def test_a_control_may_not_claim_an_interruption_its_function_cannot_deliver(
    function, interruption_type, covert, policy
):
    """A.3: the typed interruption points "prevent a logging control from being
    counted as prevention or a detector from being credited as containment"."""
    control = covert["control-implementations"][0]
    control["function"] = function
    control["interruption-type"] = interruption_type
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == control["id"] and "interruption-type" in f.message
        for f in findings
    )


def test_an_interruption_point_that_is_not_on_the_path_is_an_error(covert, policy):
    # A.1 principle 4: "a control is useful only if its location in an attack
    # path and its interruption function are explicit". A point off the path
    # locates the control nowhere on it.
    control = covert["control-implementations"][0]
    control["interruption-point"] = "L4:some-other-node"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == control["id"] and "is not a node of attack path" in f.message
        for f in findings
    )


@pytest.mark.parametrize(
    ("collection", "field"),
    [
        ("control-implementations", "owner"),
        ("assurance-contracts", "owner"),
        ("decisions", "decision-maker"),
    ],
)
def test_an_owner_that_is_not_a_declared_role_is_an_error(
    collection, field, covert, policy
):
    # A.5 level 3: "required roles exist". A.1 principle 5 explains why: an
    # owner nobody declared cannot approve residual risk or be held to a fix.
    covert[collection][0][field] = "role-nobody-declared"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == covert[collection][0]["id"] and "role-nobody-declared" in f.message
        for f in findings
    )


def test_a_system_owner_that_is_not_a_declared_role_is_an_error(covert, policy):
    covert["system"]["owner"] = "role-nobody-declared"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any("system owner" in f.message for f in findings)


def test_a_contract_whose_function_differs_from_its_control_is_an_error(covert, policy):
    """The contract verifies the control; a mismatch verifies something else.

    A.3 pairs each control implementation with an assurance contract, so a
    detect control paired with a prevent contract has no agreed subject: neither
    object states what is actually being checked.
    """
    contract = covert["assurance-contracts"][0]
    assert contract["function"] == "detect"
    contract["function"] = "prevent"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == contract["id"] and "does not match the function" in f.message
        for f in findings
    )


def test_a_decision_rule_that_contradicts_its_test_threshold_is_an_error(covert, policy):
    """Two numbers for one metric means the gate result depends on who reads it.

    A.3 makes "test and threshold" one decision procedure. If the contract gates
    at 0.5 and the test reports against 0.1, level 6's "second evaluator reaches
    the same result" property is already lost.
    """
    contract = covert["assurance-contracts"][0]
    contract["decision-rule"]["source-inclusion-asymmetry-max"] = 0.5
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == contract["id"] and "disagrees with threshold" in f.message
        for f in findings
    )


def test_a_decision_rule_may_add_bounds_the_test_does_not_state(covert, policy):
    # Only shared keys can disagree. The containment contract already bounds
    # metrics the counterfactual test never measures, and that is not a defect.
    covert["assurance-contracts"][0]["decision-rule"]["novel-metric-max"] = 0.2
    assert validate_l3_semantic(covert, FROZEN_NOW, policy) == []


def test_an_unregistered_test_pack_is_an_error(covert, policy):
    covert["tests"][0]["test-pack"] = "pack-invented-here"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == "test-counterfactual-symmetry-001"
        and "standard registry" in f.message
        for f in findings
    )


def test_a_missing_test_pack_is_a_warning_not_an_error(covert, policy):
    """Citing no pack is unmeasured coverage, not a false claim.

    A.7's registry makes coverage comparable across packages. A test that cites
    no pack cannot be compared, but it has not asserted anything untrue, so the
    honest report is a warning that the comparison did not happen.
    """
    del covert["tests"][0]["test-pack"]
    findings = validate_l3_semantic(covert, FROZEN_NOW, policy)
    assert errors_at(findings, 3) == []
    assert any(
        f.object_id == "test-counterfactual-symmetry-001" and "A.7" in f.message
        for f in warnings_at(findings, 3)
    )


def test_a_digest_algorithm_the_policy_bundle_forbids_is_an_error(covert, policy):
    # A.5 level 3: "artifact digests use permitted algorithms". Which algorithms
    # those are is an organisational choice carried by the bundle (A.4).
    document = copy.deepcopy(policy.raw)
    document["permitted-digest-algorithms"] = ["sha512"]
    tightened = policy_from_document(document)
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, tightened), 3)
    assert any("digest algorithm 'sha256'" in f.message for f in findings)


def test_evidence_collected_after_the_evaluation_instant_is_an_error(covert, policy):
    covert["evidence"][0]["collected-at"] = "2026-08-01T00:00:00Z"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any("in the future at evaluation time" in f.message for f in findings)


def test_evidence_invalidated_before_it_was_collected_is_an_error(covert, policy):
    """A.5 level 3: "timestamps are coherent".

    This is the only cross-field timestamp rule in the validator, and it is the
    one JSON Schema cannot state: both values are individually well-formed
    ``date-time`` strings, so level 1 sees nothing wrong. An evidence record
    that was retired before it was taken did not come from the collector it
    names, and an auditor reading it needs to be told so rather than shown a
    clean run.
    """
    evidence = covert["evidence"][0]
    assert evidence["collected-at"] == "2026-07-15T00:00:00Z"
    evidence["invalidated-at"] = "2026-01-01T00:00:00Z"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == evidence["id"] and "invalidated-at is before collected-at" in f.message
        for f in findings
    )


def test_evidence_invalidated_after_it_was_collected_is_coherent(covert, policy):
    # The ordinary case: evidence is collected, then something supersedes it.
    # A.5's currency formula treats a non-null invalidated-at as a level 4
    # freshness question, so the coherent ordering must produce nothing at
    # level 3 -- otherwise every superseded record would look malformed.
    covert["evidence"][0]["invalidated-at"] = "2026-07-20T00:00:00Z"
    assert validate_l3_semantic(covert, FROZEN_NOW, policy) == []


#: (fixture name, collection, field). One case per timestamp the coherence
#: check parses. ``findings`` lives on the remediation package, which is the
#: only shipped example that has any.
MALFORMED_TIMESTAMP_CASES = [
    ("covert", "evidence", "collected-at"),
    ("covert", "evidence", "max-age"),
    ("covert", "evidence", "invalidated-at"),
    ("memory", "findings", "due-date"),
    ("covert", "decisions", "expiry"),
]


@pytest.mark.parametrize(
    ("fixture_name", "collection", "field"),
    MALFORMED_TIMESTAMP_CASES,
    ids=[f"{collection}.{field}" for _, collection, field in MALFORMED_TIMESTAMP_CASES],
)
def test_every_timestamp_the_coherence_check_parses_is_reported_when_unparseable(
    fixture_name, collection, field, request, policy
):
    """Level 3 names the field it could not read instead of skipping it.

    Level 1 rejects these too, but level 3 is reached with input level 1 has
    already reported, and a coherence check that quietly swallows a value it
    cannot parse is the "unrunnable check that looks like a passing one" the
    module docstring forbids.
    """
    package = request.getfixturevalue(fixture_name)
    package[collection][0][field] = "not-a-timestamp"
    findings = errors_at(validate_l3_semantic(package, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == package[collection][0]["id"]
        and f"invalid {field}: " in f.message
        for f in findings
    )


def test_a_threat_target_that_names_nothing_in_the_package_is_an_error(covert, policy):
    """A.2 makes ``target`` part of the threat tuple, so it has to denote something.

    Level 2 does not resolve it: a target may legitimately be a data class
    rather than an object with an id, so the check belongs to level 3, and
    without it a threat can name an asset the package never declares while
    every reference in the package still resolves.
    """
    threat = covert["threats"][0]
    threat["target"] = "cmp-nothing-declares-this"
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == threat["id"]
        and "is neither a component id, the system id, nor a declared data class"
        in f.message
        for f in findings
    )


def test_a_threat_may_target_a_declared_data_class(covert, policy):
    # A.2: the tuple's target is an "affected asset or stakeholder", and the
    # system boundary declares its data classes precisely so that a threat can
    # name one. Resolving targets against components alone would reject it.
    data_class = covert["system"]["data-classes"][0]
    covert["threats"][0]["target"] = data_class
    assert validate_l3_semantic(covert, FROZEN_NOW, policy) == []


def test_a_threat_that_outlives_a_session_with_no_contract_is_warned_about(covert, policy):
    """Level 3 adds the reason the level 5 gap matters, and stays a warning.

    A.2's temporal profile exists so that "long-running risk" is explicit. A
    threat whose persistence is ``session`` is bounded by the session; one that
    outlives it is reassessed by nothing at all. Reporting that as an error
    here would double-count the level 5 "required threats have assurance
    contracts" rule, so it is a warning that names the temporal reason.
    """
    orphan = copy.deepcopy(covert["threats"][0])
    orphan["id"] = "thr-persistent-and-unverified"
    assert orphan["temporal-profile"]["persistence"] != "session"
    covert["threats"].append(orphan)

    findings = validate_l3_semantic(covert, FROZEN_NOW, policy)
    assert errors_at(findings, 3) == []
    assert any(
        f.object_id == "thr-persistent-and-unverified"
        and "persists beyond a session" in f.message
        for f in warnings_at(findings, 3)
    )


def test_an_adversarial_test_that_states_no_utility_threshold_is_an_error(covert, policy):
    """A.7: "Every adversarial test pack must report security and benign-task
    utility together."

    An empty object satisfies the schema, so level 3 is the only place this is
    caught. Without it a control that refuses every contested topic scores as
    secure, which A.7 names as the failure the utility threshold exists to stop.
    """
    test = covert["tests"][0]
    assert test["adversarial"] is True
    test["utility-thresholds"] = {}
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == test["id"]
        and "states no minimum benign-task utility" in f.message
        for f in findings
    )


def test_an_adversarial_utility_threshold_with_no_comparison_suffix_is_an_error(
    covert, policy
):
    # A bare metric name states a number but not which side of it passes, so
    # the rule evaluator cannot apply it and the declared utility floor is
    # unenforceable. Reported by name so the author knows which key to fix.
    test = covert["tests"][0]
    test["utility-thresholds"] = {"contested-topic-answer-rate": 0.9}
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == test["id"]
        and "carry no comparison suffix" in f.message
        and "contested-topic-answer-rate" in f.message
        for f in findings
    )


def test_an_exception_whose_owner_is_not_a_declared_role_is_an_error(covert, policy):
    """A.1 principle 5: "A named accountable person or body must approve
    exceptions and residual-risk acceptance."

    Distinct from the general owner check: this one fires on an exception whose
    ``decision-maker`` is not even a role reference, which the role check skips
    because there is no name to resolve. An exception nobody owns is automation
    silently accepting residual risk, which is the thing the principle forbids.
    """
    unowned = copy.deepcopy(covert["decisions"][0])
    unowned.update(
        {
            "id": "dec-exception-unowned",
            "decision-type": "exception",
            "applies-to": ["ac-epistemic-integrity-001"],
            "expiry": "2026-09-30",
            "decision-maker": 7,
        }
    )
    covert["decisions"].append(unowned)
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    assert any(
        f.object_id == "dec-exception-unowned"
        and "exception has no owner that resolves to a declared responsible role"
        in f.message
        for f in findings
    )


def test_an_exception_without_an_expiry_is_an_error(covert, policy):
    covert["decisions"].append(
        {
            "id": "dec-exception-no-expiry",
            "decision-type": "exception",
            "gate-decision": "approve",
            "applies-to": ["ac-epistemic-integrity-001"],
            "policy-used": "meaf-default:2.0.0",
            "decision-maker": "role-assurance-review-board",
            "residual-risk": "unquantified",
            "scope": "ac-epistemic-integrity-001",
            "justification": "An exception nobody time-bounded.",
            "expiry": "whenever",
            "compensating-controls": [],
        }
    )
    findings = errors_at(validate_l3_semantic(covert, FROZEN_NOW, policy), 3)
    # A.5 level 3: "exceptions have owners and expiry dates".
    reported = messages_for(findings, "dec-exception-no-expiry")
    # Two distinct checks, and both are load-bearing. The timestamp check says
    # the value could not be read; the exception check says this particular
    # decision is unbounded in time, which is what A.3's "time-bounded" clause
    # is about. A decision whose expiry is unreadable is not time-bounded, and
    # only the second message says so.
    assert any("invalid expiry: " in message for message in reported)
    assert any("exception has no usable expiry date" in message for message in reported)


# --------------------------------------------------------------------------
# Level 5: policy validity
# --------------------------------------------------------------------------


def test_the_clean_package_has_no_policy_errors(covert, policy):
    assert validate_l5_policy(covert, FROZEN_NOW, policy) == []


def test_a_threat_no_contract_references_is_an_error(covert, policy):
    # A.5 level 5: "required threats have assurance contracts". An enumerated
    # threat with nothing verifying its mitigation is documentation, not
    # assurance.
    orphan = copy.deepcopy(covert["threats"][0])
    orphan["id"] = "thr-nothing-verifies-this"
    covert["threats"].append(orphan)
    findings = errors_at(validate_l5_policy(covert, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "thr-nothing-verifies-this"
        and "no assurance contract" in f.message
        for f in findings
    )


def test_a_control_no_contract_verifies_is_an_error(covert, policy):
    # A.3: "Every control implementation is paired with an assurance contract."
    orphan = copy.deepcopy(covert["control-implementations"][0])
    orphan["id"] = "ctl-unverified"
    covert["control-implementations"].append(orphan)
    findings = errors_at(validate_l5_policy(covert, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "ctl-unverified" and "not paired with any assurance contract" in f.message
        for f in findings
    )


def test_the_interruption_requirement_is_a_policy_choice_not_a_framework_constant(
    covert, policy, strict_policy
):
    """A.3: "deployment policy should require at least one currently verified
    control before the harmful outcome".

    The clean package interrupts its path with a detect control. The default
    bundle accepts ``blocks`` or ``detects`` on a critical path; the strict
    bundle accepts only ``blocks``. The same package therefore passes one and
    fails the other, which is the point of shipping the rules in a bundle rather
    than in code.
    """
    covert["attack-paths"][0]["impact"] = "critical"
    path_id = covert["attack-paths"][0]["id"]

    def interruption_errors(bundle):
        return [
            f
            for f in errors_at(validate_l5_policy(covert, FROZEN_NOW, bundle), 5)
            if f.object_id == path_id and "before the harmful outcome" in f.message
        ]

    assert interruption_errors(policy) == []
    assert interruption_errors(strict_policy) != []


def test_a_path_with_no_recovery_control_fails_the_recovery_requirement(covert, policy):
    # The default bundle requires a contain or restore mechanism on a high
    # impact path, which is A.3's "one verified containment or recovery
    # mechanism" for each high-impact path.
    covert["control-implementations"] = [covert["control-implementations"][0]]
    covert["assurance-contracts"] = [covert["assurance-contracts"][0]]
    findings = errors_at(validate_l5_policy(covert, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "path-covert-influence-001" and "contains or restores" in f.message
        for f in findings
    )


def test_a_failing_contract_with_no_finding_is_an_error(memory, policy):
    """A.5 level 5: "failed tests produce findings".

    The remediation package records its failure. Deleting the finding leaves a
    contract that is known to fail and a package that never says so, which is
    the state the level exists to forbid.
    """
    memory["findings"] = []
    findings = errors_at(validate_l5_policy(memory, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "ac-memory-write-screening-001"
        and "no finding records the failure" in f.message
        for f in findings
    )


def test_the_remediation_package_records_its_failure_and_so_reports_no_such_error(
    memory, policy
):
    findings = validate_l5_policy(memory, FROZEN_NOW, policy)
    assert errors_at(findings, 5) == []

    # A.3 requires a *currently verified* control on a high-impact path, and
    # this package's blocking control is failing. That gap is real and stays
    # visible as a warning naming the decision that bounds it -- an exception is
    # the sanctioned way not to meet the requirement, not a way to hide it.
    coverage = [f for f in findings if "coverage rests on exception" in f.message]
    assert len(coverage) == 1
    assert coverage[0].severity == "warning"
    assert "dec-exception-memory-write-2026-06" in coverage[0].message


def test_an_expired_decision_is_an_error(covert, policy):
    # A.5 level 5: "expired evidence or exceptions change the gate state".
    covert["decisions"][0]["expiry"] = "2026-01-15"
    findings = errors_at(validate_l5_policy(covert, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "dec-gate-2026-07" and "expired on 2026-01-15" in f.message
        for f in findings
    )


def test_an_exception_longer_than_the_policy_ceiling_is_an_error(
    covert, policy, strict_policy
):
    """A.3: exceptions "must be explicit, scoped, approved, and time-bounded".

    How long a bound may be is the adopting organisation's choice, so the same
    156-day exception is inside the default bundle's 180-day ceiling and outside
    the strict bundle's 90-day one.
    """
    covert["decisions"].append(
        {
            "id": "dec-exception-long",
            "decision-type": "exception",
            "gate-decision": "approve-with-conditions",
            "applies-to": ["ac-epistemic-integrity-001"],
            "policy-used": "meaf-default:2.0.0",
            "decision-maker": "role-assurance-review-board",
            "residual-risk": "medium",
            "scope": "ac-epistemic-integrity-001 only",
            "justification": "Accepted while the harness is rebuilt.",
            "expiry": "2026-12-31",
            "compensating-controls": ["ctl-high-impact-recommendation-hold"],
        }
    )

    def ceiling_errors(bundle):
        return [
            f
            for f in errors_at(validate_l5_policy(covert, FROZEN_NOW, bundle), 5)
            if f.object_id == "dec-exception-long" and "ceiling" in f.message
        ]

    assert ceiling_errors(policy) == []
    assert ceiling_errors(strict_policy) != []


def test_an_indeterminate_contract_fails_closed_on_a_high_impact_path(covert, policy):
    """A.5: indeterminate "must not be silently coerced to pass".

    The default bundle fails closed above medium impact, so a contract whose
    evidence has gone missing is reported as an error rather than dropped.
    """
    covert["assurance-contracts"][0]["required-evidence"] = ["ev-not-collected-yet"]
    findings = errors_at(validate_l5_policy(covert, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "ac-epistemic-integrity-001" and "fails closed" in f.message
        for f in findings
    )


def test_failing_evidence_that_no_finding_accounts_for_is_an_error(covert, policy):
    covert["evidence"][0]["result"] = "fail"
    findings = errors_at(validate_l5_policy(covert, FROZEN_NOW, policy), 5)
    assert any(
        f.object_id == "ev-counterfactual-run-2026-07"
        and "no finding references any contract" in f.message
        for f in findings
    )


# --------------------------------------------------------------------------
# Level 6: reproducibility
# --------------------------------------------------------------------------


def test_the_clean_package_has_no_reproducibility_errors(covert, policy):
    assert validate_l6_reproducibility(covert, policy) == []


def test_an_unversioned_collector_is_an_error(covert, policy):
    # A.9 requires "version pinning" of the assurance tooling itself. Two
    # evaluators running different builds of the same named collector cannot be
    # shown to have reached the same result for the same reason.
    covert["evidence"][0]["collector"] = "epistemic-integrity-harness"
    findings = errors_at(validate_l6_reproducibility(covert, policy), 6)
    assert any(
        f.object_id == "ev-counterfactual-run-2026-07"
        and "lacks an explicit version" in f.message
        for f in findings
    )


def test_an_unpinned_test_pack_version_is_an_error(covert, policy):
    # A.7 packs are versioned, and a bare "1.0.0" does not say version of what.
    covert["tests"][0]["test-pack-version"] = "1.0.0"
    findings = errors_at(validate_l6_reproducibility(covert, policy), 6)
    assert any(
        f.object_id == "test-counterfactual-symmetry-001"
        and "does not pin a named pack" in f.message
        for f in findings
    )


def test_a_shell_invoking_runner_is_a_warning(covert, policy):
    """The package must pin the command, not the shell that composes one.

    Reported as a warning rather than an error: the package may still be
    reproducible in practice, but nothing in it establishes that, and A.9 asks
    for reproducible builds of the assurance system itself.
    """
    covert["tests"][0]["runner"]["command"] = ["/bin/bash", "-c", "run-the-harness"]
    findings = warnings_at(validate_l6_reproducibility(covert, policy), 6)
    assert any("not pinned by the package" in f.message for f in findings)


def test_gating_on_probabilistic_evidence_without_a_metric_bound_is_an_error(
    covert, policy
):
    """A.5: an LLM judgment is "not deterministic telemetry".

    A contract that gates on a classifier score while stating only how many
    cases to sample has declared no decision procedure, so two evaluators
    looking at the same score may disagree about whether it passed.
    """
    covert["assurance-contracts"][0]["decision-rule"] = {"minimum-paired-cases": 500}
    findings = errors_at(validate_l6_reproducibility(covert, policy), 6)
    assert any(
        f.object_id == "ac-epistemic-integrity-001" and "no metric bound" in f.message
        for f in findings
    )


def test_a_sampling_rule_alone_does_not_count_as_a_decision_rule_for_deterministic_evidence(
    covert, policy
):
    # The containment contract gates on a deterministic drill, so the
    # probabilistic-evidence rule does not apply to it at all.
    covert["assurance-contracts"][1]["decision-rule"] = {"minimum-drills": 1}
    assert validate_l6_reproducibility(covert, policy) == []


def test_evaluating_under_a_bundle_the_package_does_not_declare_is_an_error(
    covert, strict_policy
):
    """A.5 level 6 fixes the policy bundle as an input to the gate result.

    "A second conforming evaluator using the same package, external evidence,
    and policy bundle" reaches the same result. A different bundle is a
    different question, and the report must say so rather than implying the
    package was checked against its own rules.
    """
    findings = errors_at(validate_l6_reproducibility(covert, strict_policy), 6)
    assert any(
        "meaf-default:2.0.0" in f.message and "meaf-example-strict:2.0.0" in f.message
        for f in findings
    )


def test_a_package_that_declares_no_policy_bundle_is_warned_about(covert, policy):
    del covert["policy-bundle"]
    findings = warnings_at(validate_l6_reproducibility(covert, policy), 6)
    assert any("declares no policy-bundle" in f.message for f in findings)


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


@pytest.mark.parametrize("example", ["covert", "memory", "broken"])
def test_validation_is_deterministic_for_a_fixed_instant_and_policy(
    example, covert, memory, broken, keyring, examples_dir, policy
):
    """Level 6 is a claim the validator has to satisfy about itself.

    Findings are compared in order: a validator whose output is a set in
    disguise gives two readers two different reports of the same package.
    """
    package = {"covert": covert, "memory": memory, "broken": broken}[example]
    kwargs = dict(now=FROZEN_NOW, keyring=keyring, root=examples_dir, policy=policy)
    assert validate_package(copy.deepcopy(package), **kwargs) == validate_package(
        copy.deepcopy(package), **kwargs
    )
