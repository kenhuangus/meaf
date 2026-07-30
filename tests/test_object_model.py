"""The object model must match manuscript appendix A.2 and A.3 exactly.

These tests exist because the object model is the part of MEAF that other
implementations have to agree with. If the schema drifts from the manuscript,
two conforming tools stop meaning the same thing by "control implementation",
and every downstream comparison becomes noise. The expectations below are
transcribed from the manuscript, not from the schema, so a schema edit that
diverges fails here rather than quietly redefining the framework.
"""

from __future__ import annotations

import pytest

from meaf.validator import load_schema

#: A.2: "A MEAF package contains nine linked object types."
NINE_OBJECT_TYPES = {
    "system": "System boundary",
    "components": "Component and AI bill of materials",
    "threats": "Threat",
    "attack-paths": "Attack path",
    "control-implementations": "Control implementation",
    "tests": "Test",
    "evidence": "Evidence",
    "findings": "Finding and remediation",
    "decisions": "Decision and exception",
}

#: A.3 introduces the assurance contract as a separate object paired with each
#: control implementation, so a conforming package carries ten collections in
#: total plus the package-level members.
PACKAGE_MEMBERS = {
    "meaf-version",
    "package-id",
    "policy-bundle",
    "lifecycle",
    "assurance-contracts",
    *NINE_OBJECT_TYPES,
}

REQUIRED_TOP_LEVEL = {
    "meaf-version",
    "package-id",
    "assurance-contracts",
    *NINE_OBJECT_TYPES,
}


@pytest.fixture(scope="module")
def schema() -> dict:
    return load_schema()


def required_of(schema: dict, definition: str) -> set[str]:
    return set(schema["$defs"][definition]["required"])


def properties_of(schema: dict, definition: str) -> set[str]:
    return set(schema["$defs"][definition]["properties"])


def test_package_carries_the_nine_object_types_plus_assurance_contracts(schema):
    assert set(schema["properties"]) == PACKAGE_MEMBERS
    assert set(schema["required"]) == REQUIRED_TOP_LEVEL


def test_no_unknown_members_are_accepted(schema):
    assert schema["additionalProperties"] is False


def test_system_boundary_required_content(schema):
    # A.2: "Owner, deployment, environment, data classes, users, trust
    # boundaries, critical outcomes". A.4 adds responsible roles, which A.5
    # level 3 then requires to exist.
    assert required_of(schema, "system") == {
        "id",
        "owner",
        "deployment",
        "environment",
        "data-classes",
        "users",
        "trust-boundaries",
        "critical-outcomes",
        "responsible-roles",
    }


def test_component_records_provider_hash_provenance_and_dependencies(schema):
    # A.2: "Models, model providers, weight or endpoint identifiers, adapters,
    # prompts, agent graphs, tools, dependencies, retrieval collections,
    # datasets, policies, hashes, and provenance".
    required = required_of(schema, "component")
    assert {"provider", "digest", "provenance-evidence", "artifact-id"} <= required
    assert "dependencies" in properties_of(schema, "component")


def test_threat_carries_every_tuple_position(schema):
    # A.2: T = (actor, capability, stage, preconditions, entry, path, objective,
    # target, outcome, temporal_profile)
    assert required_of(schema, "threat") == {
        "id",
        "actor",
        "capabilities",
        "stage",
        "preconditions",
        "attack-classes",
        "objective",
        "entry-layers",
        "path",
        "target",
        "affected-stakeholders",
        "outcomes",
        "temporal-profile",
    }


def test_temporal_profile_has_the_eight_declared_fields(schema):
    assert required_of(schema, "temporal-profile") == {
        "persistence",
        "activation-latency",
        "exposure-unit",
        "compounding-rule",
        "dormancy",
        "detection-horizon",
        "reversibility",
        "recovery-objective",
    }


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        # A.2: "Session, cross-session, model-version, agent-identity, or
        # ecosystem lifetime"
        (
            "persistence",
            {"session", "cross-session", "model-version", "agent-identity", "ecosystem"},
        ),
        # "Turn, retrieval, memory write, tool call, delegation, task, or
        # wall-clock interval"
        (
            "exposure-unit",
            {
                "turn",
                "retrieval",
                "memory-write",
                "tool-call",
                "delegation",
                "task",
                "wall-clock-interval",
            },
        ),
        # "None, cumulative, thresholded, feedback-driven, or empirically
        # specified function"
        (
            "compounding-rule",
            {"none", "cumulative", "thresholded", "feedback-driven", "specified-function"},
        ),
        # "Automatic, checkpoint-dependent, reconstruction-dependent, model
        # replacement, or unknown"
        (
            "reversibility",
            {
                "automatic",
                "checkpoint-dependent",
                "reconstruction-dependent",
                "model-replacement",
                "unknown",
            },
        ),
    ],
)
def test_temporal_profile_enumerations_match_the_manuscript(schema, field, expected):
    assert set(schema["$defs"]["temporal-profile"]["properties"][field]["enum"]) == expected


def test_recovery_objective_states_both_quantities(schema):
    # A.2: "Maximum acceptable containment time and maximum acceptable loss of
    # legitimate state" is two numbers, not one sentence.
    assert required_of(schema, "recovery-objective") == {
        "max-containment-time",
        "max-acceptable-loss",
    }


def test_detection_horizon_states_a_length_or_a_period(schema):
    # A.2: "Minimum sequence length or observation period required by the detector"
    horizon = schema["$defs"]["detection-horizon"]
    assert set(horizon["properties"]) == {"minimum-observations", "observation-period"}
    assert horizon["minProperties"] == 1


def test_control_implementation_carries_its_six_declared_fields(schema):
    # A.2: "Prevent, detect, contain, or recover function; owner; implementation
    # location; dependencies; enforcement mode; failure behavior"
    required = required_of(schema, "control-implementation")
    assert {
        "function",
        "owner",
        "implementation-location",
        "dependencies",
        "enforcement-mode",
        "failure-behavior",
    } <= required
    # A.3: "Controls are mapped to attack paths through typed interruption points"
    assert {"attack-paths", "interruption-point", "interruption-type"} <= required


def test_control_function_and_interruption_types_are_closed_vocabularies(schema):
    control = schema["$defs"]["control-implementation"]["properties"]
    assert set(control["function"]["enum"]) == {"prevent", "detect", "contain", "recover"}
    assert set(control["interruption-type"]["enum"]) == {
        "blocks",
        "detects",
        "limits",
        "contains",
        "restores",
        "supports-investigation",
    }


def test_assurance_contract_matches_the_ac_tuple(schema):
    # A.3: AC = (claim, subject, threats, function, test, threshold, evidence,
    # cadence, failure_action, owner). "threshold" is decision-rule; "evidence"
    # is required-evidence plus the acceptable classes and freshness the same
    # sentence calls for.
    assert required_of(schema, "assurance-contract") == {
        "id",
        "claim",
        "subject",
        "control",
        "threats",
        "function",
        "test",
        "decision-rule",
        "required-evidence",
        "evidence-classes",
        "evidence-max-age",
        "cadence",
        "failure-action",
        "owner",
    }


def test_contract_names_the_control_it_verifies_and_not_the_interruption(schema):
    """The pairing lives on the contract; the path mapping lives on the control.

    A.3: "Every control implementation is paired with an assurance contract. A
    control implementation describes how a threat is mitigated, while an
    assurance contract defines the evidence and tests required to verify that
    mitigation works." Interruption point and type describe the mitigation, so
    they belong to the control. Duplicating them onto the contract is what made
    the two objects indistinguishable in 1.0.0.
    """
    contract = properties_of(schema, "assurance-contract")
    assert "control" in contract
    assert "interruption-point" not in contract
    assert "interruption-type" not in contract


def test_failure_action_is_the_enumerated_assurance_response(schema):
    # A.3: failure_action "states whether the system alerts, degrades
    # privileges, blocks deployment, suspends autonomous operation, quarantines
    # memory, or invokes recovery".
    assert set(
        schema["$defs"]["assurance-contract"]["properties"]["failure-action"]["enum"]
    ) == {
        "alert",
        "degrade-privileges",
        "block-deployment",
        "suspend-autonomous-operation",
        "quarantine-memory",
        "invoke-recovery",
    }


def test_failure_action_is_distinct_from_control_failure_behavior(schema):
    """What the assurance system does, versus what the control itself does.

    These are different questions with different answers, and conflating them
    loses the one an incident responder needs: is this guardrail fail-open?
    """
    contract_actions = set(
        schema["$defs"]["assurance-contract"]["properties"]["failure-action"]["enum"]
    )
    control_behaviors = set(
        schema["$defs"]["control-implementation"]["properties"]["failure-behavior"]["enum"]
    )
    assert control_behaviors == {"fail-closed", "fail-open", "degrade", "alert-only"}
    assert not contract_actions & control_behaviors


def test_test_object_required_content(schema):
    # A.2: "Procedure, target, inputs, oracle, metrics, thresholds, sampling
    # plan, expected result, and test-pack version"
    assert {
        "procedure",
        "target",
        "inputs",
        "oracle",
        "metrics",
        "thresholds",
        "sampling-plan",
        "expected-result",
        "test-pack-version",
    } <= required_of(schema, "test")


def test_adversarial_tests_must_state_utility_thresholds(schema):
    # A.7: "Every adversarial test pack must report security and benign-task
    # utility together... The package therefore records both the security
    # threshold and the minimum utility threshold used by the gate."
    conditional = schema["$defs"]["test"]["allOf"][0]
    assert conditional["if"]["properties"]["adversarial"]["const"] is True
    assert set(conditional["then"]["required"]) == {"utility-metrics", "utility-thresholds"}


def test_evidence_required_content(schema):
    # A.2: "Subject, source, method, collector, timestamps, validity window,
    # artifact digest, result, signature, and evidence class"
    assert required_of(schema, "evidence") == {
        "id",
        "class",
        "subject-digests",
        "source",
        "method",
        "collector",
        "collected-at",
        "max-age",
        "invalidated-at",
        "result",
    }


def test_probabilistic_evidence_carries_every_mandated_field(schema):
    # A.5: "the evidence must identify the evaluator model and prompt,
    # calibration set, threshold, uncertainty or confidence interval, known
    # failure modes, and independent escalation path".
    assert required_of(schema, "model-metadata") == {
        "evaluator-model",
        "evaluator-prompt-digest",
        "threshold",
        "calibration-set",
        "uncertainty",
        "known-failure-modes",
        "escalation-path",
    }


def test_evidence_classes_stay_distinguishable(schema):
    """A deterministic observation may not smuggle in model metadata.

    A.1 principle 2 keeps the two classes apart. A deterministic observation
    carrying evaluator metadata is a probabilistic inference wearing the wrong
    label, which is exactly the confusion the principle forbids.
    """
    conditions = schema["$defs"]["evidence"]["allOf"]
    probabilistic = conditions[0]
    deterministic = conditions[1]
    assert probabilistic["if"]["properties"]["class"]["const"] == "probabilistic-inference"
    assert probabilistic["then"]["required"] == ["model-metadata"]
    assert deterministic["if"]["properties"]["class"]["const"] == "deterministic-observation"
    assert deterministic["then"]["not"]["required"] == ["model-metadata"]


def test_finding_required_content(schema):
    # A.2: "Failed claim, severity, affected paths, root cause, corrective
    # action, due date, and retest reference"
    assert required_of(schema, "finding") == {
        "id",
        "failed-claim",
        "severity",
        "affected-paths",
        "root-cause",
        "corrective-action",
        "due-date",
        "retest-reference",
    }


def test_finding_severity_is_aggregatable(schema):
    # A.5's summary requires "open findings by severity", which a free string
    # cannot support.
    assert set(schema["$defs"]["finding"]["properties"]["severity"]["enum"]) == {
        "critical",
        "high",
        "medium",
        "low",
    }


def test_decision_required_content(schema):
    # A.2: "Gate decision, policy used, decision-maker, residual risk, scope,
    # justification, expiry, and compensating controls"
    assert {
        "gate-decision",
        "policy-used",
        "decision-maker",
        "residual-risk",
        "scope",
        "justification",
        "expiry",
        "compensating-controls",
    } <= required_of(schema, "decision")


def test_exceptions_must_name_what_they_except(schema):
    conditional = schema["$defs"]["decision"]["allOf"][0]
    assert set(conditional["if"]["properties"]["decision-type"]["enum"]) == {
        "exception",
        "not-applicable",
    }
    assert conditional["then"]["required"] == ["applies-to"]


def test_attack_path_records_impact(schema):
    # A.5 level 5 speaks of "high-impact paths"; without a rating the clause is
    # not evaluable and the requirement has to be applied uniformly or not at all.
    assert "impact" in required_of(schema, "attack-path")
    assert set(schema["$defs"]["attack-path"]["properties"]["impact"]["enum"]) == {
        "critical",
        "high",
        "medium",
        "low",
    }


def test_placeholder_digests_are_no_longer_schema_legal(schema):
    patterns = [entry["pattern"] for entry in schema["$defs"]["digest"]["oneOf"]]
    assert all("REPLACE_WITH" not in pattern for pattern in patterns)
    assert any("sha256" in pattern for pattern in patterns)
