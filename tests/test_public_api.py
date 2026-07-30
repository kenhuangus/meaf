"""The published surface of ``meaf`` is a promise to other implementations.

MEAF only pays off if a second tool can read a package, run the same checks and
reach the same gate result (A.5 level 6, reproducibility). That makes the import
surface, the function signatures and the shapes that cross the wire part of the
specification rather than incidental implementation detail. A rename here is a
breaking change for every integrator, so it should require deleting a test and
saying so, not merely editing a module.

The version lockstep is asserted for the same reason. ``__version__``,
``SCHEMA_VERSION``, the schema's own ``meaf-version`` pattern and the version
each shipped example declares must move together, because a package that says
2.0.0 while the schema accepts only 2.0.0 is the only combination in which a
consumer can trust the declaration at all.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import fields
from typing import Any, Callable

import pytest

import meaf
from meaf.attest import check_attestation
from meaf.contract import ContractState
from meaf.model import Currency, Finding
from meaf.policy import default_policy_path
from meaf.signing import canonical_payload
from meaf.validator import load_schema
from tests.conftest import EXAMPLES

#: Transcribed from the areas the reference implementation claims to cover.
#: Grouped the way the appendix groups them so that a name added to the module
#: without a decision about which promise it belongs to fails here.
EXPECTED_SURFACE = {
    # package loading and the six conformance levels of A.5
    "load_package",
    "validate_package",
    "format_findings",
    "has_errors",
    "Finding",
    # the four contract states of A.5 and the gate they feed
    "CONTRACT_STATES",
    "ContractState",
    "GateResult",
    "evaluate_contract",
    "evaluate_contracts",
    "evaluate_gate",
    # the policy bundle of A.4
    "Policy",
    "default_policy",
    "load_policy",
    # the A.5 currency predicate and the artifact binding it depends on
    "Currency",
    "evidence_currency",
    "evidence_is_fresh",
    "check_attestation",
    "update_attestation",
    "compute_digest",
    "default_root_for_package",
    # the standard test packs of A.7 and the evidence their execution produces
    "run_tests",
    "TestRunResult",
    "TestPack",
    "load_registry",
    # the lifecycle state machine of A.8
    "attempt_transition",
    "current_state",
    "legal_next_states",
    "TransitionResult",
    # A.1 principle 6: human-readable views are projections, plus A.4 interop
    "build_report",
    "conformance_summary",
    "export_oscal",
    # the change-impact analysis of A.8 step 5, and A.9 adoption
    "analyse_change",
    "ChangeImpact",
    "assess_adoption",
    "migrate_package",
    "MigrationReport",
    # evidence attribution
    "sign_evidence",
    "verify_evidence",
    "load_keyring",
    "canonical_payload",
}

CLASS_NAMES = {
    "Finding",
    "ContractState",
    "GateResult",
    "Policy",
    "Currency",
    "TestRunResult",
    "TestPack",
    "TransitionResult",
    "ChangeImpact",
    "MigrationReport",
}


def public(name: str) -> Any:
    return getattr(meaf, name)


# --------------------------------------------------------------------------
# The import surface
# --------------------------------------------------------------------------


def test_the_exported_surface_is_exactly_the_intended_one():
    assert set(meaf.__all__) == EXPECTED_SURFACE


def test_no_name_is_exported_twice():
    assert len(meaf.__all__) == len(set(meaf.__all__))


@pytest.mark.parametrize("name", sorted(EXPECTED_SURFACE))
def test_every_exported_name_resolves(name):
    assert hasattr(meaf, name), f"{name} is in __all__ but not importable from meaf"


@pytest.mark.parametrize("name", sorted(CLASS_NAMES))
def test_exported_types_are_classes(name):
    assert inspect.isclass(public(name))


@pytest.mark.parametrize("name", sorted(EXPECTED_SURFACE - CLASS_NAMES - {"CONTRACT_STATES"}))
def test_exported_functions_are_callable(name):
    obj = public(name)
    assert callable(obj) and not inspect.isclass(obj)


def test_contract_states_is_the_four_state_vocabulary_of_a5():
    # A.5: "An assurance contract has 4 possible states".
    assert set(meaf.CONTRACT_STATES) == {"pass", "fail", "indeterminate", "not-applicable"}


# --------------------------------------------------------------------------
# Version lockstep
# --------------------------------------------------------------------------


def test_distribution_and_schema_versions_agree():
    assert meaf.__version__ == meaf.SCHEMA_VERSION


def test_the_schema_accepts_exactly_the_declared_schema_version():
    """The pattern is what a consumer checks; the constant is what a producer writes."""
    pattern = load_schema()["properties"]["meaf-version"]["pattern"]
    escaped = meaf.SCHEMA_VERSION.replace(".", r"\.")
    assert pattern == f"^{escaped}$"


@pytest.mark.parametrize("example", ["covert-influence.json", "memory-poisoning.json"])
def test_shipped_examples_declare_the_current_schema_version(example):
    package = json.loads((EXAMPLES / example).read_text(encoding="utf-8"))
    assert package["meaf-version"] == meaf.SCHEMA_VERSION


def test_the_default_policy_bundle_moves_with_the_schema():
    """A.4 asks for three versioned artifacts; two of them are versioned here."""
    bundle = json.loads(default_policy_path().read_text(encoding="utf-8"))
    assert bundle["policy-version"] == meaf.POLICY_SCHEMA_VERSION


# --------------------------------------------------------------------------
# Signatures, as an API stability contract
# --------------------------------------------------------------------------


def parameters(function: Callable[..., Any]) -> tuple[list[str], list[str], set[str]]:
    """Positional names, keyword-only names, and which keyword-only ones are required."""
    signature = inspect.signature(function)
    positional = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind
        in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    keyword_only = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind is parameter.KEYWORD_ONLY
    ]
    required = {
        name
        for name in keyword_only
        if signature.parameters[name].default is inspect.Parameter.empty
    }
    return positional, keyword_only, required


LOAD_BEARING_SIGNATURES = [
    (
        meaf.validate_package,
        ["package"],
        ["now", "schema", "keyring", "root", "policy"],
        set(),
    ),
    (meaf.evaluate_contract, ["package", "contract"], ["now", "policy"], {"now"}),
    (meaf.evaluate_gate, ["package"], ["now", "policy", "states"], {"now"}),
    (meaf.conformance_summary, ["package"], ["now", "policy", "states"], {"now"}),
    (meaf.build_report, ["package"], ["now", "policy"], {"now"}),
    (meaf.run_tests, ["package"], ["test_id", "sign_with", "now", "cwd"], set()),
    (
        meaf.attempt_transition,
        ["package", "to_state"],
        ["actor", "reason", "now", "keyring", "root", "policy"],
        set(),
    ),
    (meaf.export_oscal, ["package", "out_dir"], ["now", "policy"], set()),
    (meaf.analyse_change, ["package", "changed_components"], ["now", "policy"], {"now"}),
    (meaf.migrate_package, ["package"], [], set()),
    (meaf.sign_evidence, ["evidence", "private_key"], ["key_id"], set()),
    (meaf.verify_evidence, ["evidence", "keyring"], [], set()),
    (check_attestation, ["package", "root"], [], set()),
]


@pytest.mark.parametrize(
    ("function", "positional", "keyword_only", "required"),
    LOAD_BEARING_SIGNATURES,
    ids=[entry[0].__name__ for entry in LOAD_BEARING_SIGNATURES],
)
def test_load_bearing_signatures_are_stable(function, positional, keyword_only, required):
    observed_positional, observed_keyword_only, observed_required = parameters(function)
    assert observed_positional == positional
    assert observed_keyword_only == keyword_only
    assert observed_required == required


@pytest.mark.parametrize(
    "function",
    [
        meaf.evaluate_contract,
        meaf.evaluate_gate,
        meaf.conformance_summary,
        meaf.build_report,
        meaf.analyse_change,
    ],
    ids=lambda function: function.__name__,
)
def test_evaluation_instant_is_keyword_only_and_mandatory(function):
    """A.5 level 6 asks for reproducibility, which wall-clock defaults defeat.

    Every entry point whose answer depends on time takes the instant explicitly,
    so a caller cannot get a different gate result tomorrow from the same bytes.
    """
    _, keyword_only, required = parameters(function)
    assert "now" in keyword_only
    assert "now" in required


# --------------------------------------------------------------------------
# Frozen wire shapes
# --------------------------------------------------------------------------


def test_attestation_record_keys_are_frozen(covert_path, example_tree):
    # Consumed by validators, dashboards and the CLI's --json output, so the key
    # set is an interface even though no schema constrains it.
    records = check_attestation(
        json.loads(covert_path.read_text(encoding="utf-8")), example_tree
    )
    assert records
    for record in records:
        assert set(record) == {
            "component-id",
            "artifact-path",
            "recorded-digest",
            "computed-digest",
            "status",
        }


def test_finding_field_names_are_frozen():
    assert [field.name for field in fields(Finding)] == [
        "level",
        "severity",
        "object_id",
        "message",
    ]
    assert set(Finding(1, "error", "obj", "message").to_dict()) == {
        "level",
        "severity",
        "object_id",
        "message",
    }


def test_contract_state_serialises_to_the_documented_keys():
    state = ContractState(
        contract_id="ac-x",
        state="pass",
        impact="high",
        reasons=("because",),
        depends_on_probabilistic=False,
        evidence_currency={},
    )
    assert set(state.to_dict()) == {
        "contract-id",
        "state",
        "impact",
        "reasons",
        "depends-on-probabilistic-inference",
        "evidence-currency",
    }


def test_currency_serialises_the_three_conjuncts_of_the_predicate():
    # A.5: current(e, t) = (t - collected_at <= max_age) AND (invalidated_at is
    # null), qualified by "its subject digest matches the deployed subject".
    # Each conjunct is reported separately so a consumer can say which failed.
    currency = Currency(
        current=False,
        binding_matches=False,
        within_max_age=True,
        not_invalidated=True,
        reasons=("bound to a superseded artifact",),
    )
    assert set(currency.to_dict()) == {
        "current",
        "binding-matches",
        "within-max-age",
        "not-invalidated",
        "reasons",
    }


def test_canonical_payload_is_byte_exact():
    """Two producers must sign the same bytes or every signature is unverifiable."""
    evidence = {
        "result": "pass",
        "id": "ev-example",
        "collected-at": "2026-07-15T00:00:00Z",
        "signature": {"algorithm": "ed25519", "key-id": "tool:x:1.0.0", "value": "AA=="},
    }
    assert canonical_payload(evidence) == (
        b'{"collected-at":"2026-07-15T00:00:00Z","id":"ev-example","result":"pass"}'
    )


def test_canonical_payload_escapes_non_ascii_rather_than_emitting_utf8():
    """The escaping choice is part of the contract, not a formatting preference."""
    assert canonical_payload({"note": "résumé"}) == b'{"note":"r\\u00e9sum\\u00e9"}'


def test_canonical_payload_ignores_the_signature_field_wherever_it_appears():
    signed = {"a": 1, "signature": {"value": "x"}}
    unsigned = {"a": 1}
    assert canonical_payload(signed) == canonical_payload(unsigned)
