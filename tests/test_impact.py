"""A change ticket has to be answerable before the change is made.

A.8 step 5 lists the events that "invalidate dependent contracts and can move
the system to degraded or suspended". The value of that clause is entirely in
being able to ask it in advance: if we swap the foundation model tomorrow, what
stops being true today? These tests hold the analysis to answering that question
without touching the package, and to recommending a lifecycle state that follows
from the gate rather than from optimism.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from meaf.impact import HYPOTHETICAL_DIGEST, analyse_change, format_impact, stale_contracts
from tests.conftest import FROZEN_NOW, STALE_NOW

CHANGED = "cmp-foundation-model"


@pytest.fixture
def impact(covert: dict[str, Any]):
    """The reference package, asked what a foundation-model swap would cost."""
    return analyse_change(covert, [CHANGED], now=FROZEN_NOW)


def contract_ids(impact) -> list[str]:
    return [entry["contract"] for entry in impact.affected_contracts]


def test_every_evidence_item_bound_to_the_changed_digest_is_invalidated(covert, impact):
    """A.1 principle 3: "Assurance follows the deployed artifact."

    Invalidation is decided by the digest the evidence names, not by which
    contract happens to require the evidence, so a provenance attestation nobody
    gates on is reported too: it is still an observation about an artifact that
    no longer exists.
    """
    changed_digest = next(
        component["digest"] for component in covert["components"] if component["id"] == CHANGED
    )
    expected = sorted(
        evidence["id"]
        for evidence in covert["evidence"]
        if changed_digest in evidence["subject-digests"]
    )

    assert list(impact.invalidated_evidence) == expected
    assert set(impact.invalidated_evidence) == {
        "ev-containment-drill-2026-07",
        "ev-counterfactual-run-2026-07",
        "ev-model-attestation",
    }


def test_evidence_bound_only_to_unchanged_artifacts_survives(covert, impact):
    assert "ev-corpus-manifest" not in impact.invalidated_evidence
    assert "ev-evaluator-prompt-attestation" not in impact.invalidated_evidence


def test_the_affected_contracts_move_from_pass_to_indeterminate(impact):
    """A.5: evidence collected against a superseded artifact is stale, not failed.

    Nothing has been observed to be wrong, so ``fail`` would overstate what is
    known. What is lost is the ability to say the claim holds, which is exactly
    the definition of ``indeterminate``.
    """
    assert contract_ids(impact) == ["ac-epistemic-integrity-001", "ac-containment-001"]
    for entry in impact.affected_contracts:
        assert entry["state-before"] == "pass"
        assert entry["state-after"] == "indeterminate"


def test_the_reason_given_is_the_artifact_binding_and_not_the_calendar(impact):
    # A.5: "Artifact binding takes precedence over calendar freshness. Evidence
    # collected one minute ago against a superseded prompt, adapter, model
    # endpoint, graph, policy, or retrieval snapshot is stale."
    for entry in impact.affected_contracts:
        assert any("not bound to the deployed subject" in reason for reason in entry["reasons"])
        assert any(HYPOTHETICAL_DIGEST in reason for reason in entry["reasons"])


def test_the_attack_paths_losing_verified_coverage_are_named(impact):
    """A.1 principle 4 makes the path, not the control, the unit of coverage.

    Naming the affected contracts is not enough to answer "is this path still
    interrupted"; that requires resolving each contract through its paired
    control to the paths the control claims to interrupt.
    """
    assert impact.affected_paths == ("path-covert-influence-001",)


def test_the_gate_moves_from_allow_to_block(impact):
    # The path is high-impact and the default bundle fails closed on an
    # indeterminate contract at that tier.
    assert impact.gate_before == "allow"
    assert impact.gate_after == "block"


def test_a_blocking_gate_recommends_suspension(impact):
    # A.8: such events "can move the system to degraded or suspended".
    assert impact.recommended_state == "suspended"


def test_state_changes_short_of_a_block_recommend_degraded(covert):
    """Degraded is the honest answer when claims lapse but policy still permits.

    On a medium-impact path the default bundle requires review rather than
    failing closed, so the system keeps running with a named loss of assurance.
    """
    covert["attack-paths"][0]["impact"] = "medium"

    impact = analyse_change(covert, [CHANGED], now=FROZEN_NOW)

    assert impact.gate_after == "review-required"
    assert contract_ids(impact) == ["ac-epistemic-integrity-001", "ac-containment-001"]
    assert impact.recommended_state == "degraded"


def test_a_change_nothing_is_bound_to_leaves_the_package_authorized(covert):
    """Not every change is material, and saying so is part of the answer.

    A.1 principle 3 invalidates results bound to the changed artifact. A
    component that no contract's subject resolves to, and that no evidence names
    a digest for, carries no dependent claim to invalidate.
    """
    # The containment contract's subject is the system as a whole, which binds
    # to every component digest; re-pointing it at one component is what makes
    # the new component genuinely unbound.
    covert["assurance-contracts"][1]["subject"] = "cmp-rag-corpus"
    covert["components"].append(
        {
            "id": "cmp-audit-log-store",
            "type": "tool",
            "artifact-id": "artifact:audit-log-store-v1",
            "digest": "sha256:" + "1" * 64,
            "provider": "office-of-research-integrity",
            "provenance-evidence": "ev-model-attestation",
            "dependencies": [],
        }
    )

    impact = analyse_change(covert, ["cmp-audit-log-store"], now=FROZEN_NOW)

    assert impact.invalidated_evidence == ()
    assert impact.affected_contracts == ()
    assert impact.affected_paths == ()
    assert impact.gate_before == impact.gate_after == "allow"
    assert impact.recommended_state == "authorized"


def test_analysing_an_unknown_component_changes_nothing(covert):
    """The analysis answers about the package it was given, not about the world.

    A component id the package does not contain binds no evidence, so the honest
    answer is that nothing in this package depends on it.
    """
    impact = analyse_change(covert, ["cmp-not-in-this-package"], now=FROZEN_NOW)

    assert impact.invalidated_evidence == ()
    assert impact.recommended_state == "authorized"


def test_analyse_change_does_not_mutate_the_input_package(covert):
    """The whole point is to run this before the change, in a pre-merge check.

    An analysis that wrote the hypothetical digest into the package would turn a
    question about a proposed change into the change itself.
    """
    before = copy.deepcopy(covert)

    analyse_change(covert, [CHANGED], now=FROZEN_NOW)

    assert covert == before


def test_the_serialized_impact_carries_every_answer(impact):
    payload = impact.to_dict()

    assert payload["changed-components"] == [CHANGED]
    assert payload["invalidated-evidence"] == list(impact.invalidated_evidence)
    assert payload["affected-paths"] == ["path-covert-influence-001"]
    assert payload["gate-before"] == "allow"
    assert payload["gate-after"] == "block"
    assert payload["recommended-lifecycle-state"] == "suspended"


def test_the_formatted_impact_names_the_evidence_contracts_paths_and_gate(impact):
    text = format_impact(impact)

    for evidence_id in impact.invalidated_evidence:
        assert evidence_id in text
    assert "ac-epistemic-integrity-001: pass -> indeterminate" in text
    assert "path-covert-influence-001" in text
    assert "Gate: allow -> block" in text
    assert "suspended" in text


# --------------------------------------------------------------------------
# Cadence-driven monitoring
# --------------------------------------------------------------------------


def test_nothing_is_stale_in_the_reference_package(covert):
    assert stale_contracts(covert, now=FROZEN_NOW) == []


def test_stale_contracts_lists_every_contract_not_in_state_pass(memory):
    """Not-pass, rather than fail: an unverifiable claim needs rerunning too.

    A.5 forbids coercing indeterminate to pass, and a monitor that only chased
    failures would leave the unverifiable ones sitting at their last known good
    state for ever.
    """
    from meaf.contract import evaluate_contracts

    expected = [
        state.contract_id
        for state in evaluate_contracts(memory, now=FROZEN_NOW)
        if state.state != "pass"
    ]

    assert stale_contracts(memory, now=FROZEN_NOW) == expected
    assert expected == ["ac-memory-write-screening-001"]


def test_evidence_that_has_aged_out_makes_every_contract_stale(covert):
    """Freshness is evaluated at an injected instant, not at import time."""
    assert stale_contracts(covert, now=FROZEN_NOW) == []

    assert stale_contracts(covert, now=STALE_NOW) == [
        "ac-epistemic-integrity-001",
        "ac-containment-001",
    ]
