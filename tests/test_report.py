"""A report is a projection, so the only thing worth testing is the projection.

Appendix A.1 principle 6 says human-readable views "are projections of the
assurance package rather than separately maintained artifacts that can drift
from it". That property is not visible by reading a rendered report: a hand-
written paragraph and a generated one look identical. What makes it checkable is
that the output is a pure function of the package, the policy and the instant,
and that everything in the package reaches the output. These tests hold the
report to both halves, and to the same refusal of an aggregate score that A.5
imposes on the summary the report is built from.
"""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from meaf.contract import evaluate_contracts
from meaf.lifecycle import LEGAL_TRANSITIONS, current_state
from meaf.model import objects
from meaf.report import (
    STATE_CLASSES,
    assurance_chain_diagram,
    attack_path_diagram,
    build_report,
    lifecycle_diagram,
    mermaid_id,
)
from tests.conftest import FROZEN_NOW, REPO_ROOT, STALE_NOW, write_package

#: A Mermaid node identifier may contain nothing else, whatever the MEAF
#: identifier it was derived from contained.
SAFE_MERMAID_ID = re.compile(r"[A-Za-z0-9_]+")

#: Lines that define a node: an identifier immediately followed by a shape
#: delimiter. Edge, class and classDef lines carry no delimiter and are skipped.
NODE_DEFINITION = re.compile(r"^ {4}(\S+?)[\[({\"]", re.M)

MERMAID_BLOCK = re.compile(r"```mermaid\n(.*?)\n```", re.DOTALL)

#: Words that would name an aggregate verdict rather than an observation. Whole
#: words only: "degraded" is a lifecycle state and "degrade" a failure behaviour,
#: and neither is a grade.
SCORE_LIKE_WORDS = re.compile(
    r"\b(scores?|grades?|grading|ratings?|overall|total-score|posture)\b",
    re.IGNORECASE,
)


def obj(package: Any, collection: str, object_id: str) -> dict[str, Any]:
    for item in package[collection]:
        if item.get("id") == object_id:
            return item
    raise AssertionError(f"{object_id} is not in {collection}")


def section(report: str, heading: str) -> str:
    """The lines of one ``##`` section of the report, heading included."""
    lines = report.splitlines()
    start = lines.index(heading)
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("## ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def defined_node_ids(diagram: str) -> set[str]:
    return set(NODE_DEFINITION.findall(diagram))


def not_applicable_decision(package: Any, contract_id: str) -> dict[str, Any]:
    decision = copy.deepcopy(package["decisions"][0])
    decision["id"] = f"dec-not-applicable-{contract_id}"
    decision["decision-type"] = "not-applicable"
    decision["gate-decision"] = "approve"
    decision["applies-to"] = [contract_id]
    decision["expiry"] = "2026-12-01"
    return decision


@pytest.fixture
def covert_report(covert: dict[str, Any]) -> str:
    return build_report(covert, now=FROZEN_NOW)


@pytest.fixture
def memory_report(memory: dict[str, Any]) -> str:
    return build_report(memory, now=FROZEN_NOW)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_the_same_package_and_instant_produce_the_same_bytes(request, package_fixture):
    package = request.getfixturevalue(package_fixture)
    first = build_report(package, now=FROZEN_NOW)
    second = build_report(copy.deepcopy(package), now=FROZEN_NOW)
    assert first == second


def test_the_report_is_deterministic_across_processes(covert, tmp_path: Path):
    """Byte-determinism has to survive a different hash seed to be worth claiming.

    Building the report twice inside one interpreter proves nothing about set
    iteration, because the seed is fixed for the life of the process. A report
    that is only stable within a run cannot be committed next to the package and
    diffed in review, which is the whole reason the module promises determinism.
    """
    package_path = write_package(tmp_path / "package.json", covert)
    script = (
        "import json, sys\n"
        "from datetime import datetime, timezone\n"
        "from meaf.report import build_report\n"
        "package = json.loads(open(sys.argv[1], encoding='utf-8').read())\n"
        "now = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)\n"
        "sys.stdout.write(build_report(package, now=now))\n"
    )

    outputs = []
    for seed in ("0", "1", "12345"):
        environment = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", script, str(package_path)],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0] == build_report(covert, now=FROZEN_NOW)


def test_the_evaluation_instant_is_part_of_the_report(covert):
    # The instant is an input, so two instants must be distinguishable in the
    # output; a report that hides when it was computed cannot be audited.
    assert "2026-07-28T12:00:00Z" in build_report(covert, now=FROZEN_NOW)
    assert "2026-12-01T00:00:00Z" in build_report(covert, now=STALE_NOW)


def test_the_report_does_not_mutate_the_package(covert):
    before = json.dumps(covert, sort_keys=True)
    build_report(covert, now=FROZEN_NOW)
    assert json.dumps(covert, sort_keys=True) == before


def test_the_policy_bundle_in_force_is_named(covert, strict_policy):
    assert "`meaf-default:2.0.0`" in build_report(covert, now=FROZEN_NOW)
    assert "`meaf-example-strict:2.0.0`" in build_report(
        covert, now=FROZEN_NOW, policy=strict_policy
    )


# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_every_attack_path_appears_in_the_report(request, package_fixture: str):
    package = request.getfixturevalue(package_fixture)
    report = build_report(package, now=FROZEN_NOW)
    paths = objects(package, "attack-paths")
    assert paths

    for attack_path in paths:
        assert f"### `{attack_path['id']}` ({attack_path['impact']} impact)" in report
        # The rendered diagram is the generated one, not a similar hand-written
        # picture: A.1 principle 6 is about drift, and an embedded copy that was
        # produced separately is exactly the drift it warns about.
        assert attack_path_diagram(package, attack_path) in report


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_each_path_diagram_carries_every_node_of_that_path(request, package_fixture: str):
    package = request.getfixturevalue(package_fixture)
    for attack_path in objects(package, "attack-paths"):
        diagram = attack_path_diagram(package, attack_path)
        for node in attack_path["nodes"]:
            assert f'"{node}"' in diagram
        for edge in attack_path["edges"]:
            assert f"|{edge}|" in diagram


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_each_path_diagram_carries_every_control_that_interrupts_it(
    request, package_fixture: str
):
    # A.1 principle 4: "A control is useful only if its location in an attack
    # path and its interruption function are explicit." A diagram that omits an
    # interruption shows a path as more open than the package says it is.
    package = request.getfixturevalue(package_fixture)
    for attack_path in objects(package, "attack-paths"):
        diagram = attack_path_diagram(package, attack_path)
        interrupting = [
            control
            for control in objects(package, "control-implementations")
            if attack_path["id"] in control["attack-paths"]
        ]
        assert interrupting
        for control in interrupting:
            assert mermaid_id("c", control["id"]) in diagram


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_each_control_is_drawn_at_the_node_it_interrupts(request, package_fixture: str):
    package = request.getfixturevalue(package_fixture)
    for attack_path in objects(package, "attack-paths"):
        diagram = attack_path_diagram(package, attack_path)
        for control in objects(package, "control-implementations"):
            if attack_path["id"] not in control["attack-paths"]:
                continue
            index = attack_path["nodes"].index(control["interruption-point"])
            expected_target = mermaid_id("n", f"{attack_path['id']}-{index}")
            edge = (
                f"    {mermaid_id('c', control['id'])} -.->|interrupts| {expected_target}"
            )
            assert edge in diagram.splitlines()


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_each_control_states_its_type_mode_and_failure_behaviour(
    request, package_fixture: str
):
    """The three fields an incident responder needs at a glance.

    A.3's typed interruptions exist so that "a logging control is not counted as
    prevention". Type alone is not enough: a blocking control in monitoring mode
    blocks nothing, and a fail-open one stops blocking exactly when it matters.
    Drawing the three together is what keeps the picture honest.
    """
    package = request.getfixturevalue(package_fixture)
    for attack_path in objects(package, "attack-paths"):
        diagram = attack_path_diagram(package, attack_path)
        for control in objects(package, "control-implementations"):
            if attack_path["id"] not in control["attack-paths"]:
                continue
            definition = next(
                line
                for line in diagram.splitlines()
                if line.strip().startswith(mermaid_id("c", control["id"]) + "{{")
            )
            assert control["interruption-type"] in definition
            assert control["enforcement-mode"] in definition
            assert control["failure-behavior"] in definition


def test_the_last_node_of_a_path_is_drawn_as_the_harmful_outcome(covert):
    attack_path = obj(covert, "attack-paths", "path-covert-influence-001")
    diagram = attack_path_diagram(covert, attack_path)
    last = mermaid_id("n", f"{attack_path['id']}-{len(attack_path['nodes']) - 1}")
    assert f"    class {last} outcomeNode;" in diagram.splitlines()


# ---------------------------------------------------------------------------
# The assurance chain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_the_assurance_chain_has_a_node_for_every_link(request, package_fixture: str):
    """Threat to path to control to contract to test to evidence, with no gaps.

    Evidence that no contract requires has no position in the chain: it supports
    no claim, and drawing it would suggest that it does. Everything that does
    have a position must be drawn, because a missing link is precisely what the
    diagram is meant to expose.
    """
    package = request.getfixturevalue(package_fixture)
    states = evaluate_contracts(package, now=FROZEN_NOW)
    diagram = assurance_chain_diagram(package, states)
    defined = defined_node_ids(diagram)

    expected: set[str] = set()
    expected |= {mermaid_id("t", threat["id"]) for threat in objects(package, "threats")}
    expected |= {mermaid_id("p", path["id"]) for path in objects(package, "attack-paths")}
    expected |= {
        mermaid_id("c", control["id"])
        for control in objects(package, "control-implementations")
    }
    for contract in objects(package, "assurance-contracts"):
        expected.add(mermaid_id("a", contract["id"]))
        expected.add(mermaid_id("x", contract["test"]))
        expected |= {
            mermaid_id("e", evidence_id) for evidence_id in contract["required-evidence"]
        }

    assert expected <= defined


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_the_assurance_chain_links_each_stage_to_the_next(request, package_fixture: str):
    package = request.getfixturevalue(package_fixture)
    states = evaluate_contracts(package, now=FROZEN_NOW)
    edges = assurance_chain_diagram(package, states).splitlines()

    for threat in objects(package, "threats"):
        assert (
            f"    {mermaid_id('t', threat['id'])} --> {mermaid_id('p', threat['path'])}"
            in edges
        )
    for control in objects(package, "control-implementations"):
        for path_id in control["attack-paths"]:
            assert (
                f"    {mermaid_id('p', path_id)} --> {mermaid_id('c', control['id'])}"
                in edges
            )
    for contract in objects(package, "assurance-contracts"):
        contract_node = mermaid_id("a", contract["id"])
        assert f"    {mermaid_id('c', contract['control'])} --> {contract_node}" in edges
        test_node = mermaid_id("x", contract["test"])
        assert f"    {contract_node} --> {test_node}" in edges
        for evidence_id in contract["required-evidence"]:
            assert f"    {test_node} --> {mermaid_id('e', evidence_id)}" in edges


@pytest.mark.parametrize(
    ("state", "mutate"),
    [
        ("pass", lambda package: None),
        (
            "fail",
            lambda package: obj(package, "evidence", "ev-counterfactual-run-2026-07").update(
                {"result": "fail"}
            ),
        ),
        (
            "indeterminate",
            lambda package: obj(
                package, "assurance-contracts", "ac-epistemic-integrity-001"
            ).update({"required-evidence": ["ev-never-collected"]}),
        ),
        (
            "not-applicable",
            lambda package: package["decisions"].append(
                not_applicable_decision(package, "ac-epistemic-integrity-001")
            ),
        ),
    ],
)
def test_each_contract_is_coloured_by_the_state_it_evaluated_to(covert, state, mutate):
    # A.5 gives the contract four states and forbids collapsing them, so the
    # diagram needs four distinguishable renderings. Indeterminate in particular
    # must not look like pass.
    mutate(covert)
    states = evaluate_contracts(covert, now=FROZEN_NOW)
    evaluated = next(s for s in states if s.contract_id == "ac-epistemic-integrity-001")
    assert evaluated.state == state

    diagram = assurance_chain_diagram(covert, states)
    node = mermaid_id("a", "ac-epistemic-integrity-001")
    assert f"    class {node} {STATE_CLASSES[state]};" in diagram.splitlines()
    assert f"state: {state}" in diagram


def test_the_four_state_classes_are_visually_distinct(covert):
    # Four class names is not enough; four identical definitions would render
    # the same picture for a passing and a failing package.
    assert len(set(STATE_CLASSES.values())) == 4
    diagram = assurance_chain_diagram(covert, evaluate_contracts(covert, now=FROZEN_NOW))
    styles = {}
    for line in diagram.splitlines():
        stripped = line.strip()
        if stripped.startswith("classDef"):
            _, name, style = stripped.split(" ", 2)
            styles[name] = style
    state_styles = [styles[class_name] for class_name in STATE_CLASSES.values()]
    assert len(set(state_styles)) == 4


def test_an_unevaluated_contract_is_not_drawn_as_passing(covert):
    """A contract with no state is labelled unevaluated and left uncoloured.

    The alternative, defaulting to the pass styling, would make an incomplete
    evaluation indistinguishable from a clean one.
    """
    diagram = assurance_chain_diagram(covert, [])
    assert "state: unevaluated" in diagram
    assert "class a_ac_epistemic_integrity_001" not in diagram


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_the_lifecycle_diagram_draws_every_legal_transition(covert):
    diagram = lifecycle_diagram(covert)
    lines = diagram.splitlines()
    for source, targets in LEGAL_TRANSITIONS.items():
        for target in targets:
            assert f"    {source} --> {target}" in lines


def test_the_lifecycle_diagram_draws_no_transition_the_state_machine_refuses(covert):
    # A.8: "State transitions are policy decisions backed by package evidence,
    # not labels chosen by the agent." A drawn arrow that the guard table would
    # refuse is a documented route to a state the machine will not grant.
    lines = lifecycle_diagram(covert).splitlines()
    drawn = {
        tuple(line.strip().split(" --> "))
        for line in lines
        if " --> " in line and "[*]" not in line
    }
    legal = {
        (source, target)
        for source, targets in LEGAL_TRANSITIONS.items()
        for target in targets
    }
    assert drawn == legal


def test_the_lifecycle_diagram_marks_entry_and_terminal_states(covert):
    lines = lifecycle_diagram(covert).splitlines()
    assert "    [*] --> draft" in lines
    # A.8: "Retirement is terminal."
    assert "    retired --> [*]" in lines
    assert LEGAL_TRANSITIONS["retired"] == frozenset()


@pytest.mark.parametrize(
    "state", ["draft", "validated", "assessed", "authorized", "degraded", "suspended"]
)
def test_the_lifecycle_diagram_marks_the_state_the_package_declares(covert, state: str):
    covert["lifecycle"] = {"state": state, "history": []}
    diagram = lifecycle_diagram(covert)
    assert current_state(covert) == state
    assert f"    note right of {state}" in diagram.splitlines()
    assert "current state of this package" in diagram
    assert diagram.count("note right of") == 1


def test_a_package_without_a_lifecycle_block_is_marked_as_draft(covert):
    # An unstated lifecycle is authoring, not authorization.
    assert "lifecycle" not in covert
    assert "    note right of draft" in lifecycle_diagram(covert).splitlines()


def test_the_report_states_the_lifecycle_state_and_embeds_the_diagram(covert):
    covert["lifecycle"] = {"state": "authorized", "history": []}
    report = build_report(covert, now=FROZEN_NOW)
    assert "- Lifecycle state: `authorized`" in report
    assert lifecycle_diagram(covert) in report


# ---------------------------------------------------------------------------
# The refusal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("package_fixture", "now"),
    [
        ("covert", FROZEN_NOW),
        ("covert", STALE_NOW),
        ("memory", FROZEN_NOW),
        ("memory", STALE_NOW),
    ],
)
def test_the_report_reports_no_aggregate_score(request, package_fixture: str, now):
    """A.5's refusal survives the projection into a document.

        MEAF intentionally does not define a universal aggregate security score.
        A single number conceals whether weak assurance comes from missing
        threats, uncovered paths, stale evidence, failed tests, or accepted
        residual risk.

    The report is where the pressure lands hardest: it is the artifact somebody
    puts in front of a committee, and a committee wants one number. This test is
    here so that adding it has to be a deliberate act. The only line permitted
    to mention a score is the one that explains why there is not one.
    """
    report = build_report(request.getfixturevalue(package_fixture), now=now)

    offending = [
        line
        for line in report.splitlines()
        if SCORE_LIKE_WORDS.search(line)
        and "no aggregate score is reported" not in line.lower()
    ]
    assert offending == []


def test_the_report_says_why_there_is_no_aggregate_score(covert_report):
    assert "No aggregate score is reported" in covert_report
    assert "a single number would conceal which dimension is weak" in covert_report


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_the_report_carries_all_eight_summary_dimensions(request, package_fixture: str):
    report = build_report(request.getfixturevalue(package_fixture), now=FROZEN_NOW)
    conformance = section(report, "## Conformance summary")
    for heading in (
        "Threat-model completeness",
        "Path-interruption coverage",
        "Control-test status",
        "Evidence freshness",
        "Open findings by severity",
        "Recovery readiness",
        "Probabilistic-evidence dependence",
        "Exception age",
    ):
        assert f"| {heading} |" in conformance


# ---------------------------------------------------------------------------
# Unresolved coverage
# ---------------------------------------------------------------------------


def test_a_clean_package_reports_nothing_unresolved(covert_report):
    unresolved = section(covert_report, "## Unresolved coverage")
    assert "Nothing unresolved at this evaluation instant." in unresolved
    # The clean package's own claim: the gate allows and no contract is failing.
    assert "- Gate decision: **allow**" in covert_report


def test_a_failing_contract_is_listed_as_unresolved(memory_report):
    unresolved = section(memory_report, "## Unresolved coverage")
    assert "`ac-memory-write-screening-001` is fail" in unresolved
    assert "Nothing unresolved" not in unresolved


def test_an_uncovered_threat_is_listed_as_unresolved(covert):
    # A.8 step 2: "Generate the human-readable threat model and unresolved-
    # coverage report from the package." A threat with no contract is the
    # canonical unresolved item.
    orphan = copy.deepcopy(obj(covert, "threats", "thr-covert-influence-001"))
    orphan["id"] = "thr-unverified-002"
    covert["threats"].append(orphan)

    unresolved = section(build_report(covert, now=FROZEN_NOW), "## Unresolved coverage")
    assert "`thr-unverified-002` has no assurance contract" in unresolved


def test_evidence_that_is_not_current_is_listed_as_unresolved(covert):
    obj(covert, "evidence", "ev-counterfactual-run-2026-07")["invalidated-at"] = (
        "2026-07-27T00:00:00Z"
    )
    unresolved = section(build_report(covert, now=FROZEN_NOW), "## Unresolved coverage")
    assert "`ev-counterfactual-run-2026-07` is not current" in unresolved


def test_a_path_with_nothing_interrupting_before_the_harmful_outcome_is_listed_as_unresolved(
    covert,
):
    """A.3: high-impact paths need a control "before the harmful outcome".

    The sibling case -- no containment or recovery mechanism -- is covered
    below, and the two are separate requirements of the same sentence. Removing
    the detect control leaves the containment control in place, so the path
    still satisfies recovery while the harmful outcome itself is reached
    uninterrupted. A report that showed nothing unresolved here would describe
    that path as more closed than the package says it is.
    """
    covert["control-implementations"] = [
        control
        for control in covert["control-implementations"]
        if control["id"] != "ctl-counterfactual-symmetry-monitor"
    ]
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-counterfactual-symmetry-monitor"
    ]
    unresolved = section(build_report(covert, now=FROZEN_NOW), "## Unresolved coverage")
    assert (
        "`path-covert-influence-001` (high) has no control interrupting "
        "before the harmful outcome" in unresolved
    )
    assert "Nothing unresolved" not in unresolved


def test_an_uninterrupted_path_is_listed_as_unresolved(covert):
    covert["control-implementations"] = [
        control
        for control in covert["control-implementations"]
        if control["id"] != "ctl-high-impact-recommendation-hold"
    ]
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-high-impact-recommendation-hold"
    ]
    unresolved = section(build_report(covert, now=FROZEN_NOW), "## Unresolved coverage")
    assert (
        "`path-covert-influence-001` (high) has no containment or recovery control"
        in unresolved
    )


def test_an_expired_exception_is_listed_as_unresolved(memory):
    unresolved = section(build_report(memory, now=STALE_NOW), "## Unresolved coverage")
    assert "`dec-exception-memory-write-2026-06` has expired" in unresolved


def test_a_control_no_contract_verifies_is_listed_as_unresolved(covert):
    """A.3: "Every control implementation is paired with an assurance contract."

    An unpaired control is the failure mode the split between the two objects
    exists to make visible: a claim that nobody undertook to check.
    """
    covert["assurance-contracts"] = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["control"] != "ctl-high-impact-recommendation-hold"
    ]
    unresolved = section(build_report(covert, now=FROZEN_NOW), "## Unresolved coverage")
    assert (
        "`ctl-high-impact-recommendation-hold` is not paired with any assurance contract"
        in unresolved
    )


# ---------------------------------------------------------------------------
# Mermaid identifier safety
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_fixture", ["covert", "memory"])
def test_no_generated_node_identifier_leaves_the_safe_alphabet(
    request, package_fixture: str
):
    """Every node id is [A-Za-z0-9_], whatever the MEAF identifier contained.

    MEAF identifiers are hyphenated and may carry colons; Mermaid reads several
    of those characters as syntax. An unescaped one does not raise here, it
    produces a diagram that silently fails to render in the viewer, which is the
    worst outcome for a document whose purpose is to be looked at.
    """
    package = request.getfixturevalue(package_fixture)
    report = build_report(package, now=FROZEN_NOW)
    diagrams = MERMAID_BLOCK.findall(report)
    assert diagrams

    identifiers = {
        node_id for diagram in diagrams for node_id in defined_node_ids(diagram)
    }
    assert identifiers
    unsafe = sorted(
        node_id for node_id in identifiers if not SAFE_MERMAID_ID.fullmatch(node_id)
    )
    assert unsafe == []


@pytest.mark.parametrize(
    "identifier",
    [
        "ac-epistemic-integrity-001",
        "L5:locally-benign-evaluation",
        'ctl "quoted" id',
        "ctl[bracketed]",
        "ctl{braced}",
        "ctl<br/>injected",
        "ctl\nnewline",
        "ctl-énfase",
    ],
)
def test_mermaid_id_sanitises_anything_a_package_can_contain(identifier: str):
    generated = mermaid_id("c", identifier)
    assert SAFE_MERMAID_ID.fullmatch(generated)
    assert generated.startswith("c_")


def test_mermaid_ids_of_different_prefixes_do_not_collide():
    # A control and the contract that verifies it are different nodes even when
    # their identifiers sanitise to the same string.
    assert mermaid_id("c", "x-1") != mermaid_id("a", "x-1")


def test_labels_containing_a_double_quote_do_not_break_the_diagram(covert):
    """Mermaid has no escape for a double quote inside a quoted label.

    The package cannot be trusted to avoid one, so the renderer replaces it. An
    unbalanced quote would swallow the rest of the diagram.
    """
    path = obj(covert, "attack-paths", "path-covert-influence-001")
    path["nodes"][0] = 'L1:say "hello"'
    diagram = attack_path_diagram(covert, path)
    assert "L1:say 'hello'" in diagram
    assert diagram.count('"') % 2 == 0
