"""The shipped examples have to be true, not merely well-formed.

An example package whose digests were typed by hand teaches the opposite of what
MEAF is for. A.1 principle 3 says "assurance follows the deployed artifact", so
the reference packages are only a demonstration of that principle if every
digest in them is the hash of a file in this repository, every signature
verifies against the shipped keyring, and the whole set can be rebuilt from a
published seed by anyone who checks out the source.

That last property is what ``meaf/examples/tools/regenerate.py --check`` proves,
and running it here is the difference between "the examples look consistent" and
"the examples are reproducible". The module also snapshots the example tree on
import and re-checks it when the session ends: a test that writes into
``meaf/examples`` instead of a temporary copy is a bug in the test suite, and it
would otherwise show up only as an unexplained dirty working tree.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from meaf.attest import compute_digest
from meaf.signing import verify_evidence
from meaf.validator import validate_package
from tests.conftest import EXAMPLES, FROZEN_NOW, REPO_ROOT

REGENERATE = EXAMPLES / "tools" / "regenerate.py"

SHIPPED_PACKAGES = ("covert-influence.json", "memory-poisoning.json")


def _tree_digests(root: Path) -> dict[str, str]:
    """Digest every file under ``root``, keyed by path relative to it."""
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }


#: The state of the example tree before any test in this session has run.
EXAMPLES_AT_IMPORT = _tree_digests(EXAMPLES)


@pytest.fixture(scope="session", autouse=True)
def examples_stay_pristine() -> Any:
    """Fail the session if any test wrote into the shipped example tree."""
    # Guard against the comparison below becoming vacuous if the walk stops
    # finding anything, which would silently retire this check.
    assert len(EXAMPLES_AT_IMPORT) >= len(SHIPPED_PACKAGES)
    yield
    assert _tree_digests(EXAMPLES) == EXAMPLES_AT_IMPORT, (
        "meaf/examples was modified during the test run; tests that write files "
        "must use the example_tree fixture or tmp_path"
    )


@pytest.fixture(scope="module")
def packages() -> dict[str, Any]:
    return {
        name: json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
        for name in SHIPPED_PACKAGES
    }


# --------------------------------------------------------------------------
# Conformance
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", SHIPPED_PACKAGES)
def test_shipped_package_validates_without_error(name, packages, keyring):
    """Both reference packages are conforming at every level of A.5."""
    findings = validate_package(
        packages[name], now=FROZEN_NOW, keyring=keyring, root=EXAMPLES
    )
    errors = [finding for finding in findings if finding.severity == "error"]
    assert errors == []


def test_the_broken_example_fails_at_every_conformance_level(broken, keyring):
    """A.5 lists six progressively stronger checks; broken.json trips all of them.

    Detail belongs in test_validator.py. What this asserts is that the example
    still covers the whole ladder, so a validator regression at any one level
    cannot hide behind the others.
    """
    findings = validate_package(broken, now=FROZEN_NOW, keyring=keyring, root=EXAMPLES)
    levels_with_errors = {
        finding.level for finding in findings if finding.severity == "error"
    }
    assert levels_with_errors == {1, 2, 3, 4, 5, 6}


# --------------------------------------------------------------------------
# Reproducibility from the published demo seed
# --------------------------------------------------------------------------


def test_the_committed_examples_are_what_the_regeneration_script_produces():
    """Digests and signatures are derived, not hand-edited.

    ``--check`` reports drift without writing, so this leaves the working tree
    alone. A failure here means somebody edited an example and did not re-sign
    it, which would make the shipped signatures unverifiable.
    """
    completed = subprocess.run(
        [sys.executable, str(REGENERATE), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "examples are up to date" in completed.stdout


# --------------------------------------------------------------------------
# Evidence attribution and artifact binding
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", SHIPPED_PACKAGES)
def test_every_evidence_signature_verifies_against_the_shipped_keyring(
    name, packages, keyring
):
    # A.5 level 4: evidence must be "signed or otherwise attributable".
    unverified = [
        evidence["id"]
        for evidence in packages[name]["evidence"]
        if not verify_evidence(evidence, keyring)
    ]
    assert unverified == []


@pytest.mark.parametrize("name", SHIPPED_PACKAGES)
def test_every_signature_is_attributed_to_the_collector_that_made_it(name, packages):
    """A keyring holder must not be able to sign as some other collector."""
    for evidence in packages[name]["evidence"]:
        assert evidence["signature"]["key-id"] == evidence["collector"]


@pytest.mark.parametrize("name", SHIPPED_PACKAGES)
def test_every_component_digest_is_the_hash_of_the_artifact_on_disk(name, packages):
    # A.1 principle 3: "Every result binds to immutable identifiers for the
    # model, adapters, prompts, orchestration graph, tool registry, policy
    # bundle, retrieval corpus, and evaluation pack."
    for component in packages[name]["components"]:
        artifact = EXAMPLES / component["artifact-path"]
        assert artifact.is_file(), f"{component['id']} names a file that is not there"
        assert component["digest"] == compute_digest(artifact)


@pytest.mark.parametrize("name", SHIPPED_PACKAGES)
def test_every_evidence_subject_digest_is_a_component_in_the_inventory(name, packages):
    """Evidence about an artifact the package does not declare binds to nothing."""
    declared = {component["digest"] for component in packages[name]["components"]}
    for evidence in packages[name]["evidence"]:
        assert evidence["subject-digests"]
        assert set(evidence["subject-digests"]) <= declared


def test_the_evaluator_prompt_binding_names_the_prompt_component(packages):
    """A.5: probabilistic evidence "must identify the evaluator model and prompt".

    Recording a digest satisfies the schema; recording *this* digest is what
    makes the binding real. If the prompt component changes and the evidence is
    not re-collected, the two stop agreeing and the claim is visibly stale.
    """
    package = packages["covert-influence.json"]
    prompt = next(
        component
        for component in package["components"]
        if component["id"] == "cmp-evaluator-prompt"
    )
    evidence = next(
        item
        for item in package["evidence"]
        if item["id"] == "ev-counterfactual-run-2026-07"
    )
    assert evidence["class"] == "probabilistic-inference"
    assert evidence["model-metadata"]["evaluator-prompt-digest"] == prompt["digest"]


def test_the_runner_digests_the_same_prompt_the_evidence_records(packages):
    """The example runner computes the binding rather than restating it.

    Its output is what a fresh run would record, so it must agree with the
    committed evidence; otherwise re-running the pilot silently unbinds the
    contract from the prompt it was evaluated against.
    """
    package = packages["covert-influence.json"]
    prompt_file = EXAMPLES / "artifacts" / "evaluator-prompt.md"
    completed = subprocess.run(
        [sys.executable, str(EXAMPLES / "runners" / "counterfactual_symmetry.py")],
        cwd=EXAMPLES,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    reported = json.loads(completed.stdout)["model-metadata"]["evaluator-prompt-digest"]
    assert reported == compute_digest(prompt_file)
    evidence = next(
        item
        for item in package["evidence"]
        if item["id"] == "ev-counterfactual-run-2026-07"
    )
    assert reported == evidence["model-metadata"]["evaluator-prompt-digest"]


# --------------------------------------------------------------------------
# The examples say what the docstrings promise
# --------------------------------------------------------------------------


def test_the_clean_example_has_no_open_findings(packages):
    assert packages["covert-influence.json"]["findings"] == []


def test_the_remediation_example_carries_a_finding_and_a_bounded_exception(packages):
    """A.1 principle 5: residual risk is accepted by a named person, with an expiry."""
    package = packages["memory-poisoning.json"]
    assert package["findings"], "the memory-poisoning example must record its failure"
    exception = next(
        decision
        for decision in package["decisions"]
        if decision["decision-type"] == "exception"
    )
    roles = {role["id"] for role in package["system"]["responsible-roles"]}
    assert exception["decision-maker"] in roles
    assert exception["expiry"]
    assert exception["applies-to"]
