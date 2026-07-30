"""Attestation is the only place the package meets the filesystem.

That makes it the only place two distinct kinds of bug can appear. A digest that
is not really the hash of the artifact silently breaks A.1 principle 3, because
the identifier the whole package binds to no longer identifies anything. And a
path that escapes the attestation root turns "validate this package" into "read
this file", which matters because packages arrive from suppliers.

Both are properties of the code rather than of the schema, so they are asserted
against the filesystem here rather than inferred from the document.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from meaf.attest import (
    STATUS_DRIFT,
    STATUS_MATCH,
    STATUS_MISSING_FILE,
    STATUS_NO_ARTIFACT_PATH,
    STATUS_OUTSIDE_ROOT,
    ArtifactPathError,
    attestation_exit_code,
    check_attestation,
    compute_digest,
    default_root_for_package,
    digest_algorithm_of,
    has_attestation_drift,
    resolve_artifact_path,
    unbound_evidence,
    update_attestation,
)
from meaf.model import SEVERITY_ERROR, has_errors
from meaf.validator import validate_package
from tests.conftest import FROZEN_NOW

#: The component whose artifact the drift tests disturb, and the evidence that
#: is bound to it in the shipped example.
MODEL_COMPONENT = "cmp-foundation-model"
MODEL_ARTIFACT = "artifacts/model-card.json"
MODEL_EVIDENCE = "ev-model-attestation"


def record_for(records: list[dict], component_id: str) -> dict:
    matches = [record for record in records if record["component-id"] == component_id]
    assert len(matches) == 1, f"expected exactly one record for {component_id}"
    return matches[0]


def component(package: dict, component_id: str) -> dict:
    matches = [item for item in package["components"] if item["id"] == component_id]
    assert len(matches) == 1
    return matches[0]


def evidence(package: dict, evidence_id: str) -> dict:
    matches = [item for item in package["evidence"] if item["id"] == evidence_id]
    assert len(matches) == 1
    return matches[0]


# --------------------------------------------------------------------------
# compute_digest
# --------------------------------------------------------------------------


def test_compute_digest_is_the_plain_hash_of_the_files_bytes(example_tree):
    """``sha256:<hex>`` must be the SHA-256 of the artifact, with no preprocessing.

    An earlier version normalised CRLF to LF before hashing. That made the
    recorded value not the SHA-256 of the file, so nobody could reproduce it with
    a standard tool, and two files differing only in line endings shared one
    digest. Line endings are pinned in ``.gitattributes`` instead, which fixes
    the checkout problem without lying about what the digest is.
    """
    path = example_tree / MODEL_ARTIFACT
    expected = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert compute_digest(path) == expected


def test_files_differing_only_in_line_endings_get_different_digests(tmp_path):
    crlf = tmp_path / "crlf.txt"
    lf = tmp_path / "lf.txt"
    crlf.write_bytes(b"first line\r\nsecond line\r\n")
    lf.write_bytes(b"first line\nsecond line\n")
    assert compute_digest(crlf) != compute_digest(lf)


@pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512"])
def test_compute_digest_honours_the_named_algorithm(tmp_path, algorithm):
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"attested bytes")
    expected = hashlib.new(algorithm, path.read_bytes()).hexdigest()
    assert compute_digest(path, algorithm) == f"{algorithm}:{expected}"


def test_an_unsupported_digest_algorithm_is_refused_rather_than_defaulted(tmp_path):
    # Silently falling back to SHA-256 would record a digest under a label that
    # does not describe it.
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"attested bytes")
    with pytest.raises(ValueError):
        compute_digest(path, "md5")


@pytest.mark.parametrize(
    ("digest", "expected"),
    [
        ("sha256:" + "a" * 64, "sha256"),
        ("sha384:" + "b" * 96, "sha384"),
        ("sha512:" + "c" * 128, "sha512"),
    ],
)
def test_digest_algorithm_of_reads_the_algorithm_the_package_recorded(digest, expected):
    # Verification has to rehash with the algorithm that produced the recorded
    # value; using a different one would report drift on an unchanged file.
    assert digest_algorithm_of(digest) == expected


@pytest.mark.parametrize("digest", ["md5:abc", "not-a-digest", None, 17])
def test_digest_algorithm_of_falls_back_when_the_recorded_digest_is_unusable(digest):
    assert digest_algorithm_of(digest) == "sha256"
    assert digest_algorithm_of(digest, default="sha512") == "sha512"


def test_a_sha512_component_digest_verifies_against_a_sha512_recomputation(
    covert, example_tree
):
    target = component(covert, MODEL_COMPONENT)
    target["digest"] = compute_digest(example_tree / MODEL_ARTIFACT, "sha512")

    record = record_for(check_attestation(covert, example_tree), MODEL_COMPONENT)
    assert record["status"] == STATUS_MATCH
    assert record["computed-digest"].startswith("sha512:")


# --------------------------------------------------------------------------
# resolve_artifact_path
# --------------------------------------------------------------------------


def test_resolve_artifact_path_accepts_a_path_inside_the_root(example_tree):
    assert resolve_artifact_path(example_tree, MODEL_ARTIFACT) == (
        example_tree.resolve() / MODEL_ARTIFACT
    )


def test_resolve_artifact_path_refuses_an_absolute_path(example_tree):
    """A.9: the assurance system is itself a high-value attack surface.

    Validating a supplier's package must not be a way to read arbitrary files on
    the machine doing the validating. A package that could name ``/etc/passwd``
    would turn every validator into a file-read primitive for whoever wrote the
    package.
    """
    with pytest.raises(ArtifactPathError):
        resolve_artifact_path(example_tree, "/etc/passwd")


@pytest.mark.parametrize(
    "artifact_path",
    ["../outside.txt", "artifacts/../../outside.txt", "..\\outside.txt"],
)
def test_resolve_artifact_path_refuses_traversal_out_of_the_root(example_tree, artifact_path):
    # The backslash case matters because the resolver normalises separators, so
    # a Windows-style traversal must not slip past a POSIX-only check.
    with pytest.raises(ArtifactPathError):
        resolve_artifact_path(example_tree, artifact_path)


def test_resolve_artifact_path_allows_traversal_that_stays_inside_the_root(example_tree):
    resolved = resolve_artifact_path(example_tree, "artifacts/../artifacts/model-card.json")
    assert resolved == example_tree.resolve() / MODEL_ARTIFACT


# --------------------------------------------------------------------------
# check_attestation statuses
# --------------------------------------------------------------------------


def test_an_untouched_example_tree_attests_as_matching(covert, example_tree):
    records = check_attestation(covert, example_tree)
    assert [record["component-id"] for record in records] == [
        item["id"] for item in covert["components"]
    ]
    assert {record["status"] for record in records} == {STATUS_MATCH}
    assert has_attestation_drift(covert, example_tree) is False


def test_a_changed_artifact_attests_as_drift(covert, example_tree):
    path = example_tree / MODEL_ARTIFACT
    path.write_bytes(path.read_bytes() + b"\n")

    record = record_for(check_attestation(covert, example_tree), MODEL_COMPONENT)
    assert record["status"] == STATUS_DRIFT
    assert record["recorded-digest"] == component(covert, MODEL_COMPONENT)["digest"]
    assert record["computed-digest"] == compute_digest(path)
    assert record["computed-digest"] != record["recorded-digest"]
    assert has_attestation_drift(covert, example_tree) is True


def test_a_deleted_artifact_attests_as_missing_rather_than_matching(covert, example_tree):
    """Deleting the file must not be a cheaper way to pass than not changing it.

    Declaring an ``artifact-path`` is a claim that the binding is checkable. If a
    missing file were silently skipped, the way to make drift disappear would be
    to remove the evidence of it.
    """
    (example_tree / MODEL_ARTIFACT).unlink()

    record = record_for(check_attestation(covert, example_tree), MODEL_COMPONENT)
    assert record["status"] == STATUS_MISSING_FILE
    assert record["computed-digest"] is None


def test_a_component_without_an_artifact_path_is_reported_as_such(covert, example_tree):
    # Not every component is a file on this machine; a hosted model endpoint has
    # nothing to hash locally. That is a distinct status, not a pass and not a
    # failure.
    del component(covert, MODEL_COMPONENT)["artifact-path"]

    record = record_for(check_attestation(covert, example_tree), MODEL_COMPONENT)
    assert record["status"] == STATUS_NO_ARTIFACT_PATH
    assert record["computed-digest"] is None


def test_an_artifact_path_outside_the_root_is_refused_rather_than_followed(
    covert, example_tree, tmp_path
):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"a file the package must not be able to read")
    component(covert, MODEL_COMPONENT)["artifact-path"] = "../outside.txt"

    record = record_for(check_attestation(covert, example_tree), MODEL_COMPONENT)
    assert record["status"] == STATUS_OUTSIDE_ROOT
    assert record["computed-digest"] is None


# --------------------------------------------------------------------------
# Broken bindings as conformance errors
#
# The statuses above are what ``check_attestation`` reports; they only matter
# operationally if ``validate_package`` turns them into level 4 errors, because
# that is what ``meaf validate`` exits on and what the lifecycle guards read.
# Each test below therefore asserts the clean baseline first, so the error it
# then demands is attributable to the broken binding and to nothing else.
# --------------------------------------------------------------------------


def level_4_errors(findings: list) -> list:
    return [
        finding
        for finding in findings
        if finding.level == 4 and finding.severity == SEVERITY_ERROR
    ]


def test_the_untouched_example_tree_is_free_of_level_4_attestation_errors(
    covert, example_tree, keyring
):
    """The baseline the three tests below measure against.

    Without this, a level 4 error already present for some unrelated reason
    would satisfy those tests and they would stop discriminating.
    """
    findings = validate_package(covert, now=FROZEN_NOW, keyring=keyring, root=example_tree)
    assert level_4_errors(findings) == []
    assert has_errors(findings) is False


def test_a_drifted_artifact_is_a_level_4_error_and_not_only_a_status(
    covert, example_tree, keyring
):
    """A.1 principle 3: "Assurance follows the deployed artifact."

    Drift means the identifier the whole package binds to no longer identifies
    what is on disk. Reporting that only in ``meaf attest`` output would leave
    ``meaf validate`` exiting 0 on a package whose bindings are false.
    """
    path = example_tree / MODEL_ARTIFACT
    path.write_bytes(path.read_bytes() + b"\n")

    findings = validate_package(covert, now=FROZEN_NOW, keyring=keyring, root=example_tree)

    errors = level_4_errors(findings)
    assert [finding.object_id for finding in errors] == [MODEL_COMPONENT]
    assert "artifact digest drift" in errors[0].message
    assert compute_digest(path) in errors[0].message
    assert has_errors(findings) is True


def test_a_deleted_artifact_is_a_level_4_error_and_not_a_silently_skipped_check(
    covert, example_tree, keyring
):
    """Deleting the file must not be a cheaper way to validate clean than drift.

    A.5 level 4 asks whether evidence is "bound to the assessed artifact". If a
    missing file were merely a status nothing acted on, the cheapest way to
    clear a drift error would be ``rm`` on the artifact, and the package would
    then pass ``draft -> validated`` and ``assessed -> authorized``.
    """
    (example_tree / MODEL_ARTIFACT).unlink()

    findings = validate_package(covert, now=FROZEN_NOW, keyring=keyring, root=example_tree)

    errors = level_4_errors(findings)
    assert [finding.object_id for finding in errors] == [MODEL_COMPONENT]
    assert "is missing" in errors[0].message
    assert MODEL_ARTIFACT in errors[0].message
    assert has_errors(findings) is True


def test_an_artifact_path_outside_the_root_is_a_level_4_error_and_not_a_pass(
    covert, example_tree, keyring, tmp_path
):
    """A.9: "The assurance system is itself a high-value attack surface."

    ``resolve_artifact_path`` refuses to read the file, which is the security
    half. The conformance half is that the refusal has to surface: a supplier
    package declaring ``../outside.txt`` must not validate clean merely because
    the traversal was not followed, or the escape attempt would reach nobody.
    """
    (tmp_path / "outside.txt").write_bytes(b"a file the package must not be able to read")
    component(covert, MODEL_COMPONENT)["artifact-path"] = "../outside.txt"

    findings = validate_package(covert, now=FROZEN_NOW, keyring=keyring, root=example_tree)

    errors = level_4_errors(findings)
    assert [finding.object_id for finding in errors] == [MODEL_COMPONENT]
    assert "outside the attestation root" in errors[0].message
    assert has_errors(findings) is True


# --------------------------------------------------------------------------
# update_attestation
# --------------------------------------------------------------------------


def test_update_attestation_rebinds_the_component_digest_to_what_is_on_disk(
    covert, example_tree
):
    path = example_tree / MODEL_ARTIFACT
    path.write_bytes(path.read_bytes() + b"\n")
    new_digest = compute_digest(path)

    updated, changes = update_attestation(covert, example_tree)

    assert component(updated, MODEL_COMPONENT)["digest"] == new_digest
    assert len(changes) == 1
    assert has_attestation_drift(updated, example_tree) is False


def test_update_attestation_leaves_the_original_package_untouched(covert, example_tree):
    path = example_tree / MODEL_ARTIFACT
    path.write_bytes(path.read_bytes() + b"\n")
    before = copy.deepcopy(covert)

    update_attestation(covert, example_tree)

    assert covert == before


def test_update_attestation_does_not_rewrite_evidence_subject_digests(covert, example_tree):
    """Rebinding the evidence would forge the relationship MEAF exists to protect.

    A.5: "Artifact binding takes precedence over calendar freshness. Evidence
    collected one minute ago against a superseded prompt, adapter, model
    endpoint, graph, policy, or retrieval snapshot is stale." Rewriting
    ``subject-digests`` to the new artifact would make evidence collected against
    the old one silently claim to be about the new one, which inverts that
    sentence and makes re-attestation a way to launder stale assurance.
    """
    path = example_tree / MODEL_ARTIFACT
    old_digest = component(covert, MODEL_COMPONENT)["digest"]
    path.write_bytes(path.read_bytes() + b"\n")

    updated, _ = update_attestation(covert, example_tree)

    assert evidence(updated, MODEL_EVIDENCE)["subject-digests"] == [old_digest]
    assert component(updated, MODEL_COMPONENT)["digest"] != old_digest


def test_the_change_log_names_the_evidence_that_has_become_unbound(covert, example_tree):
    path = example_tree / MODEL_ARTIFACT
    old_digest = component(covert, MODEL_COMPONENT)["digest"]
    path.write_bytes(path.read_bytes() + b"\n")
    expected = unbound_evidence(covert, {old_digest})
    assert MODEL_EVIDENCE in expected

    _, changes = update_attestation(covert, example_tree)

    assert len(changes) == 1
    entry = changes[0]
    assert old_digest in entry and compute_digest(path) in entry
    # The operator's next action is to re-collect exactly these items, so the
    # log has to name them rather than say that some evidence was affected.
    for evidence_id in expected:
        assert evidence_id in entry


def test_a_re_attested_package_no_longer_validates_clean(covert, example_tree, keyring):
    """Re-attestation fixes the drift and exposes the assurance gap underneath.

    The component now matches the artifact on disk, so level 4's attestation
    check is satisfied, but the evidence is still bound to a digest no component
    carries. That is the correct outcome: the package is honest about the fact
    that nothing has yet been observed about the artifact now deployed.
    """
    path = example_tree / MODEL_ARTIFACT
    old_digest = component(covert, MODEL_COMPONENT)["digest"]
    path.write_bytes(path.read_bytes() + b"\n")

    baseline = validate_package(
        covert, now=FROZEN_NOW, keyring=keyring, root=example_tree
    )
    assert has_errors(baseline) is True

    updated, _ = update_attestation(covert, example_tree)
    findings = validate_package(
        updated, now=FROZEN_NOW, keyring=keyring, root=example_tree
    )

    assert has_errors(findings) is True
    unbound = [
        finding
        for finding in findings
        if finding.level == 4 and "not in the package inventory" in finding.message
    ]
    assert unbound, "expected the re-bound package to report its now-unbound evidence"
    assert {finding.severity for finding in unbound} == {SEVERITY_ERROR}
    assert all(old_digest in finding.message for finding in unbound)
    assert MODEL_EVIDENCE in {finding.object_id for finding in unbound}


def test_update_attestation_reports_nothing_when_no_artifact_has_changed(covert, example_tree):
    updated, changes = update_attestation(covert, example_tree)
    assert changes == []
    assert updated == covert


# --------------------------------------------------------------------------
# Roots and exit codes
# --------------------------------------------------------------------------


def test_default_root_for_package_is_the_directory_holding_the_package(covert_path):
    """Artifact paths are relative to the package, not to the caller's cwd.

    Any other choice would make the same package attest differently depending on
    where the validator happened to be run from.
    """
    assert default_root_for_package(covert_path) == covert_path.resolve().parent


def test_default_root_for_package_resolves_a_relative_package_path(tmp_path, monkeypatch):
    package_path = tmp_path / "nested" / "package.json"
    package_path.parent.mkdir()
    package_path.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert default_root_for_package(Path("nested/package.json")) == package_path.resolve().parent


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (STATUS_MATCH, 0),
        (STATUS_NO_ARTIFACT_PATH, 0),
        (STATUS_DRIFT, 1),
        (STATUS_MISSING_FILE, 1),
        (STATUS_OUTSIDE_ROOT, 1),
    ],
)
def test_attestation_exit_code_fails_only_on_a_broken_binding(status, expected):
    assert attestation_exit_code([{"status": status}]) == expected


def test_one_failing_record_among_matches_still_fails_the_run():
    records = [{"status": STATUS_MATCH}, {"status": STATUS_DRIFT}, {"status": STATUS_MATCH}]
    assert attestation_exit_code(records) == 1


def test_an_empty_record_set_is_not_a_failure():
    assert attestation_exit_code([]) == 0
