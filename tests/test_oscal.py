"""The OSCAL export has to be readable by OSCAL tooling, not just by MEAF.

An export that a NIST or FedRAMP toolchain rejects is worth nothing, so these
tests check the export against the OSCAL 1.1.2 JSON model rather than against
whatever the exporter happens to emit. Three failure modes are specifically
guarded here because each one has already occurred in this codebase or in the
wider OSCAL ecosystem: XML-shaped singular wrappers where the JSON model
requires an array, threats emitted as catalog controls, and identifiers that
collide when two collections share an id string.

The fourth guarantee is determinism. An authorization package that changes
because it was regenerated on a different afternoon cannot be diffed, signed or
compared, so the export reads no wall clock and this file proves it by exporting
twice across a real second.
"""

from __future__ import annotations

import copy
import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

import pytest

from meaf.contract import evaluate_contracts
from meaf.oscal import (
    ASSESSMENT_PLAN_FILE,
    ASSESSMENT_RESULTS_FILE,
    CATALOG_FILE,
    COMPONENT_DEFINITION_FILE,
    EXPORT_FILES,
    MAESTRO_NS,
    OSCAL_VERSION,
    POAM_FILE,
    PROFILE_FILE,
    SSP_FILE,
    export_assessment_results,
    export_catalog,
    export_oscal,
    export_poam,
    meaf_uuid,
)
from tests.conftest import FROZEN_NOW

#: The newest ``collected-at`` in the covert-influence example. Every document
#: exported from that package must report exactly this as ``last-modified``.
NEWEST_COVERT_EVIDENCE = "2026-07-15T00:00:00Z"

#: A.4 names the MAESTRO semantics that must survive the crossing into OSCAL:
#: "maestro:layer, maestro:attack-path, maestro:temporal-profile,
#: maestro:interruption-type, maestro:evidence-class, and maestro:artifact-binding".
MAESTRO_PROPERTY_NAMES = {
    "layer",
    "attack-path",
    "temporal-profile",
    "interruption-type",
    "evidence-class",
    "artifact-binding",
}

MAESTRO_LAYER_RE = re.compile(r"^L[1-7]$")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def root_of(document: dict[str, Any]) -> dict[str, Any]:
    """The single top-level assembly of an OSCAL document."""
    return next(iter(document.values()))


def walk(node: Any) -> Iterator[dict[str, Any]]:
    """Yield every dict nested anywhere inside an exported document."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)


def all_props(document: Any) -> list[dict[str, Any]]:
    return [
        prop
        for holder in walk(document)
        for prop in holder.get("props", [])
        if isinstance(prop, dict)
    ]


def catalog_control_ids(document: dict[str, Any]) -> list[str]:
    """Control ids from both the grouped and the ungrouped catalog positions."""
    catalog = document["catalog"]
    ids = [control["id"] for control in catalog.get("controls", [])]
    for group in catalog.get("groups", []):
        ids.extend(control["id"] for control in group.get("controls", []))
    return ids


def resources_titled(document: Any, prefix: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in root_of(document)["back-matter"]["resources"]
        if str(resource.get("title", "")).startswith(prefix)
    ]


@pytest.fixture
def documents(covert: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """All seven documents exported from the clean reference package."""
    return {filename: exporter(covert) for filename, exporter in EXPORT_FILES.items()}


# --------------------------------------------------------------------------
# Document identity
# --------------------------------------------------------------------------


def test_the_export_produces_the_six_oscal_models_of_the_mapping_table():
    # A.4 maps MEAF onto Catalog, Profile, Component Definition, System Security
    # Plan, Assessment Plan, Assessment Results and POA&M. Catalog and Profile
    # share one row, which is why six models are seven documents.
    assert set(EXPORT_FILES) == {
        CATALOG_FILE,
        PROFILE_FILE,
        COMPONENT_DEFINITION_FILE,
        SSP_FILE,
        ASSESSMENT_PLAN_FILE,
        ASSESSMENT_RESULTS_FILE,
        POAM_FILE,
    }


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_each_document_has_exactly_one_top_level_member_naming_its_model(
    documents, filename
):
    """OSCAL JSON wraps a document in a single member named for its model.

    A second top-level member, or a member named anything other than the model,
    makes the file unloadable by any OSCAL processor.
    """
    document = documents[filename]
    assert isinstance(document, dict)
    assert list(document) == [Path(filename).stem]
    assert isinstance(root_of(document), dict)


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_every_document_carries_a_uuid_that_parses_as_a_uuid(documents, filename):
    assert uuid.UUID(root_of(documents[filename])["uuid"]).version == 5


# --------------------------------------------------------------------------
# JSON array shapes
# --------------------------------------------------------------------------

#: Every assembly OSCAL declares with cardinality greater than one. In OSCAL's
#: XML syntax these appear as repeated singular elements, and a naive port emits
#: the XML shape as {"controls": {"control": [...]}}. That is not the OSCAL JSON
#: model and no OSCAL JSON parser accepts it: in JSON the plural member IS the
#: array. Each case below therefore asserts a bare list.
ARRAY_ASSEMBLIES = [
    pytest.param(CATALOG_FILE, lambda d: d["catalog"]["groups"], id="catalog-groups"),
    pytest.param(
        CATALOG_FILE,
        lambda d: d["catalog"]["groups"][0]["controls"],
        id="catalog-controls",
    ),
    pytest.param(PROFILE_FILE, lambda d: d["profile"]["imports"], id="profile-imports"),
    pytest.param(
        COMPONENT_DEFINITION_FILE,
        lambda d: d["component-definition"]["components"],
        id="component-definition-components",
    ),
    pytest.param(
        SSP_FILE,
        lambda d: d["system-security-plan"]["system-implementation"]["components"],
        id="ssp-components",
    ),
    pytest.param(
        SSP_FILE,
        lambda d: d["system-security-plan"]["system-implementation"]["users"],
        id="ssp-users",
    ),
    pytest.param(
        ASSESSMENT_PLAN_FILE,
        lambda d: d["assessment-plan"]["local-definitions"]["activities"],
        id="assessment-plan-activities",
    ),
    pytest.param(
        ASSESSMENT_RESULTS_FILE,
        lambda d: d["assessment-results"]["results"],
        id="assessment-results-results",
    ),
    pytest.param(
        ASSESSMENT_RESULTS_FILE,
        lambda d: d["assessment-results"]["results"][0]["observations"],
        id="assessment-results-observations",
    ),
    pytest.param(
        POAM_FILE,
        lambda d: d["plan-of-action-and-milestones"]["poam-items"],
        id="poam-items",
    ),
]


@pytest.mark.parametrize(("filename", "select"), ARRAY_ASSEMBLIES)
def test_repeatable_assemblies_are_json_arrays(documents, filename, select):
    assembly = select(documents[filename])
    assert isinstance(assembly, list)
    assert assembly, "an empty array would not prove the shape is right"
    assert all(isinstance(entry, dict) for entry in assembly)


def test_ungrouped_controls_are_also_an_array(covert):
    """A control whose location has no MAESTRO layer lands at catalog top level.

    The top-level ``controls`` member is exercised separately because it is a
    different code path from the grouped one, and the XML-wrapper mistake tends
    to be made in exactly one of the two.
    """
    for control in covert["control-implementations"]:
        control["implementation-location"] = "unlocated-runtime-surface"

    catalog = export_catalog(covert)["catalog"]
    assert "groups" not in catalog
    assert isinstance(catalog["controls"], list)
    assert len(catalog["controls"]) == len(covert["control-implementations"])


def test_catalog_groups_are_named_for_the_maestro_layer_they_hold(documents):
    groups = documents[CATALOG_FILE]["catalog"]["groups"]
    assert [group["id"] for group in groups] == ["L5", "L6"]
    assert all(group["title"].startswith(group["id"]) for group in groups)


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_metadata_carries_the_four_members_oscal_requires(documents, covert, filename):
    metadata = root_of(documents[filename])["metadata"]
    assert set(metadata) >= {"title", "last-modified", "version", "oscal-version"}
    assert metadata["title"]
    # The document version is the MEAF package version: an OSCAL projection of
    # a package is not independently versioned from it.
    assert metadata["version"] == covert["meaf-version"]


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_every_document_declares_oscal_1_1_2(documents, filename):
    assert root_of(documents[filename])["metadata"]["oscal-version"] == OSCAL_VERSION
    assert OSCAL_VERSION == "1.1.2"


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_last_modified_is_the_newest_evidence_timestamp(documents, filename):
    """The package's modification time is an observation, not a clock reading.

    A.1 principle 1 separates claims from evidence; a ``last-modified`` taken
    from the exporting machine's clock is a claim about the package that no
    evidence supports, and it makes two exports of the same package differ.
    """
    assert root_of(documents[filename])["metadata"]["last-modified"] == (
        NEWEST_COVERT_EVIDENCE
    )


def test_last_modified_moves_when_newer_evidence_arrives(covert):
    later = copy.deepcopy(covert["evidence"][0])
    later["id"] = "ev-later-run"
    later["collected-at"] = "2026-07-20T06:30:00Z"
    covert["evidence"].append(later)

    assert (
        export_catalog(covert)["catalog"]["metadata"]["last-modified"]
        == "2026-07-20T06:30:00Z"
    )


def test_metadata_lists_the_responsible_roles_the_ssp_refers_to(documents):
    # A.4 maps "responsible roles" into the SSP, and OSCAL resolves a role-id
    # against metadata/roles, so an unlisted role-id is a dangling reference.
    metadata = root_of(documents[SSP_FILE])["metadata"]
    declared = {role["id"] for role in metadata["roles"]}
    implemented = root_of(documents[SSP_FILE])["control-implementation"][
        "implemented-requirements"
    ]
    used = {
        role["role-id"]
        for requirement in implemented
        for role in requirement["responsible-roles"]
    }
    assert used <= declared


def test_two_exports_separated_in_real_time_are_byte_identical(covert, tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"

    export_oscal(covert, first)
    # A full second of wall clock. Any timestamp read from the clock at the
    # second resolution the exporter formats with would differ across this gap.
    time.sleep(1.05)
    export_oscal(covert, second)

    for filename in EXPORT_FILES:
        assert (first / filename).read_bytes() == (second / filename).read_bytes()


# --------------------------------------------------------------------------
# Identifier determinism and namespacing
# --------------------------------------------------------------------------


def test_meaf_uuid_is_stable_across_calls():
    assert meaf_uuid("pkg-a", "components", "cmp-x") == meaf_uuid(
        "pkg-a", "components", "cmp-x"
    )


def test_meaf_uuid_is_a_valid_version_5_uuid():
    value = meaf_uuid("pkg-a", "components", "cmp-x")
    assert str(uuid.UUID(value)) == value
    assert uuid.UUID(value).version == 5


def test_the_same_id_in_two_collections_gets_two_uuids():
    """The collision the collection qualifier exists to prevent.

    A component and an assurance contract may legitimately share an id string
    across two documents. Deriving both UUIDs from the id alone made them the
    same object as far as OSCAL was concerned.
    """
    assert meaf_uuid("pkg-a", "components", "shared-id") != meaf_uuid(
        "pkg-a", "assurance-contracts", "shared-id"
    )


def test_two_packages_do_not_share_uuids_for_the_same_object_id():
    assert meaf_uuid("pkg-a", "components", "cmp-x") != meaf_uuid(
        "pkg-b", "components", "cmp-x"
    )


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_no_uuid_is_reused_within_a_document(documents, filename):
    identifiers = [
        holder["uuid"]
        for holder in walk(documents[filename])
        if isinstance(holder.get("uuid"), str)
    ]
    assert len(identifiers) == len(set(identifiers))


# --------------------------------------------------------------------------
# The A.4 mapping table
# --------------------------------------------------------------------------


def test_control_implementations_become_catalog_controls(documents, covert):
    # A.4: "MAESTRO control catalog and external-framework mappings -> Catalog
    # and Profile models".
    assert set(catalog_control_ids(documents[CATALOG_FILE])) == {
        control["id"] for control in covert["control-implementations"]
    }


def test_threats_become_assessment_results_risks(documents, covert):
    # A.4: "Observations, risks, findings, and collected evidence -> Assessment
    # Results model". The MEAF threat is the OSCAL risk.
    risks = documents[ASSESSMENT_RESULTS_FILE]["assessment-results"]["results"][0][
        "risks"
    ]
    assert isinstance(risks, list)
    assert {risk["title"] for risk in risks} == {
        threat["id"] for threat in covert["threats"]
    }
    assert all(risk["status"] == "open" for risk in risks)


def test_a_threat_is_never_emitted_as_a_catalog_control(documents, covert):
    """A threat is not a security control, and a catalog says only controls.

    An earlier export emitted both, which made the catalog assert that "an
    attacker biases generation" was a control an organisation could implement.
    """
    control_ids = set(catalog_control_ids(documents[CATALOG_FILE]))
    threat_ids = {threat["id"] for threat in covert["threats"]}
    assert not control_ids & threat_ids


def test_every_catalog_control_is_classed_as_a_control_implementation(documents):
    catalog = documents[CATALOG_FILE]["catalog"]
    for group in catalog["groups"]:
        for control in group["controls"]:
            assert control["class"] == "maestro-control-implementation"


def test_evidence_becomes_observations(documents, covert):
    observations = documents[ASSESSMENT_RESULTS_FILE]["assessment-results"]["results"][
        0
    ]["observations"]
    assert {observation["title"] for observation in observations} == {
        evidence["id"] for evidence in covert["evidence"]
    }
    collected = {
        observation["title"]: observation["collected"] for observation in observations
    }
    assert collected["ev-counterfactual-run-2026-07"] == NEWEST_COVERT_EVIDENCE


def test_probabilistic_evidence_is_observed_by_test_and_the_rest_by_examine(
    documents, covert
):
    """A.1 principle 2 keeps the two evidence classes distinguishable.

    OSCAL's observation method is the natural carrier: an inference drawn from
    running a test is not the same act as examining a recorded configuration.
    """
    observations = {
        observation["title"]: observation
        for observation in documents[ASSESSMENT_RESULTS_FILE]["assessment-results"][
            "results"
        ][0]["observations"]
    }
    for evidence in covert["evidence"]:
        expected = "TEST" if evidence["class"] == "probabilistic-inference" else "EXAMINE"
        assert observations[evidence["id"]]["methods"] == [expected]


def test_findings_become_findings_whose_objective_is_not_satisfied(memory):
    # A.5: fail means "at least one required test or deterministic policy
    # predicate fails", so the objective the finding targets is not satisfied.
    results = export_assessment_results(memory)["assessment-results"]["results"][0]
    findings = {finding["title"]: finding for finding in results["findings"]}
    assert set(findings) == {finding["id"] for finding in memory["findings"]}

    for finding in findings.values():
        assert finding["target"]["type"] == "objective-id"
        assert finding["target"]["status"]["state"] == "not-satisfied"

    # The reason carries the finding's own status, so a reviewer can tell an
    # untouched failure from one already under remediation. Exporting every
    # finding with the same reason would leave remediated work indistinguishable
    # from work nobody has started.
    in_progress = findings["finding-memory-write-screening-001"]
    assert in_progress["target"]["status"]["reason"] == "remediation in progress"


def test_a_resolved_finding_does_not_export_as_an_open_objective(memory):
    """A remediated finding is not an open not-satisfied objective.

    Exporting it as one keeps closed work on the assessor's desk forever, which
    is how a POA&M stops being read.
    """
    memory["findings"][0]["status"] = "resolved"
    results = export_assessment_results(memory)["assessment-results"]["results"][0]
    finding = results["findings"][0]
    assert finding["target"]["status"]["state"] == "satisfied"


def test_a_finding_targets_the_assessment_objective_of_the_claim_it_failed(memory):
    """The catalog part id and the finding target id have to be the same string.

    Otherwise the assessment result names an objective the catalog does not
    define, and the failure cannot be traced back to a control.
    """
    finding = export_assessment_results(memory)["assessment-results"]["results"][0][
        "findings"
    ][0]
    contract_id = memory["findings"][0]["failed-claim"]
    assert finding["target"]["target-id"] == f"{contract_id}_obj"

    catalog = export_catalog(memory)["catalog"]
    objective_ids = {
        part["id"]
        for group in catalog.get("groups", [])
        for control in group["controls"]
        for part in control["parts"]
        if part["name"] == "assessment-objective"
    }
    assert finding["target"]["target-id"] in objective_ids


def test_a_passing_contract_state_records_a_satisfied_objective(covert, policy):
    """The contrast that makes not-satisfied meaningful.

    A.5 gives a contract four states; an assessment result that only ever says
    "not-satisfied" cannot distinguish a passing control from an unassessed one.
    """
    states = evaluate_contracts(covert, now=FROZEN_NOW, policy=policy)
    assert {state.state for state in states} == {"pass"}

    results = export_assessment_results(covert, now=FROZEN_NOW, policy=policy)[
        "assessment-results"
    ]["results"][0]
    satisfied = {
        finding["target"]["target-id"]: finding["target"]["status"]["state"]
        for finding in results["findings"]
    }
    assert satisfied == {
        f"{contract['id']}_obj": "satisfied" for contract in covert["assurance-contracts"]
    }


def test_open_findings_and_live_exceptions_become_poam_items(memory):
    # A.4: "Open remediation items and milestones -> Plan of Action and
    # Milestones model".
    items = export_poam(memory)["plan-of-action-and-milestones"]["poam-items"]
    titles = [item["title"] for item in items]

    assert "finding-memory-write-screening-001" in titles
    assert any(title.startswith("dec-exception-memory-write-2026-06") for title in titles)
    # The authorization decision is the gate itself, not an outstanding item.
    assert not any("dec-authorization-2026-06" in title for title in titles)


def test_a_poam_item_links_back_to_the_assessment_result_finding(memory):
    items = export_poam(memory)["plan-of-action-and-milestones"]["poam-items"]
    item = next(
        item for item in items if item["title"] == "finding-memory-write-screening-001"
    )
    linked = {related["finding-uuid"] for related in item["related-findings"]}

    findings = export_assessment_results(memory)["assessment-results"]["results"][0][
        "findings"
    ]
    assert linked == {
        finding["uuid"]
        for finding in findings
        if finding["title"] == "finding-memory-write-screening-001"
    }


@pytest.mark.parametrize("status", ["resolved", "risk-accepted"])
def test_a_closed_finding_is_not_an_open_remediation_item(memory, status):
    memory["findings"][0]["status"] = status
    items = export_poam(memory)["plan-of-action-and-milestones"]["poam-items"]
    assert "finding-memory-write-screening-001" not in [item["title"] for item in items]


def test_a_package_with_nothing_outstanding_still_emits_a_poam_item(documents):
    """OSCAL requires at least one poam-item, so "nothing open" must be stated.

    The covert-influence example has no findings and no exception, and an empty
    poam-items array would be an invalid document rather than a clean one.
    """
    items = documents[POAM_FILE]["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == 1
    assert items[0]["title"] == "No open remediation items"


# --------------------------------------------------------------------------
# Back matter
# --------------------------------------------------------------------------


def test_back_matter_holds_a_resource_for_every_component_and_evidence_item(
    documents, covert
):
    resources = root_of(documents[CATALOG_FILE])["back-matter"]["resources"]
    assert isinstance(resources, list)
    assert len(resources) == len(covert["components"]) + len(covert["evidence"])


def test_component_resources_carry_their_digest_as_an_rlink_hash(documents, covert):
    resources = {
        resource["title"]: resource
        for resource in resources_titled(documents[CATALOG_FILE], "Artifact for ")
    }
    for component in covert["components"]:
        rlink = resources[f"Artifact for {component['id']}"]["rlinks"][0]
        algorithm, value = component["digest"].split(":", 1)
        assert algorithm == "sha256"
        # OSCAL takes hash algorithm names from the NIST registry, so the
        # digest prefix has to be translated rather than passed through.
        assert rlink["hashes"] == [{"algorithm": "SHA-256", "value": value}]


def test_evidence_resources_reference_the_evidence_instead_of_embedding_it(
    documents, covert
):
    """A.4: large evidence stays external, addressed by digest.

    "Large traces, model cards, dataset manifests, red-team corpora, and signed
    telemetry remain external resources addressed by digest and linked through
    OSCAL back matter." An embedded trace would defeat the whole point.
    """
    evidence_index = {evidence["id"]: evidence for evidence in covert["evidence"]}
    resources = resources_titled(documents[ASSESSMENT_RESULTS_FILE], "Evidence ")
    assert len(resources) == len(evidence_index)

    for resource in resources:
        evidence = evidence_index[resource["title"].removeprefix("Evidence ")]
        bindings = {
            prop["value"] for prop in resource["props"] if prop["name"] == "artifact-binding"
        }
        assert bindings == {",".join(evidence["subject-digests"])}
        # base64 is OSCAL's inline-content member; rlinks would point at a copy.
        assert "base64" not in resource
        assert "rlinks" not in resource


def test_observations_point_at_the_back_matter_resource_for_their_evidence(documents):
    results = documents[ASSESSMENT_RESULTS_FILE]["assessment-results"]["results"][0]
    resource_uuids = {
        resource["uuid"]
        for resource in resources_titled(documents[ASSESSMENT_RESULTS_FILE], "Evidence ")
    }
    for observation in results["observations"]:
        for reference in observation["relevant-evidence"]:
            assert reference["href"].startswith("#")
            assert reference["href"][1:] in resource_uuids


# --------------------------------------------------------------------------
# Cross-document references
# --------------------------------------------------------------------------

CROSS_DOCUMENT_IMPORTS = [
    pytest.param(
        PROFILE_FILE,
        lambda d: d["profile"]["imports"][0]["href"],
        CATALOG_FILE,
        id="profile-imports-catalog",
    ),
    pytest.param(
        SSP_FILE,
        lambda d: d["system-security-plan"]["import-profile"]["href"],
        PROFILE_FILE,
        id="ssp-imports-profile",
    ),
    pytest.param(
        ASSESSMENT_PLAN_FILE,
        lambda d: d["assessment-plan"]["import-ssp"]["href"],
        SSP_FILE,
        id="assessment-plan-imports-ssp",
    ),
    pytest.param(
        ASSESSMENT_RESULTS_FILE,
        lambda d: d["assessment-results"]["import-ap"]["href"],
        ASSESSMENT_PLAN_FILE,
        id="assessment-results-imports-plan",
    ),
    pytest.param(
        POAM_FILE,
        lambda d: d["plan-of-action-and-milestones"]["import-ssp"]["href"],
        SSP_FILE,
        id="poam-imports-ssp",
    ),
    pytest.param(
        COMPONENT_DEFINITION_FILE,
        lambda d: d["component-definition"]["components"][0]["control-implementations"][
            0
        ]["source"],
        CATALOG_FILE,
        id="component-definition-sources-catalog",
    ),
]


@pytest.mark.parametrize(("filename", "select", "target"), CROSS_DOCUMENT_IMPORTS)
def test_cross_document_references_resolve_to_files_the_export_writes(
    covert, tmp_path, filename, select, target
):
    written = export_oscal(covert, tmp_path)
    href = select(json.loads((tmp_path / filename).read_text(encoding="utf-8")))

    assert href == f"./{target}"
    resolved = (tmp_path / filename).parent / href
    assert resolved.resolve() in {path.resolve() for path in written}
    assert resolved.is_file()


def test_the_profile_selects_every_control_the_catalog_defines(documents):
    selected = documents[PROFILE_FILE]["profile"]["imports"][0]["include-controls"][0][
        "with-ids"
    ]
    assert isinstance(selected, list)
    assert set(selected) == set(catalog_control_ids(documents[CATALOG_FILE]))


def test_the_assessment_plan_reviews_every_control_the_catalog_defines(documents):
    selections = documents[ASSESSMENT_PLAN_FILE]["assessment-plan"]["reviewed-controls"][
        "control-selections"
    ]
    assert isinstance(selections, list)
    reviewed = {
        include["control-id"]
        for selection in selections
        for include in selection["include-controls"]
    }
    assert reviewed == set(catalog_control_ids(documents[CATALOG_FILE]))


def test_a_component_subject_resolves_to_the_ssp_component_of_the_same_name(
    documents, covert
):
    """A.4 routes inventory through the SSP, so subjects must resolve into it.

    An assessment-plan subject-uuid that no SSP component carries is a dangling
    reference across two documents, which is exactly the class of error A.5
    level 2 exists to prevent inside one.
    """
    ssp_component_uuids = {
        component["uuid"]
        for component in root_of(documents[SSP_FILE])["system-implementation"][
            "components"
        ]
    }
    subjects = [
        subject
        for task in documents[ASSESSMENT_PLAN_FILE]["assessment-plan"]["tasks"]
        for association in task["associated-activities"]
        for subject in association["subjects"]
    ]
    subject_uuids = {
        include["subject-uuid"]
        for subject in subjects
        for include in subject.get("include-subjects", [])
    }
    component_ids = {component["id"] for component in covert["components"]}
    expected = {
        meaf_uuid(covert["package-id"], "ssp-component", contract["subject"])
        for contract in covert["assurance-contracts"]
        if contract["subject"] in component_ids
    }
    assert expected
    assert expected <= subject_uuids & ssp_component_uuids

    # A contract whose subject is the system is not a component, so it has no
    # SSP component uuid to point at. It selects the whole inventory rather than
    # inventing an identifier that resolves to nothing.
    system_subject_contracts = [
        contract
        for contract in covert["assurance-contracts"]
        if contract["subject"] not in component_ids
    ]
    assert system_subject_contracts
    assert any("include-all" in subject for subject in subjects)
    assert subject_uuids <= ssp_component_uuids


def test_tasks_associate_with_activities_the_plan_defines(documents):
    plan = documents[ASSESSMENT_PLAN_FILE]["assessment-plan"]
    activity_uuids = {
        activity["uuid"] for activity in plan["local-definitions"]["activities"]
    }
    for task in plan["tasks"]:
        for association in task["associated-activities"]:
            assert association["activity-uuid"] in activity_uuids


# --------------------------------------------------------------------------
# MAESTRO properties
# --------------------------------------------------------------------------


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_property_names_are_tokens_and_carry_a_namespace(documents, filename):
    """A.4 carries MAESTRO semantics "in namespaced properties and links".

    OSCAL property names are tokens and cannot contain a colon, so the
    manuscript's ``maestro:layer`` is written as name "layer" plus an ns member.
    A property literally named "maestro:layer" is schema-invalid OSCAL.
    """
    # The profile carries no MAESTRO semantics of its own; it only selects
    # controls the catalog already annotates. Emptiness is checked across the
    # whole export by the next test rather than document by document.
    for prop in all_props(documents[filename]):
        assert set(prop) >= {"name", "value", "ns"}
        assert ":" not in prop["name"]
        assert prop["ns"] == MAESTRO_NS


def test_every_maestro_semantic_named_in_a4_survives_the_export(documents):
    exported = {prop["name"] for document in documents.values() for prop in all_props(document)}
    assert MAESTRO_PROPERTY_NAMES <= exported


def test_layer_properties_hold_real_maestro_layers(documents):
    values = {
        prop["value"]
        for document in documents.values()
        for prop in all_props(document)
        if prop["name"] == "layer"
    }
    assert values
    # MAESTRO has exactly seven layers; anything else is a mis-parsed node label.
    assert all(MAESTRO_LAYER_RE.match(value) for value in values), values


def test_the_namespace_is_a_resolvable_uri():
    assert MAESTRO_NS.startswith("https://")


# --------------------------------------------------------------------------
# Writing the export
# --------------------------------------------------------------------------


def test_export_oscal_writes_exactly_the_declared_files(covert, tmp_path):
    written = export_oscal(covert, tmp_path)

    assert [path.name for path in written] == list(EXPORT_FILES)
    assert {path.name for path in tmp_path.iterdir()} == set(EXPORT_FILES)
    assert all(path.parent == tmp_path for path in written)


def test_export_oscal_creates_a_missing_output_directory(covert, tmp_path):
    out_dir = tmp_path / "nested" / "oscal"
    written = export_oscal(covert, out_dir)
    assert out_dir.is_dir()
    assert len(written) == len(EXPORT_FILES)


@pytest.mark.parametrize("filename", sorted(EXPORT_FILES))
def test_written_documents_parse_as_json_and_match_the_exporter(
    covert, tmp_path, filename
):
    export_oscal(covert, tmp_path)
    written = json.loads((tmp_path / filename).read_text(encoding="utf-8"))
    assert written == EXPORT_FILES[filename](covert)
