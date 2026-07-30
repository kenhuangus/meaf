"""MEAF package validator — the six conformance levels of manuscript A.5.

    1. Syntactic validity     the serialization conforms to the declared schema
    2. Referential integrity  every reference resolves to exactly one object
    3. Semantic validity      layers, ordering, digests, timestamps, roles,
                              exceptions
    4. Evidence validity      attributable, bound, approved method, in window,
                              classified
    5. Policy validity        threat coverage, path interruption, findings from
                              failures, expiry changes the gate state
    6. Reproducibility        a second evaluator with the same package, evidence
                              and policy bundle reaches the same gate result

Two rules govern everything below. A check that *fails* produces an error. A
check that *cannot run* produces a warning and never a silent pass, because an
unrunnable check is indistinguishable from a passing one to anybody reading the
output. Levels 2 through 6 also tolerate structurally invalid input: level 1 has
already reported it, and a validator that stops at the first malformed object
hides the rest of the package's problems from the person trying to fix it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from meaf.model import (
    COLLECTOR_VERSION_RE,
    FUNCTION_INTERRUPTION_TYPES,
    SEVERITY_ERROR,
    SEVERITY_WARNING,
    Finding,
    TimestampError,
    digest_algorithm,
    has_errors,
    index_by_id,
    layer_number,
    objects,
    parse_date,
    parse_datetime,
    parse_duration,
    role_ids,
    unique_index,
)
from meaf.contract import (
    STATE_FAIL,
    STATE_INDETERMINATE,
    contract_states_by_id,
    evaluate_contracts,
    has_evaluable_decision_rule,
    live_exception,
)
from meaf.packs import known_pack_ids
from meaf.policy import INDETERMINATE_FAIL_CLOSED, Policy, default_policy
from meaf.signing import validate_l4_evidence

SCHEMA_FILE = "meaf-2.0.0.schema.json"

#: Collections whose members carry an ``id`` that other objects may reference.
REFERENCED_COLLECTIONS = (
    "components",
    "threats",
    "attack-paths",
    "control-implementations",
    "assurance-contracts",
    "tests",
    "evidence",
    "findings",
    "decisions",
)

#: Runner argument-vector heads that make a test unreproducible because the real
#: command lives in a string the package does not pin.
UNPINNED_RUNNER_HEADS = frozenset({"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell"})

#: Threshold key forms the rule evaluator understands. Kept in step with
#: ``meaf.testpack.evaluate_rule``; a form the evaluator handles must not be
#: rejected here, and a form it cannot handle must not pass.
THRESHOLD_SUFFIXES = ("-max", "-min", "-exact")
SAMPLING_PREFIX = "minimum-"


def _format_checker() -> FormatChecker:
    """A format checker for the three formats this schema actually uses.

    ``jsonschema`` ignores ``format`` unless a checker is supplied, which is why
    ``"collected-at": "not-a-date"`` passed level 1 before. These handlers reuse
    the same parsers the rest of the validator uses, so level 1 and level 3
    cannot disagree about whether a timestamp is well formed.
    """
    checker = FormatChecker()

    @checker.checks("date-time", raises=TimestampError)
    def _check_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return True
        parse_datetime(value)
        return True

    @checker.checks("date", raises=TimestampError)
    def _check_date(value: object) -> bool:
        if not isinstance(value, str):
            return True
        parse_date(value)
        return True

    @checker.checks("duration", raises=TimestampError)
    def _check_duration(value: object) -> bool:
        if not isinstance(value, str):
            return True
        parse_duration(value)
        return True

    return checker


FORMAT_CHECKER = _format_checker()


def load_schema() -> dict[str, Any]:
    schema_path = Path(__file__).parent / "schema" / SCHEMA_FILE
    with schema_path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_package(path: Path) -> Any:
    """Load a package document. The caller validates; this only parses."""
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _error(level: int, object_id: str | None, message: str) -> Finding:
    return Finding(level=level, severity=SEVERITY_ERROR, object_id=object_id, message=message)


def _warning(level: int, object_id: str | None, message: str) -> Finding:
    return Finding(level=level, severity=SEVERITY_WARNING, object_id=object_id, message=message)


# --------------------------------------------------------------------------
# Level 1: syntactic validity
# --------------------------------------------------------------------------


def validate_l1_syntactic(package: Any, schema: dict[str, Any]) -> list[Finding]:
    validator = Draft202012Validator(schema, format_checker=FORMAT_CHECKER)
    findings: list[Finding] = []
    for error in sorted(validator.iter_errors(package), key=lambda e: list(e.path)):
        path = "/".join(str(part) for part in error.absolute_path) or "(root)"
        findings.append(_error(1, path, error.message))
    return findings


# --------------------------------------------------------------------------
# Level 2: referential integrity
# --------------------------------------------------------------------------


def _reference_targets(package: Any) -> dict[str, dict[str, list[dict[str, Any]]]]:
    return {
        name: index_by_id(objects(package, name)) for name in REFERENCED_COLLECTIONS
    }


def _check_ref(
    findings: list[Finding],
    value: Any,
    targets: dict[str, dict[str, list[dict[str, Any]]]],
    collection: str,
    object_id: str,
    field: str,
) -> None:
    """Report a reference that resolves to anything other than exactly one object."""
    if not isinstance(value, str):
        return
    matches = targets[collection].get(value, [])
    if not matches:
        findings.append(
            _error(
                2,
                object_id,
                f"dangling reference {field}={value!r} (no {collection} with that id)",
            )
        )


def validate_l2_referential(package: Any) -> list[Finding]:
    findings: list[Finding] = []
    targets = _reference_targets(package)

    # Duplicate identifiers are reported once, by the collection that holds them.
    for collection in REFERENCED_COLLECTIONS:
        for object_id, matches in sorted(targets[collection].items()):
            if len(matches) > 1:
                findings.append(
                    _error(
                        2,
                        object_id,
                        f"duplicate id in {collection} ({len(matches)} objects); "
                        f"a reference to it cannot resolve to exactly one object",
                    )
                )

    system = package.get("system") if isinstance(package, dict) else None
    system_id = system.get("id") if isinstance(system, dict) else None

    for component in objects(package, "components"):
        component_id = str(component.get("id", "(unknown)"))
        _check_ref(
            findings,
            component.get("provenance-evidence"),
            targets,
            "evidence",
            component_id,
            "provenance-evidence",
        )
        for dependency in component.get("dependencies", []) or []:
            _check_ref(findings, dependency, targets, "components", component_id, "dependencies[]")

    for threat in objects(package, "threats"):
        threat_id = str(threat.get("id", "(unknown)"))
        _check_ref(findings, threat.get("path"), targets, "attack-paths", threat_id, "path")

    for control in objects(package, "control-implementations"):
        control_id = str(control.get("id", "(unknown)"))
        for path_id in control.get("attack-paths", []) or []:
            _check_ref(findings, path_id, targets, "attack-paths", control_id, "attack-paths[]")
        for dependency in control.get("dependencies", []) or []:
            if not isinstance(dependency, str):
                continue
            if dependency in targets["components"] or dependency in targets["control-implementations"]:
                continue
            findings.append(
                _error(
                    2,
                    control_id,
                    f"dangling reference dependencies[]={dependency!r} "
                    "(no components or control-implementations with that id)",
                )
            )

    for contract in objects(package, "assurance-contracts"):
        contract_id = str(contract.get("id", "(unknown)"))
        _check_ref(
            findings,
            contract.get("control"),
            targets,
            "control-implementations",
            contract_id,
            "control",
        )
        _check_ref(findings, contract.get("test"), targets, "tests", contract_id, "test")
        for threat_id in contract.get("threats", []) or []:
            _check_ref(findings, threat_id, targets, "threats", contract_id, "threats[]")
        for evidence_id in contract.get("required-evidence", []) or []:
            _check_ref(
                findings, evidence_id, targets, "evidence", contract_id, "required-evidence[]"
            )
        subject = contract.get("subject")
        if isinstance(subject, str) and subject not in targets["components"] and subject != system_id:
            findings.append(
                _error(
                    2,
                    contract_id,
                    f"dangling reference subject={subject!r} "
                    "(no components with that id, and not the system id)",
                )
            )

    for test in objects(package, "tests"):
        test_id = str(test.get("id", "(unknown)"))
        target = test.get("target")
        if isinstance(target, str) and target not in targets["components"] and target != system_id:
            findings.append(
                _error(
                    2,
                    test_id,
                    f"dangling reference target={target!r} "
                    "(no components with that id, and not the system id)",
                )
            )

    for finding_object in objects(package, "findings"):
        finding_id = str(finding_object.get("id", "(unknown)"))
        _check_ref(
            findings,
            finding_object.get("failed-claim"),
            targets,
            "assurance-contracts",
            finding_id,
            "failed-claim",
        )
        _check_ref(
            findings,
            finding_object.get("retest-reference"),
            targets,
            "tests",
            finding_id,
            "retest-reference",
        )
        for path_id in finding_object.get("affected-paths", []) or []:
            _check_ref(findings, path_id, targets, "attack-paths", finding_id, "affected-paths[]")

    for decision in objects(package, "decisions"):
        decision_id = str(decision.get("id", "(unknown)"))
        for contract_id in decision.get("applies-to", []) or []:
            _check_ref(
                findings,
                contract_id,
                targets,
                "assurance-contracts",
                decision_id,
                "applies-to[]",
            )
        for control_id in decision.get("compensating-controls", []) or []:
            _check_ref(
                findings,
                control_id,
                targets,
                "control-implementations",
                decision_id,
                "compensating-controls[]",
            )

    return findings


# --------------------------------------------------------------------------
# Level 3: semantic validity
# --------------------------------------------------------------------------


def _validate_attack_paths(package: Any) -> list[Finding]:
    findings: list[Finding] = []
    for attack_path in objects(package, "attack-paths"):
        path_id = str(attack_path.get("id", "(unknown)"))
        nodes = attack_path.get("nodes")
        edges = attack_path.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            continue

        for node in nodes:
            if layer_number(node) is None:
                findings.append(
                    _error(
                        3,
                        path_id,
                        f"invalid attack-path node {node!r}; expected L1-L7:<label>",
                    )
                )

        # An attack path is a traversal, so one typed edge joins each adjacent
        # pair of nodes. Layer numbers are deliberately not required to ascend:
        # the manuscript's own chains include L3 to L2 and L5 to L6 traversals.
        if len(edges) != len(nodes) - 1:
            findings.append(
                _error(
                    3,
                    path_id,
                    f"attack-path has {len(nodes)} nodes and {len(edges)} edges; "
                    f"expected {max(len(nodes) - 1, 0)} edges, one per traversal step",
                )
            )

        for index in range(1, len(nodes)):
            if nodes[index] == nodes[index - 1]:
                findings.append(
                    _error(
                        3,
                        path_id,
                        f"attack-path repeats node {nodes[index]!r} consecutively, "
                        "which is not a traversal step",
                    )
                )

    return findings


def _validate_digest_algorithms(package: Any, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    permitted = policy.permitted_digest_algorithms

    def check(digest: Any, object_id: str, field: str) -> None:
        algorithm = digest_algorithm(digest)
        if algorithm is None:
            return
        if algorithm not in permitted:
            findings.append(
                _error(
                    3,
                    object_id,
                    f"{field} uses digest algorithm {algorithm!r}, which policy "
                    f"{policy.name} does not permit "
                    f"({', '.join(sorted(permitted))})",
                )
            )

    for component in objects(package, "components"):
        check(component.get("digest"), str(component.get("id", "(unknown)")), "digest")
    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id", "(unknown)"))
        for digest in evidence.get("subject-digests", []) or []:
            check(digest, evidence_id, "subject-digests[]")
        metadata = evidence.get("model-metadata")
        if isinstance(metadata, dict):
            check(
                metadata.get("evaluator-prompt-digest"),
                evidence_id,
                "model-metadata/evaluator-prompt-digest",
            )
    return findings


def _validate_timestamps(package: Any, now: datetime) -> list[Finding]:
    """A.5 level 3: timestamps are coherent.

    Coherence only. Whether evidence is still inside its validity window is a
    level 4 question, because that is where the manuscript puts it and because
    the answer depends on what is deployed, not on the timestamps alone.
    """
    findings: list[Finding] = []
    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id", "(unknown)"))
        try:
            collected = parse_datetime(evidence.get("collected-at"))
        except TimestampError as exc:
            findings.append(_error(3, evidence_id, f"invalid collected-at: {exc}"))
            continue

        if collected > now:
            findings.append(
                _error(3, evidence_id, "collected-at is in the future at evaluation time")
            )

        try:
            parse_duration(evidence.get("max-age"))
        except TimestampError as exc:
            findings.append(_error(3, evidence_id, f"invalid max-age: {exc}"))

        invalidated_at = evidence.get("invalidated-at")
        if invalidated_at is not None:
            try:
                invalidated = parse_datetime(invalidated_at)
            except TimestampError as exc:
                findings.append(_error(3, evidence_id, f"invalid invalidated-at: {exc}"))
                continue
            if invalidated < collected:
                findings.append(
                    _error(3, evidence_id, "invalidated-at is before collected-at")
                )

    for finding_object in objects(package, "findings"):
        try:
            parse_date(finding_object.get("due-date"))
        except TimestampError as exc:
            findings.append(
                _error(3, str(finding_object.get("id", "(unknown)")), f"invalid due-date: {exc}")
            )

    for decision in objects(package, "decisions"):
        try:
            parse_date(decision.get("expiry"))
        except TimestampError as exc:
            findings.append(
                _error(3, str(decision.get("id", "(unknown)")), f"invalid expiry: {exc}")
            )

    return findings


def _validate_roles(package: Any) -> list[Finding]:
    """A.5 level 3: required roles exist.

    An owner nobody has declared cannot be held accountable for remediation, so
    an unresolvable owner is an error rather than a naming preference.
    """
    findings: list[Finding] = []
    declared = role_ids(package)
    if not declared:
        return [
            _warning(
                3,
                None,
                "package declares no responsible-roles, so owner and decision-maker "
                "references cannot be resolved",
            )
        ]

    system = package.get("system") if isinstance(package, dict) else None
    if isinstance(system, dict):
        owner = system.get("owner")
        if isinstance(owner, str) and owner not in declared:
            findings.append(
                _error(3, str(system.get("id", "(unknown)")), f"system owner {owner!r} is not a declared role")
            )

    for collection, field in (
        ("control-implementations", "owner"),
        ("assurance-contracts", "owner"),
        ("decisions", "decision-maker"),
    ):
        for item in objects(package, collection):
            value = item.get(field)
            if isinstance(value, str) and value not in declared:
                findings.append(
                    _error(
                        3,
                        str(item.get("id", "(unknown)")),
                        f"{field} {value!r} is not a declared responsible role",
                    )
                )
    return findings


def _validate_control_coherence(package: Any) -> list[Finding]:
    """Controls must interrupt where they claim to, in a way their function allows."""
    findings: list[Finding] = []
    path_index = unique_index(objects(package, "attack-paths"))

    for control in objects(package, "control-implementations"):
        control_id = str(control.get("id", "(unknown)"))
        function = control.get("function")
        interruption_type = control.get("interruption-type")
        permitted = FUNCTION_INTERRUPTION_TYPES.get(function)
        if permitted is not None and interruption_type not in permitted:
            findings.append(
                _error(
                    3,
                    control_id,
                    f"control declares function {function!r} but interruption-type "
                    f"{interruption_type!r}; a {function} control may only "
                    f"{' or '.join(sorted(permitted))}",
                )
            )

        point = control.get("interruption-point")
        for path_id in control.get("attack-paths", []) or []:
            attack_path = path_index.get(path_id)
            if attack_path is None:
                continue
            nodes = attack_path.get("nodes")
            if isinstance(nodes, list) and point not in nodes:
                findings.append(
                    _error(
                        3,
                        control_id,
                        f"interruption-point {point!r} is not a node of attack path "
                        f"{path_id!r}, so the control interrupts nothing on it",
                    )
                )
    return findings


def _validate_contract_coherence(package: Any) -> list[Finding]:
    findings: list[Finding] = []
    control_index = unique_index(objects(package, "control-implementations"))
    test_index = unique_index(objects(package, "tests"))

    for contract in objects(package, "assurance-contracts"):
        contract_id = str(contract.get("id", "(unknown)"))
        control = control_index.get(contract.get("control"))
        if control is not None and contract.get("function") != control.get("function"):
            findings.append(
                _error(
                    3,
                    contract_id,
                    f"contract function {contract.get('function')!r} does not match "
                    f"the function {control.get('function')!r} of its paired control "
                    f"{control.get('id')!r}",
                )
            )

        test = test_index.get(contract.get("test"))
        if test is not None:
            thresholds = test.get("thresholds")
            decision_rule = contract.get("decision-rule")
            if isinstance(thresholds, dict) and isinstance(decision_rule, dict):
                for key in sorted(set(thresholds) & set(decision_rule)):
                    if thresholds[key] != decision_rule[key]:
                        findings.append(
                            _error(
                                3,
                                contract_id,
                                f"decision-rule {key}={decision_rule[key]!r} disagrees "
                                f"with threshold {key}={thresholds[key]!r} in test "
                                f"{test.get('id')!r}",
                            )
                        )
    return findings


def _validate_tests(package: Any) -> list[Finding]:
    findings: list[Finding] = []
    registered = known_pack_ids()

    for test in objects(package, "tests"):
        test_id = str(test.get("id", "(unknown)"))
        pack = test.get("test-pack")
        if pack is None:
            findings.append(
                _warning(
                    3,
                    test_id,
                    "test cites no standard test-pack, so its coverage cannot be "
                    "compared against the appendix A.7 registry",
                )
            )
        elif pack not in registered:
            findings.append(
                _error(3, test_id, f"test-pack {pack!r} is not in the standard registry")
            )

        if test.get("adversarial") is True:
            thresholds = test.get("utility-thresholds")
            if isinstance(thresholds, dict):
                unevaluable = sorted(
                    key
                    for key in thresholds
                    if not key.endswith(THRESHOLD_SUFFIXES)
                    and not key.startswith(SAMPLING_PREFIX)
                    and not isinstance(thresholds[key], bool)
                )
                if unevaluable:
                    findings.append(
                        _error(
                            3,
                            test_id,
                            "utility-thresholds keys carry no comparison suffix and "
                            f"cannot be evaluated: {', '.join(unevaluable)}",
                        )
                    )
                if not thresholds:
                    findings.append(
                        _error(
                            3,
                            test_id,
                            "adversarial test states no minimum benign-task utility; a "
                            "control that refuses every request would score as secure",
                        )
                    )
    return findings


def _validate_threats(package: Any) -> list[Finding]:
    findings: list[Finding] = []
    system = package.get("system") if isinstance(package, dict) else None
    system_id = system.get("id") if isinstance(system, dict) else None
    data_classes = set(system.get("data-classes", []) or []) if isinstance(system, dict) else set()
    component_ids = {
        component.get("id") for component in objects(package, "components")
    }

    contracts_by_threat: dict[str, list[dict[str, Any]]] = {}
    for contract in objects(package, "assurance-contracts"):
        for threat_id in contract.get("threats", []) or []:
            if isinstance(threat_id, str):
                contracts_by_threat.setdefault(threat_id, []).append(contract)

    for threat in objects(package, "threats"):
        threat_id = str(threat.get("id", "(unknown)"))
        target = threat.get("target")
        if (
            isinstance(target, str)
            and target not in component_ids
            and target != system_id
            and target not in data_classes
        ):
            findings.append(
                _error(
                    3,
                    threat_id,
                    f"target {target!r} is neither a component id, the system id, nor a "
                    "declared data class",
                )
            )

        profile = threat.get("temporal-profile")
        persistence = profile.get("persistence") if isinstance(profile, dict) else None
        if persistence is not None and persistence != "session":
            if not contracts_by_threat.get(threat_id):
                # A warning, not an error: A.5 puts "required threats have
                # assurance contracts" at level 5, and reporting the same gap at
                # both levels would double-count it. This one adds the reason
                # the gap matters more for a threat that outlives a session.
                findings.append(
                    _warning(
                        3,
                        threat_id,
                        f"threat persists beyond a session ({persistence}) and has no "
                        "assurance contract, so nothing reassesses it as the deployment ages",
                    )
                )
    return findings


def _validate_exceptions(package: Any) -> list[Finding]:
    """A.5 level 3: exceptions have owners and expiry dates."""
    findings: list[Finding] = []
    declared = role_ids(package)
    for decision in objects(package, "decisions"):
        if decision.get("decision-type") not in ("exception", "not-applicable"):
            continue
        decision_id = str(decision.get("id", "(unknown)"))
        maker = decision.get("decision-maker")
        if not isinstance(maker, str) or (declared and maker not in declared):
            findings.append(
                _error(
                    3,
                    decision_id,
                    "exception has no owner that resolves to a declared responsible role",
                )
            )
        try:
            parse_date(decision.get("expiry"))
        except TimestampError:
            findings.append(_error(3, decision_id, "exception has no usable expiry date"))
    return findings


def validate_l3_semantic(
    package: Any,
    now: datetime,
    policy: Policy | None = None,
) -> list[Finding]:
    if policy is None:
        policy = default_policy()
    findings: list[Finding] = []
    findings.extend(_validate_attack_paths(package))
    findings.extend(_validate_digest_algorithms(package, policy))
    findings.extend(_validate_timestamps(package, now))
    findings.extend(_validate_roles(package))
    findings.extend(_validate_control_coherence(package))
    findings.extend(_validate_contract_coherence(package))
    findings.extend(_validate_tests(package))
    findings.extend(_validate_threats(package))
    findings.extend(_validate_exceptions(package))
    return findings


# --------------------------------------------------------------------------
# Level 5: policy validity
# --------------------------------------------------------------------------


def _path_coverage(package: Any) -> dict[str, list[dict[str, Any]]]:
    """Controls grouped by the attack path they claim to interrupt."""
    coverage: dict[str, list[dict[str, Any]]] = {}
    for control in objects(package, "control-implementations"):
        for path_id in control.get("attack-paths", []) or []:
            if isinstance(path_id, str):
                coverage.setdefault(path_id, []).append(control)
    return coverage


def _interrupts_before_outcome(control: dict[str, Any], attack_path: dict[str, Any]) -> bool:
    """True when the control interrupts at a node earlier than the final one.

    A control that only acts at the terminal node acts once the harmful outcome
    has already been reached, which is containment or recovery rather than
    interruption before harm.
    """
    nodes = attack_path.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        return False
    point = control.get("interruption-point")
    if point not in nodes:
        return False
    return nodes.index(point) < len(nodes) - 1


def _validate_path_interruption(
    package: Any,
    policy: Policy,
    contract_states: dict[str, Any],
    now: datetime,
) -> list[Finding]:
    """A.3: each high-impact path needs a *currently verified* control and a
    verified containment or recovery mechanism.

    When the policy demands a passing contract, a control whose contract is
    failing does not count — but A.3 also says "Exceptions must be explicit,
    scoped, approved, and time-bounded". A failing contract under a live
    exception therefore downgrades the finding to a warning naming the
    exception, rather than either passing silently or making the exception
    mechanism useless.
    """
    findings: list[Finding] = []
    coverage = _path_coverage(package)
    contracts_by_control: dict[str, list[str]] = {}
    for contract in objects(package, "assurance-contracts"):
        control_id = contract.get("control")
        contract_id = contract.get("id")
        if isinstance(control_id, str) and isinstance(contract_id, str):
            contracts_by_control.setdefault(control_id, []).append(contract_id)

    for attack_path in objects(package, "attack-paths"):
        path_id = str(attack_path.get("id", "(unknown)"))
        impact = attack_path.get("impact", "critical")
        requirement = policy.interruption_requirement(impact)
        controls = coverage.get(path_id, [])

        def satisfied(
            types: list[str], require_before_outcome: bool
        ) -> tuple[bool, str | None]:
            """(covered, exception id when coverage rests on an exception)."""
            excepted_by: str | None = None
            for control in controls:
                if control.get("interruption-type") not in types:
                    continue
                if require_before_outcome and not _interrupts_before_outcome(control, attack_path):
                    continue
                if not requirement["require-contract-pass"]:
                    return True, None
                for contract_id in contracts_by_control.get(str(control.get("id")), []):
                    state = contract_states.get(contract_id)
                    if state is not None and state.state == "pass":
                        return True, None
                    exception = live_exception(package, contract_id, now)
                    if exception is not None and excepted_by is None:
                        excepted_by = str(exception.get("id"))
            return (excepted_by is not None), excepted_by

        for types, before_outcome, description in (
            (requirement["require-before-outcome"], True, "before the harmful outcome"),
            (requirement["require-recovery"], False, "for containment or recovery"),
        ):
            if not types:
                continue
            covered, excepted_by = satisfied(types, before_outcome)
            qualifier = (
                " with a passing assurance contract"
                if requirement["require-contract-pass"]
                else ""
            )
            requirement_text = (
                f"{impact}-impact attack path has no control that "
                f"{' or '.join(sorted(types))} {description}{qualifier}"
            )
            if not covered:
                findings.append(_error(5, path_id, requirement_text))
            elif excepted_by is not None:
                findings.append(
                    _warning(
                        5,
                        path_id,
                        f"{requirement_text}; coverage rests on exception {excepted_by}",
                    )
                )
    return findings


def validate_l5_policy(
    package: Any,
    now: datetime,
    policy: Policy | None = None,
) -> list[Finding]:
    if policy is None:
        policy = default_policy()

    findings: list[Finding] = []
    states = contract_states_by_id(evaluate_contracts(package, now=now, policy=policy))

    contracts_by_threat: dict[str, list[dict[str, Any]]] = {}
    for contract in objects(package, "assurance-contracts"):
        for threat_id in contract.get("threats", []) or []:
            if isinstance(threat_id, str):
                contracts_by_threat.setdefault(threat_id, []).append(contract)

    for threat in objects(package, "threats"):
        threat_id = str(threat.get("id", "(unknown)"))
        if not contracts_by_threat.get(threat_id):
            findings.append(_error(5, threat_id, "threat has no assurance contract"))

    # A.3: "Every control implementation is paired with an assurance contract."
    # An unpaired control is a mitigation nobody has agreed to verify.
    verified_controls = {
        contract.get("control")
        for contract in objects(package, "assurance-contracts")
        if isinstance(contract.get("control"), str)
    }
    for control in objects(package, "control-implementations"):
        control_id = str(control.get("id", "(unknown)"))
        if control_id not in verified_controls:
            findings.append(
                _error(
                    5,
                    control_id,
                    "control implementation is not paired with any assurance contract, "
                    "so nothing verifies that the mitigation works",
                )
            )

    findings_by_contract = {
        finding.get("failed-claim")
        for finding in objects(package, "findings")
        if isinstance(finding.get("failed-claim"), str)
    }

    # Contract states are reported before the path-coverage rules that derive
    # from them, so the first error an operator sees names the claim that broke
    # rather than the coverage gap that followed from it.
    for contract_id, state in sorted(states.items()):
        if state.state == STATE_FAIL and contract_id not in findings_by_contract:
            findings.append(
                _error(
                    5,
                    contract_id,
                    "contract state is fail but no finding records the failure",
                )
            )
        if state.state == STATE_INDETERMINATE:
            handling = policy.indeterminate_handling(state.impact)
            severity_reason = "; ".join(state.reasons)
            if handling == INDETERMINATE_FAIL_CLOSED:
                findings.append(
                    _error(
                        5,
                        contract_id,
                        f"contract is indeterminate on a {state.impact}-impact path and "
                        f"policy {policy.name} fails closed: {severity_reason}",
                    )
                )
            else:
                findings.append(
                    _warning(
                        5,
                        contract_id,
                        f"contract is indeterminate on a {state.impact}-impact path; "
                        f"policy {policy.name} says {handling}: {severity_reason}",
                    )
                )

    findings.extend(_validate_path_interruption(package, policy, states, now))

    for evidence in objects(package, "evidence"):
        if evidence.get("result") != "fail":
            continue
        evidence_id = str(evidence.get("id", "(unknown)"))
        linked = {
            contract["id"]
            for contract in objects(package, "assurance-contracts")
            if evidence_id in (contract.get("required-evidence") or [])
            and isinstance(contract.get("id"), str)
        }
        if linked and not (linked & findings_by_contract):
            findings.append(
                _error(
                    5,
                    evidence_id,
                    "evidence reports fail but no finding references any contract that requires it",
                )
            )

    for decision in objects(package, "decisions"):
        decision_id = str(decision.get("id", "(unknown)"))
        try:
            expiry = parse_date(decision.get("expiry"))
        except TimestampError:
            continue
        if expiry < now.date():
            findings.append(_error(5, decision_id, f"decision expired on {expiry.isoformat()}"))
            continue
        if decision.get("decision-type") in ("exception", "not-applicable"):
            remaining = (expiry - now.date()).days
            if remaining > policy.maximum_exception_age_days:
                findings.append(
                    _error(
                        5,
                        decision_id,
                        f"exception runs {remaining} days, beyond the "
                        f"{policy.maximum_exception_age_days} day ceiling in policy {policy.name}",
                    )
                )

    return findings


# --------------------------------------------------------------------------
# Level 6: reproducibility
# --------------------------------------------------------------------------


def validate_l6_reproducibility(package: Any, policy: Policy | None = None) -> list[Finding]:
    """Would a second evaluator reach the same gate result from this package?

    Each check below names something that, if left unpinned, makes the answer
    depend on the evaluator's environment rather than on the package.
    """
    if policy is None:
        policy = default_policy()
    findings: list[Finding] = []

    for evidence in objects(package, "evidence"):
        evidence_id = str(evidence.get("id", "(unknown)"))
        collector = evidence.get("collector")
        if not isinstance(collector, str) or not COLLECTOR_VERSION_RE.match(collector):
            findings.append(
                _error(
                    6,
                    evidence_id,
                    "evidence collector lacks an explicit version "
                    "(expected name:major.minor.patch)",
                )
            )

    for test in objects(package, "tests"):
        test_id = str(test.get("id", "(unknown)"))
        version = test.get("test-pack-version")
        if isinstance(version, str) and ":" not in version:
            findings.append(
                _error(
                    6,
                    test_id,
                    f"test-pack-version {version!r} does not pin a named pack "
                    "(expected pack-name:major.minor.patch)",
                )
            )
        runner = test.get("runner")
        if isinstance(runner, dict):
            command = runner.get("command")
            if isinstance(command, list) and command:
                head = str(command[0]).rsplit("/", 1)[-1]
                if head in UNPINNED_RUNNER_HEADS:
                    findings.append(
                        _warning(
                            6,
                            test_id,
                            f"runner invokes {head!r}, so the executed command is not "
                            "pinned by the package and may differ between evaluators",
                        )
                    )

    evidence_index = unique_index(objects(package, "evidence"))
    for contract in objects(package, "assurance-contracts"):
        contract_id = str(contract.get("id", "(unknown)"))
        probabilistic = [
            evidence_index[eid]
            for eid in contract.get("required-evidence", []) or []
            if eid in evidence_index
            and evidence_index[eid].get("class") == "probabilistic-inference"
        ]
        if probabilistic and not has_evaluable_decision_rule(contract.get("decision-rule")):
            findings.append(
                _error(
                    6,
                    contract_id,
                    "contract gates on probabilistic inference but its decision-rule "
                    "states no metric bound, so two evaluators may disagree",
                )
            )

    declared = package.get("policy-bundle") if isinstance(package, dict) else None
    if not isinstance(declared, dict):
        findings.append(
            _warning(
                6,
                None,
                "package declares no policy-bundle, so a second evaluator cannot know "
                "which cross-object rules produced this result",
            )
        )
    else:
        declared_name = f"{declared.get('id')}:{declared.get('version')}"
        if declared_name != policy.name:
            findings.append(
                _error(
                    6,
                    None,
                    f"package declares policy bundle {declared_name} but was evaluated "
                    f"under {policy.name}",
                )
            )

    return findings


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def validate_package(
    package: Any,
    *,
    now: datetime | None = None,
    schema: dict[str, Any] | None = None,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
    policy: Policy | None = None,
) -> list[Finding]:
    """Run all six conformance levels and return every finding.

    ``now`` is injectable so that a package's gate result is reproducible: pass
    the evaluation instant rather than letting wall-clock drift change the
    answer between two runs.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    if schema is None:
        schema = load_schema()
    if policy is None:
        policy = default_policy()

    findings: list[Finding] = validate_l1_syntactic(package, schema)

    if not isinstance(package, dict):
        return findings

    findings.extend(validate_l2_referential(package))
    findings.extend(validate_l3_semantic(package, now, policy))
    findings.extend(
        validate_l4_evidence(package, keyring=keyring, root=root, policy=policy, now=now)
    )
    findings.extend(validate_l5_policy(package, now, policy))
    findings.extend(validate_l6_reproducibility(package, policy))
    return findings


def format_findings(findings: list[Finding]) -> str:
    if not findings:
        return "Validation passed (0 errors, 0 warnings)."
    lines: list[str] = []
    for level in range(1, 7):
        level_findings = [f for f in findings if f.level == level]
        if not level_findings:
            continue
        lines.append(f"L{level}:")
        for finding in level_findings:
            obj = finding.object_id or "(package)"
            lines.append(f"  [{finding.severity}] {obj}: {finding.message}")
    errors = sum(1 for f in findings if f.severity == SEVERITY_ERROR)
    warnings = sum(1 for f in findings if f.severity == SEVERITY_WARNING)
    lines.append(f"Summary: {errors} error(s), {warnings} warning(s).")
    return "\n".join(lines)


__all__ = [
    "Finding",
    "format_findings",
    "has_errors",
    "load_package",
    "load_schema",
    "validate_l1_syntactic",
    "validate_l2_referential",
    "validate_l3_semantic",
    "validate_l5_policy",
    "validate_l6_reproducibility",
    "validate_package",
]
