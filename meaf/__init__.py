"""MEAF — the MAESTRO Executable Assurance Framework, reference implementation.

A MEAF package links a declared system boundary to the nine object types of
manuscript appendix A.2, plus the assurance contracts of A.3:

    system                    the boundary the package covers
    components                the AI bill of materials, bound by digest
    threats                   attack tuples with an explicit temporal profile
    attack-paths              ordered MAESTRO nodes with typed edges
    control-implementations   how and where each threat is interrupted
    tests                     reproducible challenges to a control claim
    evidence                  attributable observations, never claims
    findings                  failed assurance carried into remediation
    decisions                 owned gate decisions and time-bounded exceptions

    assurance-contracts       what must be observed for a control to count as
                              working; the smallest independently evaluable unit

The distinction between the last two is the one worth holding on to. A *control
implementation* describes the mitigation: prevent, detect, contain or recover;
where it runs; what it depends on; whether it is enforcing or merely watching;
and what it does when it breaks. An *assurance contract* describes the proof:
which falsifiable claim, tested how, against which thresholds, with what
evidence, how often, and who is accountable when it fails. A control without a
contract is an assertion nobody has agreed to check.
"""

from __future__ import annotations

__version__ = "2.0.0"
SCHEMA_VERSION = "2.0.0"
POLICY_SCHEMA_VERSION = "2.0.0"

from meaf.adoption import assess_adoption
from meaf.attest import (
    check_attestation,
    compute_digest,
    default_root_for_package,
    update_attestation,
)
from meaf.contract import (
    CONTRACT_STATES,
    ContractState,
    GateResult,
    evaluate_contract,
    evaluate_contracts,
    evaluate_gate,
)
from meaf.impact import ChangeImpact, analyse_change
from meaf.lifecycle import (
    TransitionResult,
    attempt_transition,
    current_state,
    legal_next_states,
)
from meaf.migrate import MigrationReport, migrate_package
from meaf.model import (
    Currency,
    Finding,
    evidence_currency,
    evidence_is_fresh,
    has_errors,
)
from meaf.oscal import export_oscal
from meaf.packs import TestPack, load_registry
from meaf.policy import Policy, default_policy, load_policy
from meaf.report import build_report
from meaf.signing import (
    canonical_payload,
    load_keyring,
    sign_evidence,
    verify_evidence,
)
from meaf.summary import conformance_summary
from meaf.testpack import TestRunResult, run_tests
from meaf.validator import format_findings, load_package, validate_package

__all__ = [
    # package loading and conformance
    "load_package",
    "validate_package",
    "format_findings",
    "has_errors",
    "Finding",
    # contract states and the gate
    "CONTRACT_STATES",
    "ContractState",
    "GateResult",
    "evaluate_contract",
    "evaluate_contracts",
    "evaluate_gate",
    # policy bundle
    "Policy",
    "default_policy",
    "load_policy",
    # evidence currency and artifact binding
    "Currency",
    "evidence_currency",
    "evidence_is_fresh",
    "check_attestation",
    "update_attestation",
    "compute_digest",
    "default_root_for_package",
    # tests and evidence production
    "run_tests",
    "TestRunResult",
    "TestPack",
    "load_registry",
    # lifecycle
    "attempt_transition",
    "current_state",
    "legal_next_states",
    "TransitionResult",
    # projections and interoperability
    "build_report",
    "conformance_summary",
    "export_oscal",
    # change management and adoption
    "analyse_change",
    "ChangeImpact",
    "assess_adoption",
    "migrate_package",
    "MigrationReport",
    # signing
    "sign_evidence",
    "verify_evidence",
    "load_keyring",
    "canonical_payload",
]
