"""MEAF — MAESTRO Executable Assurance Framework pilot."""

__version__ = "1.0.0"
SCHEMA_VERSION = "1.0.0"

from meaf.attest import (
    check_attestation,
    compute_digest,
    default_root_for_package,
    update_attestation,
)
from meaf.lifecycle import (
    TransitionResult,
    attempt_transition,
    current_state,
    legal_next_states,
)
from meaf.oscal import export_oscal
from meaf.signing import (
    canonical_payload,
    load_keyring,
    sign_evidence,
    verify_evidence,
)
from meaf.testpack import TestRunResult, run_tests
from meaf.validator import (
    Finding,
    format_findings,
    has_errors,
    load_package,
    validate_package,
)

__all__ = [
    "load_package",
    "validate_package",
    "format_findings",
    "has_errors",
    "Finding",
    "check_attestation",
    "update_attestation",
    "compute_digest",
    "default_root_for_package",
    "run_tests",
    "TestRunResult",
    "attempt_transition",
    "current_state",
    "legal_next_states",
    "TransitionResult",
    "export_oscal",
    "sign_evidence",
    "verify_evidence",
    "load_keyring",
    "canonical_payload",
]
