# MEAF Developer Guide

This guide is for engineers who need to **extend** the MEAF pilot: add conformance checks, CLI commands, schema fields, test runners, lifecycle guards, or OSCAL mappings. For what the tool does and how to operate it, see [README.md](README.md).

---

## 1. Orientation

### Who this guide is for

You have read [README.md](README.md) and can run `validate`, `attest`, and `run-tests`. You now need to change the implementation without breaking wire contracts, measurement validity, or the public API surface in `meaf.__all__`.

### Module map

| File | Responsibility | Depends on | Depended on by |
|------|----------------|------------|----------------|
| `meaf/__init__.py` | Published API re-exports, `__version__`, `SCHEMA_VERSION` | `attest`, `contracts`, `lifecycle`, `oscal`, `signing`, `summary`, `testpack`, `validator` | External callers, `test_meaf.py` |
| `meaf/__main__.py` | CLI (`argparse`, `sys.exit`) | `attest`, `contracts`, `lifecycle`, `oscal`, `signing`, `summary`, `testpack`, `validator` | `python -m meaf` only |
| `meaf/validator.py` | L1-L3, L5, L6 checks; `Finding`; `validate_package` orchestration | `jsonschema`; lazy `meaf.signing.validate_l4_evidence`, `meaf.contracts.evaluate_contracts` | `signing`, `lifecycle`, `contracts`, `summary`, `testpack`, `__init__`, `__main__`, tests |
| `meaf/contracts.py` | Per-contract state evaluation (appendix A.5) | `testpack._metric_rules`, `validator.evidence_is_fresh` | `validator` (L5), `summary`, `__init__`, `__main__`, tests |
| `meaf/summary.py` | Conforming eight-dimension summary (no aggregate score) | `contracts`, `lifecycle`, `validator` | `__init__`, `__main__`, tests |
| `meaf/signing.py` | Ed25519 sign/verify; L4 evidence checks | `validator.Finding`; lazy `meaf.attest.check_attestation` | `testpack`, `validator` (L4), `__init__`, `__main__`, tests |
| `meaf/attest.py` | Digest computation, attestation records, `update_attestation` | stdlib only | `signing` (L4 drift), `lifecycle`, `__init__`, `__main__`, tests |
| `meaf/testpack.py` | Subprocess runners, decision-rule evaluation, evidence emission | `signing`, `validator.parse_datetime` | `__init__`, `__main__`, tests |
| `meaf/lifecycle.py` | State machine, transition guards | `validator`; lazy `meaf.attest.has_attestation_drift` | `__init__`, `__main__`, tests |
| `meaf/oscal.py` | Deterministic OSCAL 1.1.2 export | stdlib only | `__init__`, `__main__`, tests |
| `meaf/schema/meaf-1.1.0.schema.json` | JSON Schema for packages | none (data) | `validator.load_schema`, tests |
| `meaf/test_meaf.py` | Pytest suite | all library modules | none |
| `meaf/examples/` | Reference packages, keyring, runners, artifacts | none (fixtures) | tests, README, this guide |

### Module dependency diagram

```
                    meaf/__main__.py  (CLI only)
                           |
    +----------+-----------+-----------+----------+----------+
    |          |           |           |          |          |
validator  signing    attest   testpack  lifecycle   oscal
    |          |           |           |          |
    |<---------+-----------+           |          |
    |          | (L4)                  |          |
    |          +----> attest (drift)   |          |
    |                                  |          |
    +--------> contracts ----> summary -+----------+  (validate_package in guards)

meaf/__init__.py  re-exports published surface from all libraries above
```

### Layering rule

- **Libraries** (`validator`, `signing`, `attest`, `testpack`, `lifecycle`, `oscal`) contain logic. They return data structures and never call `sys.exit` or parse CLI arguments.
- **`meaf/__main__.py`** is the only place `argparse` and process exit codes live.
- **`meaf/__init__.py`** is the published surface. Names in `__all__` and their signatures are versioned (see [Section 13](#13-release-process)).

Import from `meaf` in external code, not from submodules.

---

## 2. How a validation runs

`validate_package` in `meaf/validator.py` is the single orchestration entry point.

### Execution order

1. **Normalize `now`** to UTC (`datetime.now(timezone.utc)` if omitted).
2. **Load schema** via `load_schema()` if not passed in.
3. **L1** `validate_l1_syntactic(package, schema)` — JSON Schema via `Draft202012Validator`.
4. **Early return** if `package` is not a `dict` (L1 may have failed on root type). L2-L6 are skipped.
5. **L2** `validate_l2_referential(package)` — id uniqueness and cross-reference resolution.
6. **L3** `validate_l3_semantic(package, now)` — layer ordering, timestamps, freshness warnings, path coverage.
7. **L4** `validate_l4_evidence(package, keyring=..., root=...)` in `meaf/signing.py` — signatures, digest binding, optional attestation drift.
8. **L5** `validate_l5_policy(package, now)` — threat coverage, failed-evidence findings, decision expiry, stale required evidence.
9. **L6** `validate_l6_reproducibility(package)` — collector version strings.

### What each level receives

| Level | Key inputs beyond `package` |
|-------|------------------------------|
| L1 | `schema` dict |
| L2 | none |
| L3 | `now` |
| L4 | `keyring` (`dict[str, bytes]` or `None`), `root` (`Path` or `None`) |
| L5 | `now` |
| L6 | none |

### Finding accumulation

Each level returns `list[Finding]`. `validate_package` extends a single list:

```python
findings: list[Finding] = []
findings.extend(validate_l1_syntactic(...))
# ...
return findings
```

`Finding` fields: `level` (int 1-6), `severity` (`"error"` or `"warning"`), `object_id` (`str | None`), `message` (`str`). `Finding.to_dict()` uses `dataclasses.asdict`.

### Flow of `now`, `keyring`, and `root`

- **`now`**: injected by caller (CLI uses wall clock; tests use `FROZEN_NOW`). Drives evidence freshness (L3 warning, L5 error for required evidence), decision expiry (L5), and lifecycle guards when validation is invoked from lifecycle.
- **`keyring`**: maps collector `key-id` strings to raw Ed25519 public key bytes. When `None`, L4 appends exactly one warning: `signature verification was not performed` and skips per-evidence verify. When provided, unsigned evidence is an **error** (`evidence is unsigned`), bad signatures are **errors** (`evidence signature verification failed`).
- **`root`**: repo root for `artifact-path` resolution. When provided, L4 calls `check_attestation` and maps `drift` to errors and `missing-file` to warnings. When `None`, attestation drift is not checked at L4.

The CLI `validate` command sets `root = default_root_for_package(args.package)` (three parents above the package file) and optional `--keyring`.

### Why L2/L3 are skipped when the package is not a dict

```587:588:meaf/validator.py
    if not isinstance(package, dict):
        return findings
```

If JSON parsed to a non-object, L1 may already report schema errors; deeper checks assume dict-shaped collections like `package.get("threats", [])`.

### Exit codes and human output

`has_errors(findings)` returns `True` if any finding has `severity == "error"`. Warnings do not affect it.

`format_findings(findings)` groups by level (L1-L6), prints `[severity] object_id: message`, then `Summary: N error(s), M warning(s).` Empty findings yield `Validation passed (0 errors, 0 warnings).`

CLI `validate` returns `1` if `has_errors(findings)`, else `0`.

### Severity model

| Severity | Meaning | Examples |
|----------|---------|----------|
| `error` | Definite conformance violation | Dangling reference (L2), unsigned evidence with keyring (L4), expired decision (L5) |
| `warning` | Check incomplete or soft policy signal | Stale evidence at L3, missing keyring at L4, empty `subject-digests` at L4, missing artifact file at L4 |

**Rule:** a check that cannot be performed must **never silently pass**. Examples:

- No keyring → one L4 warning, not silent success on signatures.
- Runner subprocess failure → `indeterminate`, not `pass` (see `testpack.py`).

---

## 3. The core invariants

Do not break these. Each lists the guarding test in `meaf/test_meaf.py`.

| Invariant | Reason | Test |
|-----------|--------|------|
| `indeterminate` is never coerced to `pass` or `fail` | Confuses "could not measure" with success or violation | `test_bad_runner_yields_indeterminate_not_fail`, `test_indeterminate_contract_does_not_cause_contracts_exit_one` |
| Contract `indeterminate` is never coerced to `pass` or `fail` | Assurance claims must not silently succeed or fail on unresolved evidence | `test_contract_state_indeterminate_stale_evidence`, `test_indeterminate_contract_does_not_cause_contracts_exit_one` |
| `not-applicable` requires an `applicability` object | Named authority must explicitly waive a contract | `test_contract_state_not_applicable_requires_applicability` |
| A check that cannot run emits a warning; never silently passes | Missing capability must be visible | `test_missing_keyring_produces_one_l4_warning` |
| Unsigned artifacts must be structurally distinguishable from signed ones | No placeholder signature objects; missing `signature` key vs invalid signature | `test_unsigned_evidence_with_keyring_reports_unsigned_not_verify_failed` |
| Digests are hashed over newline-normalized bytes | CRLF checkouts must not cause false drift | `test_example_artifact_digests_match_recorded_values` |
| `attest --update` rebinds digests but never forges signatures | `update_attestation` updates component digests and `subject-digests`; it does not call `sign_evidence` | `test_attest_update_repairs_drift_and_preserves_evidence_bindings` (rebind); `test_run_tests_without_sign_with_emits_no_signature` (unsigned evidence has no `signature` key) |
| OSCAL export stays deterministic; no wall-clock time or randomness | Reproducible exports for diffing and CI | `test_oscal_export_is_deterministic` |
| Public surface in `__all__` is exact | API stability contract | `test_public_api_surface` (also `test_public_callable_signatures`, `test_frozen_wire_contracts`) |

### Contract-state precedence (appendix A.5)

`evaluate_contract` in `meaf/contracts.py` applies these rules in order; the first match wins:

1. **`not-applicable`** — only when the contract carries an `applicability` object (`approved-by`, `rationale`, `scope`). A contract without `applicability` can never reach this state.
2. **`fail`** — any required-evidence item resolves and has `result: fail`.
3. **`indeterminate`** — any required-evidence item is missing, stale at `now`, invalidated, has `result: indeterminate`, or is class `probabilistic-inference` while the contract has no decision-rule to interpret it.
4. **`pass`** — every required-evidence item resolves, is current, and has `result: pass`.

The implementation includes an explicit comment that `indeterminate` must never be silently coerced to `pass` or `fail`. L5 validation additionally requires that every contract in `fail` state has a `findings` entry referencing it (`test_fail_contract_without_finding_is_l5_error`).

---

## 4. Extension walkthrough A: add a new conformance check

This example adds an **L5 policy check**: every `decisions[].compensating-controls` entry must reference an existing `assurance-contracts` id. The check does not exist in the stock codebase; follow along in a branch, then revert if you were only learning.

### 1. Add the check function body

In `meaf/validator.py`, inside `validate_l5_policy`, after the failed-evidence loop and before the decision expiry loop, add:

```python
    contract_ids = {contract["id"] for contract in package.get("assurance-contracts", [])}
    for decision in package.get("decisions", []):
        decision_id = decision.get("id", "(unknown)")
        for control_id in decision.get("compensating-controls", []):
            if control_id not in contract_ids:
                findings.append(
                    Finding(
                        level=5,
                        severity="error",
                        object_id=decision_id,
                        message=(
                            f"dangling reference compensating-controls={control_id!r} "
                            f"(no assurance-contracts with that id)"
                        ),
                    )
                )
```

### 2. Level and severity

- **L5** for policy and authorization-adjacent rules (alongside decision expiry and threat coverage).
- **`error`** because a decision pointing at a non-existent contract is a hard referential violation (similar to L2 dangling refs, but decisions are not wired in L2).

### 3. Wire into `validate_package`

No change needed if you added code inside `validate_l5_policy`; it is already called from `validate_package`.

For a **new level function**, extend `validate_package` in the same file following the L1-L6 pattern.

### 4. Test

Add to `meaf/test_meaf.py`:

```python
def test_decision_compensating_controls_must_resolve():
    package = copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))
    package["decisions"][0]["compensating-controls"].append("ac-nonexistent")
    findings = validate_package(package, now=FROZEN_NOW, root=REPO_ROOT)
    errors = [
        f
        for f in findings
        if f.level == 5
        and f.severity == "error"
        and f.object_id == "dec-gate-2026-07"
        and "compensating-controls='ac-nonexistent'" in f.message
    ]
    assert len(errors) == 1

    clean = validate_package(
        load_package(EXAMPLES / "covert-influence.json"),
        now=FROZEN_NOW,
        root=REPO_ROOT,
    )
    compensating_errors = [
        f for f in clean if f.level == 5 and "compensating-controls" in f.message
    ]
    assert not compensating_errors
```

### 5. Run and verify

Clean example (exit code 0):

```bash
python -m meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json
```

```
L4:
  [warning] ev-containment-drill-2026-07: evidence has empty subject-digests
Summary: 0 error(s), 1 warning(s).
```

Injected dangling reference (exit code 1):

```bash
python -c "import copy; from pathlib import Path; from datetime import datetime, timezone; from meaf.validator import validate_package, format_findings, load_package; package = copy.deepcopy(load_package(Path('meaf/examples/covert-influence.json'))); package['decisions'][0]['compensating-controls'].append('ac-nonexistent'); findings = validate_package(package, now=datetime(2026,7,28,12,0,0,tzinfo=timezone.utc), root=Path('.')); print(format_findings(findings))"
```

```
L4:
  [warning] (unknown): signature verification was not performed
  [warning] ev-containment-drill-2026-07: evidence has empty subject-digests
L5:
  [error] dec-gate-2026-07: dangling reference compensating-controls='ac-nonexistent' (no assurance-contracts with that id)
Summary: 1 error(s), 2 warning(s).
```

**If you were only following along, revert changes to `validator.py` and `test_meaf.py` before submitting other work.**

---

## 5. Extension walkthrough B: add a new CLI subcommand

### Where the subparser goes

In `meaf/__main__.py`, after existing parsers:

```python
    my_parser = subparsers.add_parser("my-cmd", help="Short help text")
    my_parser.add_argument("package", type=Path, help="Path to package JSON")
```

### Argument conventions in this codebase

- Package path is always a positional `Path` argument named `package`.
- Optional paths use `type=Path` (`--keyring`, `--root`, `--output`, `--out-dir`).
- Machine-readable output uses `--json` with `json.dumps(..., indent=2)`.
- Defaults: `lifecycle --actor` defaults to `"unknown"`; `lifecycle --reason` defaults to `""`.
- Keyring resolution uses `_resolve_keyring(path)` which returns `None` when path is omitted.

### Return exit codes from `main`

`main()` returns an `int`; `if __name__ == "__main__": sys.exit(main())`.

Pattern after `args = parser.parse_args(argv)`:

```python
    if args.command == "my-cmd":
        package = load_package(args.package)
        result = my_library_function(package)  # logic in library module
        print(result)
        return 0  # or 1 on failure
```

### Rule: no logic in the CLI

The CLI loads packages, resolves paths (`default_root_for_package`, `_resolve_keyring`), prints formatted output, and maps results to exit codes. Parsing JSON, validating, attesting, running tests, and lifecycle transitions belong in library modules.

---

## 6. Extension walkthrough C: extend the schema

Schema file: `meaf/schema/meaf-1.1.0.schema.json`.

### Add an optional field without breaking existing packages

1. Add the property under the relevant `$defs` object (or top-level `properties` for package fields).
2. Do **not** add it to `required`.
3. Prefer `additionalProperties: false` on objects (existing pattern); only add keys you intend to validate.

Existing packages without the field continue to pass L1.

### Additive vs breaking changes

| Change | Breaking? |
|--------|-----------|
| New optional property | No (within same `meaf-version`) |
| New `required` property | Yes |
| Tighter `pattern` / `enum` | Yes |
| `meaf-version` pattern change | Yes (major package format) |

### Schema version and `meaf.SCHEMA_VERSION`

Top-level `meaf-version` in packages:

```json
"meaf-version": {
  "type": "string",
  "pattern": "^1\\.0\\.0$"
}
```

`meaf/__init__.py` sets `SCHEMA_VERSION = "1.1.0"`. The schema filename is `meaf-1.1.0.schema.json`. These must stay aligned (`test_schema_version_matches_package_version`).

### Update in lockstep

When changing the schema:

1. `meaf/schema/meaf-1.1.0.schema.json` (or new version file for a major bump)
2. `meaf/__init__.py` — `SCHEMA_VERSION` and `__version__` if releasing
3. `meaf/examples/covert-influence.json` — reference package
4. `meaf/test_meaf.py` — version and validation tests
5. `README.md` — object model section if user-facing fields change

If L1 is insufficient, add semantic checks in `validator.py` (L3/L5/L6).

---

## 7. Extension walkthrough D: write a test runner in another language

Runner contract is implemented in `meaf/testpack.py` (`run_test_subprocess`, `_parse_runner_output`). It is language-agnostic.

### Subprocess rules

- `runner.command`: argv list for `subprocess.run`.
- Exit code must be `0` for the harness to parse stdout; non-zero, timeout, or `OSError` → `indeterminate`.
- stdout must be one JSON object: `{"result": "pass|fail|indeterminate", "metrics": {<name>: <number>, ...}}`.
- Unknown `result` values are coerced to `indeterminate`.
- Non-numeric metric values are dropped; missing metrics in decision-rules → `indeterminate`.

### Declare in a test object

```json
"runner": {
  "command": ["bash", "path/to/runner.sh"],
  "timeout-seconds": 60,
  "working-directory": "optional/relative/cwd"
}
```

`working-directory` is optional; default cwd is the caller's cwd (`Path.cwd()` in CLI `run-tests`).

### POSIX shell example (`runner.sh`)

```sh
#!/bin/sh
printf '%s\n' '{"result":"pass","metrics":{"containment-latency-seconds":120,"unreviewed-recommendations":0}}'
```

Executed output (verified on this repo's environment):

```
{"result":"pass","metrics":{"containment-latency-seconds":120,"unreviewed-recommendations":0}}
```

Wire for `test-containment-playbook-001` style metrics:

```json
"runner": {
  "command": ["bash", "meaf/examples/runners/containment_drill.sh"],
  "timeout-seconds": 30
}
```

### Node.js example (`runner.mjs`)

```javascript
#!/usr/bin/env node
const payload = {
  result: "pass",
  metrics: {
    "containment-latency-seconds": 120,
    "unreviewed-recommendations": 0,
  },
};
console.log(JSON.stringify(payload));
```

Executed output (Node.js v24.5.0 on this environment):

```
{"result":"pass","metrics":{"containment-latency-seconds":120,"unreviewed-recommendations":0}}
```

### Exit-code and indeterminate rules

| Runner outcome | `runner_result` | Evidence `result` (after contract rules) |
|----------------|-----------------|------------------------------------------|
| exit 0, valid JSON, metrics satisfy rules | `pass` | `pass` (or `fail` if rule fails) |
| exit 0, metric violates `-max`/`-min` rule | `pass` | `fail` |
| exit non-zero, timeout, bad JSON | `indeterminate` | `indeterminate` |
| missing metric for a rule | rule → `indeterminate` | `indeterminate` |

Never map `indeterminate` to `pass` or `fail` in runner code. The harness enforces this in `_combine_results` and `execute_test`.

Reference Python runner: `meaf/examples/runners/counterfactual_symmetry.py`.

---

## 8. Extension walkthrough E: add a lifecycle state or guard

### Transition table

`LEGAL_TRANSITIONS` in `meaf/lifecycle.py`:

```python
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"validated"}),
    "validated": frozenset({"assessed"}),
    "assessed": frozenset({"authorized", "draft"}),
    "authorized": frozenset({"degraded", "suspended", "retired"}),
    "degraded": frozenset({"authorized", "suspended"}),
    "suspended": frozenset({"assessed", "retired"}),
    "retired": frozenset(),
}
```

States: `STATES` frozenset in the same file.

### How guards are evaluated

`check_transition_guard(package, from_state, to_state, now=..., keyring=..., root=...)` returns `(granted: bool, reason: str)`.

`attempt_transition` calls the guard; on refusal returns `TransitionResult(granted=False, reason=guard_reason)` without mutating lifecycle.

### Containment transitions are never gated

```147:148:meaf/lifecycle.py
    if to_state == "suspended" and from_state in ("authorized", "degraded"):
        return True, "containment transition always permitted"
```

Do not add guards that block `authorized → suspended` or `degraded → suspended`.

### Add a new guard

Example: block `assessed → authorized` when a new policy field is missing — add a branch in `check_transition_guard` before the final `return True, "transition permitted"`:

```python
    if from_state == "assessed" and to_state == "authorized":
        # existing checks...
        if not package.get("system", {}).get("my-new-field"):
            return False, "system.my-new-field required for authorization"
```

### Test granted and refused paths

Granted path pattern: `test_lifecycle_legal_transitions_granted`.

Refused path pattern: `test_lifecycle_illegal_transitions_refused`:

```python
    granted, reason = check_transition_guard(
        package, "draft", "authorized", now=FROZEN_NOW
    )
    assert not granted
    assert "not legal" in reason
```

For a new guard refusal, assert `not granted` and a stable substring in `reason` (human-readable reasons are not API-stable, but tests in this repo match substrings like `"not legal"` and `"no degradation trigger"`).

---

## 9. The OSCAL export

Implementation: `meaf/oscal.py`. Entry point: `export_oscal(package, out_dir)`.

### Structure

`EXPORT_FILES` maps filename to exporter function:

| File | Function |
|------|----------|
| `catalog.json` | `export_catalog` |
| `profile.json` | `export_profile` |
| `component-definition.json` | `export_component_definition` |
| `system-security-plan.json` | `export_ssp` |
| `assessment-plan.json` | `export_assessment_plan` |
| `assessment-results.json` | `export_assessment_results` |
| `plan-of-action-and-milestones.json` | `export_poam` |

Each exporter returns a dict; `export_oscal` writes `json.dumps(payload, indent=2, sort_keys=True) + "\n"`.

### Deterministic UUIDs

```python
def meaf_uuid(package_id: str, object_id: str) -> str:
    return str(uuid.uuid5(_package_namespace(package_id), object_id))
```

`_package_namespace` uses `uuid.uuid5(uuid.NAMESPACE_URL, f"meaf:{package_id}")`. No `uuid.uuid4()`, no randomness.

### `last-modified` from evidence, not wall clock

`_newest_evidence_timestamp(package)` scans `evidence[].collected-at`, takes the maximum parseable timestamp, formats as `%Y-%m-%dT%H:%M:%SZ`. If no evidence, uses `1970-01-01T00:00:00Z`. Used in `_metadata` for every OSCAL model.

### Add a new OSCAL model or field without breaking determinism

1. Add an exporter function that uses only package content and `meaf_uuid` / `_metadata`.
2. Register in `EXPORT_FILES`.
3. Do not call `datetime.now()` or random UUIDs.
4. Run `test_oscal_export_is_deterministic` (two exports to temp dirs, byte-compare all `EXPORT_FILES` keys).

MAESTRO-specific props use `_maestro_prop(name, value)` with namespace `https://cloudsecurityalliance.org/maestro`.

---

## 10. Testing practice

### Suite organization

Single file: `meaf/test_meaf.py` (27 tests). Run from repo root:

```bash
python -m pytest meaf/test_meaf.py -q
```

### Fixtures and constants

| Name | Value / role |
|------|----------------|
| `EXAMPLES` | `Path(__file__).parent / "examples"` |
| `REPO_ROOT` | `Path(__file__).parent.parent` |
| `FROZEN_NOW` | `datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)` |
| `PUBLIC_API_EXPORTS` | Expected `meaf.__all__` |
| `EXPECTED_CALLABLE_SIGNATURES` | Public function signatures |
| `ATTESTATION_RECORD_KEYS` | Keys on each attestation record |
| `FINDING_FIELD_NAMES` | `Finding` dataclass fields |
| `CANONICAL_PAYLOAD_FIXTURE` | Evidence dict + expected canonical bytes |

Use `FROZEN_NOW` whenever timestamps affect freshness or expiry.

### `tmp_path` for mutating files

Copy examples into `tmp_path` with `shutil.copytree`, mutate artifacts or packages there. See `test_attestation_drift_detected_and_validated`, `test_attest_update_repairs_drift_and_preserves_evidence_bindings`.

**Never write into `meaf/examples/`** in tests.

### Ephemeral keys in tests

```python
private_key = Ed25519PrivateKey.generate()
public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
keyring = {"test-collector:1.0.0": public_bytes}
```

See `test_ed25519_signature_round_trip`. Example keyring file: `meaf/examples/keyring.json` (public keys only).

### What a good failing test looks like

1. Start from `copy.deepcopy(load_package(EXAMPLES / "covert-influence.json"))` or minimal inline dict.
2. Make one intentional violation.
3. Call the specific function or `validate_package` with explicit `now`, `keyring`, `root` as needed.
4. Assert exact `level`, `severity`, `object_id`, and `message` strings as emitted (not substring guesses unless testing refusal reasons).
5. Assert the clean example does not fire the new finding (`test_covert_influence_validates_clean` is the baseline).

---

## 11. Measurement-validity pitfalls

Expanded guidance for anyone adding checks or runners. See also [README.md](README.md#measurement-validity-traps).

### Tautological defenses

**Symptom:** Runner oracle reuses the assurance contract claim text or the same predicate that defines ground truth.

**Why it inflates results:** The "test" cannot fail unless the claim is already false by definition.

**Avoid here:** Separate `assurance-contracts.claim` (human statement) from `tests.oracle` and runner metrics. Runners emit numeric `metrics`; `decision-rule` keys with `-max`/`-min` suffixes evaluate those metrics in `evaluate_decision_rule`.

### Scoring free-text rationale instead of operative parameters

**Symptom:** Harness grades prose fields (`justification`, `claim`, `root-cause`) instead of digests, timestamps, or metric values.

**Why it inflates results:** LLM-generated rationales can sound compliant without operative parameters changing.

**Avoid here:** `run_test_subprocess` only accepts numeric metrics in JSON. Decision rules only inspect `-max` and `-min` suffix keys against `metrics`.

### Ground-truth label leakage in evaluation harness

**Symptom:** Runner or oracle reads labels or answers from the package JSON that should be hidden during evaluation (for example threat ids embedded in test inputs that mirror expected outcomes).

**Why it inflates results:** The measurement instrument sees the answer key.

**Avoid here:** Runners should read external fixtures or generated inputs, not package fields that encode expected outcomes. Package `tests.inputs` describes the procedure; stdout `metrics` must come from execution, not from copying package claims.

### Coercing `indeterminate`

**Symptom:** Mapping subprocess failure, timeout, or missing metrics to `fail` (or `pass`).

**Why it inflates or deflates results:** Infrastructure faults become false security failures, or incomplete runs become false passes.

**Avoid here:** `_parse_runner_output` and `evaluate_decision_rule` return `indeterminate`; `_combine_results` preserves it unless `fail` is present. Guarded by `test_bad_runner_yields_indeterminate_not_fail`.

---

## 12. Debugging and common failures

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| False digest drift after clone on Windows | CRLF vs LF without normalization | Digests use `compute_digest` (CRLF→LF). Run `attest --update` only when intentionally rebinding; see README tamper walkthrough |
| `evidence signature verification failed` after `attest --update` | Expected: signatures cover old `subject-digests` in canonical payload | Re-collect and re-sign evidence; `--update` does not forge signatures |
| Stale-evidence warnings that depend on current date | `validate` uses wall-clock `now` by default | Compare with `FROZEN_NOW` in tests; pass explicit `now` in library calls |
| Lifecycle refusal with opaque reason | Guard failed in `check_transition_guard` | Read `reason` string on CLI: `Transition refused: ... (reason)` |
| `L1/L2/L3 validation errors remain` on `draft → validated` | Blocking errors at levels 1-3 | `python -m meaf validate package --json` for machine-readable findings |
| `no degradation trigger detected` on `authorized → degraded` | No drift, stale evidence, or digest change | Tamper artifact or wait for stale required evidence; see `test_lifecycle_degraded_requires_attestation_drift_when_root_supplied` |
| `signature verification was not performed` | No `--keyring` | Pass `--keyring path/to/keyring.json` or accept the single L4 warning |
| `evidence is unsigned` with keyring | Evidence object has no `signature` key | Sign with `run-tests --sign-with` or `sign_evidence` |

### Machine inspection

```bash
python -m meaf validate meaf/examples/covert-influence.json --json --keyring meaf/examples/keyring.json
python -m meaf attest meaf/examples/covert-influence.json --json
```

`validate --json` prints a JSON array of `Finding.to_dict()` objects. `attest --json` prints attestation records with keys: `component-id`, `artifact-path`, `recorded-digest`, `computed-digest`, `status`.

---

## 13. Release process

Tied to the stability contract in [README.md](README.md#stability-and-versioning).

### What forces a major bump

- Removing or renaming `meaf.__all__` exports or changing their call signatures
- Changing CLI subcommands, flags, or exit codes
- Breaking MEAF package JSON schema (`meaf-version` pattern, new required fields)
- Changing `canonical_payload` bytes or test-runner stdout contract

### Update in lockstep

1. `meaf/__init__.py` — `__version__`, `SCHEMA_VERSION`
2. `meaf/schema/meaf-<version>.schema.json` — pattern on `meaf-version`
3. `meaf/examples/covert-influence.json` — `meaf-version` field
4. `meaf/test_meaf.py` — `test_schema_version_matches_package_version`, API tests
5. `README.md` — version references
6. This guide if module map or contracts change

### Full verification

```bash
python -m pytest meaf/test_meaf.py -q
python -m meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json
python -m meaf attest meaf/examples/covert-influence.json
python -m meaf validate meaf/examples/broken.json
python -m meaf run-tests meaf/examples/covert-influence.json --test test-counterfactual-symmetry-001
```

### Tag

After verification on `main`, tag the release (for example `v1.0.0`) pointing at the commit that bumped versions.

---

## 14. Contribution checklist

Before opening a PR:

- [ ] Logic lives in a library module, not `__main__.py`
- [ ] New findings use real `level`, `severity`, `object_id`, and `message` patterns consistent with existing checks
- [ ] Checks that cannot run emit warnings (or `indeterminate` in testpack), never silent pass
- [ ] Tests use `FROZEN_NOW` when time matters; file mutations use `tmp_path`, not `meaf/examples/`
- [ ] Public API changes update `meaf.__all__` and `test_public_api_surface` only if intentional (version decision)
- [ ] Schema changes update example package and version tests if applicable
- [ ] README updated only for user-facing behavior; extension details go here

Full verification block:

```bash
python -m pytest meaf/test_meaf.py -q
python -m meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json
python -m meaf attest meaf/examples/covert-influence.json
git status --short
```

Expected clean tree aside from your intentional changes; `git status` should not show dirty files under `meaf/examples/` from tests.
