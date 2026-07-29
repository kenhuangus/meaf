# MEAF Pilot

MEAF (MAESTRO Executable Assurance Framework) is a machine-readable assurance layer over the Cloud Security Alliance MAESTRO seven-layer agentic-AI threat taxonomy. A MEAF package links a declared system boundary to components, threats, attack paths, assurance contracts, tests, evidence, findings, and gate decisions in one JSON artifact. Evidence and decisions reference component digests, so when a deployed artifact changes, stale assurance claims are detectable and lifecycle state can degrade.

This repository is a pilot implementation, not a certification tool. It evaluates whether claims about a declared system boundary are internally consistent, backed by evidence, and still bound to the artifacts on disk. It does not certify that an agent is safe.

## Install and quickstart

Requires Python 3.10 or newer (tested on Python 3.13). From the repository root:

```bash
pip install -r requirements.txt
python -m meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json
python -m meaf attest meaf/examples/covert-influence.json
python -m meaf run-tests meaf/examples/covert-influence.json
python -m meaf lifecycle meaf/examples/covert-influence.json --to validated --actor reviewer --reason "L1-L3 clean" --output /tmp/validated-package.json --keyring meaf/examples/keyring.json
```

The last command writes the transitioned package to a new path, leaving the shipped example untouched. Point `--output` at the package file itself to persist state in place, or omit it to inspect transitions without writing anything.

## Repository layout

```
meaf-repo/
├── README.md                          # This document
├── requirements.txt                   # Python dependencies (cryptography, jsonschema, pytest)
├── .gitignore                         # Ignores __pycache__, *.pem, *.key, .pytest_cache/
├── meaf/
│   ├── __init__.py                    # Package version string
│   ├── __main__.py                    # CLI entry point (python -m meaf)
│   ├── validator.py                   # Conformance levels L1-L6
│   ├── signing.py                     # Ed25519 evidence signing and L4 checks
│   ├── attest.py                      # Artifact digest attestation
│   ├── testpack.py                    # Test runner execution and evidence emission
│   ├── lifecycle.py                   # Package lifecycle state machine
│   ├── oscal.py                       # OSCAL 1.1.2 export
│   ├── test_meaf.py                   # Pytest suite (23 tests)
│   ├── schema/
│   │   └── meaf-0.1.0.schema.json     # JSON Schema for package structure
│   └── examples/
│       ├── covert-influence.json      # Complete reference package
│       ├── broken.json                # Intentionally invalid package for error demos
│       ├── keyring.json               # Public Ed25519 keys for example evidence
│       ├── artifacts/
│       │   ├── model-card.json        # Foundation-model artifact bound to cmp-foundation-model
│       │   └── corpus-manifest.json   # Corpus artifact bound to cmp-rag-corpus
│       └── runners/
│           └── counterfactual_symmetry.py  # Example test-pack runner
```

## Concepts and object model

A MEAF package contains nine linked object types. Each type has required fields defined in `meaf/schema/meaf-0.1.0.schema.json`.

### system

Declares the assurance boundary: who owns the system, where it runs, and what matters.

Required fields: `id`, `owner`, `deployment`, `environment`, `data-classes`, `users`, `trust-boundaries`, `critical-outcomes`.

### components

Deployable artifacts inside the boundary. Each component carries a content digest and optional `artifact-path` for on-disk attestation.

Required fields: `id`, `type`, `artifact-id`, `digest`, `provenance-evidence`.

`type` must be one of: `foundation-model-service`, `retrieval-collection`, `adapter`, `prompt`, `agent-graph`, `tool`, `dataset`, `policy`.

### threats

MAESTRO-aligned threat objects tied to an attack path and temporal profile.

Required fields: `id`, `actor`, `capabilities`, `attack-classes`, `objective`, `entry-layers`, `path`, `affected-stakeholders`, `outcomes`, `temporal-profile`.

`temporal-profile` requires: `persistence`, `activation-latency`, `exposure-unit`, `compounding-rule`, `dormancy`, `detection-horizon`, `reversibility`, `recovery-objective`.

### attack-paths

Ordered MAESTRO layer nodes (`L1` through `L7`) connected by flow edges.

Required fields: `id`, `nodes`, `edges`.

`nodes` entries must match `^L[1-7]:[a-z0-9][a-z0-9-]*$`. `edges` must be one of: `data-flow`, `control-flow`, `trust-flow`, `privilege-flow`, `memory-flow`, `evidence-gap`.

### assurance-contracts

Claims about what must hold, which test evaluates them, and what evidence is required.

Required fields: `id`, `claim`, `subject`, `threats`, `function`, `interruption-point`, `interruption-type`, `test`, `decision-rule`, `required-evidence`, `cadence`, `failure-action`, `owner`.

`function`: `prevent`, `detect`, `contain`, or `recover`.

`interruption-type`: `blocks`, `detects`, `limits`, `contains`, `restores`, or `supports-investigation`.

### tests

Executable test definitions. A `runner` object is optional in the schema but required for `run-tests` execution.

Required fields: `id`, `procedure`, `target`, `inputs`, `oracle`, `metrics`, `thresholds`, `sampling-plan`, `expected-result`, `test-pack-version`.

### evidence

Observations or inferences bound to artifact digests.

Required fields: `id`, `class`, `subject-digests`, `method`, `collector`, `collected-at`, `max-age`, `invalidated-at`, `result`.

`class`: `deterministic-observation` or `probabilistic-inference` (the latter also requires `model-metadata`).

`result`: `pass`, `fail`, or `indeterminate`.

Optional: `signature`, `model-metadata`.

### findings

Records of failed claims with remediation tracking.

Required fields: `id`, `failed-claim`, `severity`, `affected-paths`, `root-cause`, `corrective-action`, `due-date`, `retest-reference`.

### decisions

Human gate decisions authorizing residual risk.

Required fields: `id`, `gate-decision`, `policy-used`, `decision-maker`, `residual-risk`, `scope`, `justification`, `expiry`, `compensating-controls`.

### Two design ideas

**Claims are separate from evidence.** An assurance contract states a claim and points to evidence objects. Evidence carries a `result` (`pass`, `fail`, or `indeterminate`) but does not by itself authorize deployment. Findings link failed evidence back to contracts; decisions record explicit human approval.

**Assurance follows the deployed artifact.** Components record `digest` values. Evidence lists `subject-digests` tying observations to specific artifact versions. When files on disk no longer match recorded digests, attestation reports drift and L4 validation fails. Lifecycle can transition from `authorized` to `degraded`.

### Evidence classes and interruption types

**Evidence classes**

| Class | Meaning |
|-------|---------|
| `deterministic-observation` | Repeatable measurement with a fixed procedure (hash check, test-pack run). |
| `probabilistic-inference` | Model-based evaluation; requires `model-metadata` (evaluator model, threshold, calibration set, uncertainty). |

**Interruption types enforced on attack paths (L3)**

Each attack path referenced by a threat must have contracts covering detection and containment:

| Type | Role |
|------|------|
| `blocks` | Prevents the attack step from succeeding. |
| `detects` | Observes the attack step occurring or attempting. |
| `contains` | Limits blast radius after detection. |
| `restores` | Recovers to an acceptable state after containment. |

The schema also allows `limits` and `supports-investigation`; L3 path coverage specifically requires `blocks` or `detects` plus `contains` or `restores`.

## End-to-end walkthrough

The commands below were run from the repository root. Tamper and repair steps use a scratch copy under a temporary directory so the shipped example in `meaf/examples/` is never modified.

### a. Validate the shipped example

```bash
python -m meaf validate meaf/examples/covert-influence.json
```

```
L4:
  [warning] (unknown): signature verification was not performed
  [warning] ev-containment-drill-2026-07: evidence has empty subject-digests
Summary: 0 error(s), 2 warning(s).
```

Exit code `0`. No errors means L1-L3 and L5-L6 pass at the current time. The two warnings are both L4:

1. **Signature verification was not performed.** Without `--keyring`, the validator skips Ed25519 checks and emits this single warning.
2. **Empty subject-digests on containment drill evidence.** `ev-containment-drill-2026-07` is system-level drill evidence not bound to a specific component digest. This is a warning, not an error.

### b. Validate with `--keyring`

```bash
python -m meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json
```

```
L4:
  [warning] ev-containment-drill-2026-07: evidence has empty subject-digests
Summary: 0 error(s), 1 warning(s).
```

The signature warning disappears. With a keyring, L4 verifies each evidence object's Ed25519 signature against the collector `key-id`. All four signed evidence items in the example package verify successfully. This proves the evidence payloads were signed by holders of the corresponding private keys; it does not prove the underlying security property being claimed.

### c. Attest artifacts

```bash
python -m meaf attest meaf/examples/covert-influence.json
```

```
cmp-foundation-model: match (artifact-path=meaf/examples/artifacts/model-card.json, recorded=sha256:ae985607ebe5646f87c980036234a25e59a5f4b4ce878e166a0425c51347063b, computed=sha256:ae985607ebe5646f87c980036234a25e59a5f4b4ce878e166a0425c51347063b)
cmp-rag-corpus: match (artifact-path=meaf/examples/artifacts/corpus-manifest.json, recorded=sha256:976b50df35f49bb58502a1f3a8dc18dab63d1c5375478518a378a8e4505d3283, computed=sha256:976b50df35f49bb58502a1f3a8dc18dab63d1c5375478518a378a8e4505d3283)
```

Exit code `0`. Attestation compares each component's recorded `digest` to `sha256:<hex>` computed from the file at `artifact-path` (resolved relative to the repo root). A match means the files on disk are the same bytes the package claims. It does not prove the files are benign, complete, or unchanged since evidence was collected; it only proves consistency right now.

### d. Run tests

```bash
python -m meaf run-tests meaf/examples/covert-influence.json
```

```
Test test-counterfactual-symmetry-001: runner=pass
  Contract ac-epistemic-integrity-001: pass
{
  "id": "ev-testpack-test-counterfactual-symmetry-001-20260729T014203Z",
  "class": "deterministic-observation",
  "subject-digests": [
    "sha256:ae985607ebe5646f87c980036234a25e59a5f4b4ce878e166a0425c51347063b"
  ],
  "method": "test-pack-execution",
  "collector": "meaf-testpack:0.1.0",
  "collected-at": "2026-07-29T01:42:03Z",
  "max-age": "P30D",
  "invalidated-at": null,
  "result": "pass"
}
```

Exit code `0`. Only tests with a `runner` field execute. The runner subprocess must exit `0` and print a JSON object on stdout (see [Writing a test runner](#writing-a-test-runner)). The harness evaluates linked assurance-contract `decision-rule` keys against runner metrics, combines results, and prints a new evidence object. Use `--output` to merge evidence into a package file; use `--sign-with` to attach an Ed25519 signature.

### e. Lifecycle: draft through authorized

The example package starts in `draft` (no `lifecycle` field defaults to `draft`).

```bash
python -m meaf lifecycle meaf/examples/covert-influence.json
```

```
Current state: draft
Legal next states: validated
Guarded transitions: validated
```

**draft -> validated.** Guard: no L1/L2/L3 errors.

```bash
python -m meaf lifecycle meaf/examples/covert-influence.json \
  --to validated --actor reviewer --reason "L1-L3 clean" \
  --output /tmp/meaf-walk-validated.json \
  --keyring meaf/examples/keyring.json
```

```
Transition granted: draft -> validated (syntactic, referential, and semantic validation passed)
```

**validated -> assessed.** Guard: every assurance contract has at least one resolving `required-evidence` entry; no evidence with `result: fail`.

```bash
python -m meaf lifecycle /tmp/meaf-walk-validated.json \
  --to assessed --actor assessor --reason "contracts have evidence" \
  --output /tmp/meaf-walk-assessed.json \
  --keyring meaf/examples/keyring.json
```

```
Transition granted: validated -> assessed (all contracts have resolving evidence and no failures)
```

**assessed -> authorized.** Guard: no errors at conformance levels 1-5; a decision with `approve` in `gate-decision`; all contract `required-evidence` is fresh.

```bash
python -m meaf lifecycle /tmp/meaf-walk-assessed.json \
  --to authorized --actor board --reason "approval gate satisfied" \
  --output /tmp/meaf-walk-authorized.json \
  --keyring meaf/examples/keyring.json
```

```
Transition granted: assessed -> authorized (all authorization guards satisfied)
```

Use `--output` pointing at the package file itself to persist transitions in place.

### f. Tamper: drift detection and degradation

The following uses `$TEMP/meaf-walkthrough/` as a scratch tree (same layout as the repo, package advanced to `authorized`). Appending a newline to `model-card.json` simulates an undeclared artifact change.

```bash
# After tampering model-card.json in the scratch copy:
python -m meaf attest $TEMP/meaf-walkthrough/meaf/examples/covert-influence.json \
  --root $TEMP/meaf-walkthrough
```

```
cmp-foundation-model: drift (artifact-path=meaf/examples/artifacts/model-card.json, recorded=sha256:ae985607ebe5646f87c980036234a25e59a5f4b4ce878e166a0425c51347063b, computed=sha256:3002f13fbc553748acac95f88cff83e0b6704b241f13d8f9d3851b147b82f7db)
cmp-rag-corpus: match (artifact-path=meaf/examples/artifacts/corpus-manifest.json, recorded=sha256:976b50df35f49bb58502a1f3a8dc18dab63d1c5375478518a378a8e4505d3283, computed=sha256:976b50df35f49bb58502a1f3a8dc18dab63d1c5375478518a378a8e4505d3283)
```

Exit code `1`.

```bash
python -m meaf validate $TEMP/meaf-walkthrough/meaf/examples/covert-influence.json \
  --keyring $TEMP/meaf-walkthrough/meaf/examples/keyring.json
```

```
L4:
  [warning] ev-containment-drill-2026-07: evidence has empty subject-digests
  [error] cmp-foundation-model: artifact digest drift: cmp-foundation-model
Summary: 1 error(s), 1 warning(s).
```

Exit code `1`. This is the core design payoff: evidence and contracts still claim the old digest, but the deployed file has changed. Assurance attached to the prior artifact version is no longer valid.

```bash
python -m meaf lifecycle $TEMP/meaf-walkthrough/meaf/examples/covert-influence.json \
  --to degraded --actor monitor --reason "artifact drift detected" \
  --output $TEMP/meaf-walkthrough/meaf/examples/covert-influence.json \
  --keyring $TEMP/meaf-walkthrough/meaf/examples/keyring.json
```

```
Transition granted: authorized -> degraded (bound artifact digest changed)
```

Without attestation drift (or stale required evidence), the same transition is refused with `no degradation trigger detected`.

### g. Repair with `attest --update`

```bash
python -m meaf attest $TEMP/meaf-walkthrough/meaf/examples/covert-influence.json \
  --update --root $TEMP/meaf-walkthrough
```

```
cmp-foundation-model: sha256:ae985607ebe5646f87c980036234a25e59a5f4b4ce878e166a0425c51347063b -> sha256:3002f13fbc553748acac95f88cff83e0b6704b241f13d8f9d3851b147b82f7db (2 evidence subject-digest(s) updated)
```

```bash
python -m meaf attest $TEMP/meaf-walkthrough/meaf/examples/covert-influence.json \
  --root $TEMP/meaf-walkthrough
```

```
cmp-foundation-model: match (artifact-path=meaf/examples/artifacts/model-card.json, recorded=sha256:3002f13fbc553748acac95f88cff83e0b6704b241f13d8f9d3851b147b82f7db, computed=sha256:3002f13fbc553748acac95f88cff83e0b6704b241f13d8f9d3851b147b82f7db)
cmp-rag-corpus: match (...)
```

Exit code `0`. `--update` rewrites component `digest` values and replaces matching entries in evidence `subject-digests`. Attestation is clean again. Evidence Ed25519 signatures were computed over the previous payloads (including old digests), so `validate --keyring` will report `evidence signature verification failed` until evidence is re-collected and re-signed. That is expected: digest repair updates bindings but does not forge new signatures.

### h. Export OSCAL

```bash
python -m meaf export-oscal meaf/examples/covert-influence.json --out-dir /tmp/meaf-oscal-out
```

```
/tmp/meaf-oscal-out/catalog.json
/tmp/meaf-oscal-out/profile.json
/tmp/meaf-oscal-out/component-definition.json
/tmp/meaf-oscal-out/system-security-plan.json
/tmp/meaf-oscal-out/assessment-plan.json
/tmp/meaf-oscal-out/assessment-results.json
/tmp/meaf-oscal-out/plan-of-action-and-milestones.json
```

Exit code `0`. Seven OSCAL 1.1.2 JSON files with deterministic UUIDs derived from `package-id` and object ids.

## Build on it: authoring your own package

Start from `meaf/examples/covert-influence.json`. Change these first:

1. **`package-id` and `system`** to describe your boundary.
2. **`components`** with real `artifact-path` files and digests from `python -c "from meaf.attest import compute_digest; from pathlib import Path; print(compute_digest(Path('your/file')))"`.
3. **`threats` and `attack-paths`** for your MAESTRO-aligned scenarios.
4. **`assurance-contracts`** linking threats to tests and required evidence.
5. **`tests`** with `runner` commands once you have executable checks.
6. **`evidence`** collected from real runs (or emitted by `run-tests`).
7. **`decisions`** with an approval `gate-decision` before targeting `authorized`.

Minimum viable package: all schema-required top-level keys, at least one component with attested artifact, one threat with a layer-ordered attack path, contracts covering detect and contain interruption types on that path, one test with a runner, evidence resolving contract `required-evidence`, and an approval decision for authorization.

### Failure output example

`meaf/examples/broken.json` is a deliberately invalid package. Running validate shows errors at multiple conformance levels:

```bash
python -m meaf validate meaf/examples/broken.json
```

```
L1:
  [error] components/0/digest: 'not-a-valid-digest' does not match '^(sha256:[a-f0-9]{64}|sha256:REPLACE_WITH_[A-Z0-9_]+)$'
  [error] components/0/type: 'invalid-component-type' is not one of ['foundation-model-service', 'retrieval-collection', 'adapter', 'prompt', 'agent-graph', 'tool', 'dataset', 'policy']
  [error] evidence/0: 'model-metadata' is a required property
  [error] evidence/0/signature: 'sig:broken' is not of type 'object'
  [error] meaf-version: '99.0.0' does not match '^0\\.1\\.0$'
L2:
  [error] path-broken-001: duplicate id in attack-paths (2 objects)
  [error] thr-broken-001: dangling reference path='path-missing' (no attack-paths with that id)
  ...
L3:
  [error] path-broken-001: attack-path nodes not layer-ordered: 'L3:upstream-node' precedes a higher layer
  ...
Summary: 19 error(s), 3 warning(s).
```

Exit code `1`.

## Writing a test runner

The test runner contract is the main extension point. It is implemented in `meaf/testpack.py`.

### Runner object

Declared on a test as `"runner": { ... }`. Required fields:

| Field | Type | Description |
|-------|------|-------------|
| `command` | array of strings | argv passed to `subprocess.run` |
| `timeout-seconds` | integer (minimum 1) | subprocess timeout |
| `working-directory` | string (optional) | cwd for the subprocess; defaults to the caller's cwd |

### Subprocess output contract

On success (exit code `0`), the subprocess must print exactly one JSON object on stdout:

```json
{"result": "pass", "metrics": {"metric-name": 0.42}}
```

Allowed `result` values: `pass`, `fail`, `indeterminate`. Any other value is coerced to `indeterminate`.

`metrics` must be a JSON object mapping names to numbers.

### Indeterminate is not fail

If the subprocess exits non-zero, times out, raises `OSError`, prints non-JSON stdout, or omits a required metric from decision-rule evaluation, the runner result is `indeterminate`, not `fail`.

Coercing `indeterminate` to `pass` would treat "measurement did not complete" as success. Coercing it to `fail` would treat infrastructure faults as security failures. Both are measurement-validity errors: they confuse "we could not measure" with "the property holds" or "the property violated."

### Decision-rule evaluation

Each assurance contract linked to the test (via `contract.test == test.id`) has a `decision-rule` object. Keys ending in `-max` require `metric <= value`; keys ending in `-min` require `metric >= value`. The metric name is the key with the suffix removed.

Example from the reference package:

```json
"decision-rule": {
  "source-inclusion-asymmetry-max": 0.1,
  "claim-support-rate-min": 0.95,
  "minimum-paired-cases": 500
}
```

Only `-max` and `-min` suffixes are evaluated. `minimum-paired-cases` is ignored by the harness (no suffix). If a rule references a metric absent from runner output, the rule result is `indeterminate`.

Final evidence `result` combines runner result with all contract rule results: any `fail` wins; else any `indeterminate` wins; else `pass`.

### Annotated example runner

`meaf/examples/runners/counterfactual_symmetry.py`:

```python
#!/usr/bin/env python3
"""Example test-pack runner for counterfactual symmetry evaluation."""

from __future__ import annotations

import json
import sys


def main() -> int:
    payload = {
        "result": "pass",
        "metrics": {
            "source-inclusion-asymmetry": 0.04,
            "claim-support-rate": 0.97,
        },
    }
    print(json.dumps(payload, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- Exit `0` so the harness reads stdout.
- Print compact JSON (not required, but conventional).
- Emit metric names matching `decision-rule` suffix conventions.
- Keep `result: pass` only when metrics satisfy thresholds; emit `fail` when they do not.

Wire it in the test object:

```json
"runner": {
  "command": ["python", "meaf/examples/runners/counterfactual_symmetry.py"],
  "timeout-seconds": 30
}
```

## Signing and key handling

### Generate an Ed25519 keypair

```python
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from meaf.signing import private_key_to_pem, public_key_to_keyring_entry

private_key = Ed25519PrivateKey.generate()
Path("collector.pem").write_bytes(private_key_to_pem(private_key))
public_entry = public_key_to_keyring_entry(private_key.public_key())
print(public_entry)  # base64 raw public key bytes
```

### Build the public keyring JSON

The keyring maps collector id strings to base64-encoded raw Ed25519 public key bytes:

```json
{
  "tool:my-collector:1.0.0": "CYajpFhDwCVUHoI9tSLEHJ+7ES0AdvIgURcDv+WWayM="
}
```

**The keyring holds PUBLIC keys only.** Never commit private keys. This repository `.gitignore` excludes `*.pem` and `*.key`.

### Sign evidence from `run-tests`

```bash
python -m meaf run-tests meaf/examples/covert-influence.json \
  --sign-with /path/to/collector.pem \
  --output updated-package.json
```

The signature `key-id` defaults to the evidence `collector` field (`meaf-testpack:0.1.0` for harness-emitted evidence).

### Verify with `validate --keyring`

```bash
python -m meaf validate updated-package.json --keyring meaf/examples/keyring.json
```

### Canonical signed payload

To interoperate with another implementation, sign and verify over the same bytes:

1. Remove the `signature` field from the evidence object.
2. Serialize with `json.dumps(unsigned, sort_keys=True, separators=(",", ":"))`.
3. Encode as UTF-8.
4. Sign or verify with Ed25519.

This matches `meaf.signing.canonical_payload()`.

## Attestation

### `artifact-path` semantics

Optional on each component. Paths are repo-root-relative POSIX strings (backslashes normalized). Resolved as `root / artifact-path` where `root` defaults to three parents above the package file (for packages under `meaf/examples/`, the repo root).

### Newline normalization

Digests are `sha256:<hex>` over file bytes with CRLF replaced by LF before hashing. Without this, Windows `git autocrlf` checkouts would change line endings and report false drift on every clone.

### Four attestation statuses

| Status | Meaning |
|--------|---------|
| `match` | Computed digest equals recorded digest. |
| `drift` | File exists but digest differs from recorded value. |
| `missing-file` | `artifact-path` set but file not found. |
| `no-artifact-path` | Component has no `artifact-path`; attestation skipped. |

### `--update` behavior

Rewrites component `digest` to the computed value for components in `drift` or `match` state. When the digest changes, every evidence `subject-digests` entry matching the old digest is updated. Does not re-sign evidence.

### Exit codes

| Code | Condition |
|------|-----------|
| `0` | Check mode: all statuses are `match` or `no-artifact-path`. Update mode: always `0`. |
| `1` | Check mode: any `drift` or `missing-file`. |

## Lifecycle

States: `draft`, `validated`, `assessed`, `authorized`, `degraded`, `suspended`, `retired`.

`retired` is terminal (no outgoing transitions). Transitions to `suspended` from `authorized` or `degraded` are never blocked (containment must not be gated).

| From | To | Guard |
|------|-----|-------|
| `draft` | `validated` | No L1/L2/L3 validation errors |
| `validated` | `assessed` | Every contract has at least one resolving `required-evidence`; no evidence with `result: fail` |
| `assessed` | `authorized` | No errors at levels 1-5; a decision with `approve` in `gate-decision`; all contract `required-evidence` fresh |
| `assessed` | `draft` | Always permitted |
| `authorized` | `degraded` | Attestation drift (when root derivable), or bound digest no longer in component inventory, or required evidence stale/invalidated |
| `authorized` | `suspended` | Always permitted (containment) |
| `authorized` | `retired` | Always permitted |
| `degraded` | `authorized` | Always permitted |
| `degraded` | `suspended` | Always permitted (containment) |
| `suspended` | `assessed` | Always permitted |
| `suspended` | `retired` | Always permitted |

Inspect current state and legal transitions:

```bash
python -m meaf lifecycle meaf/examples/covert-influence.json
```

Attempt a transition (exit `0` if granted, `1` if refused):

```bash
python -m meaf lifecycle meaf/examples/covert-influence.json \
  --to validated --actor reviewer --reason "reason text" \
  --output path/to/updated.json
```

## Conformance levels

Pass `--keyring` to `validate` to enable L4 signature checks. Without it, L4 emits one warning that signature verification was not performed.

| Level | Checks | Failure example |
|-------|--------|-----------------|
| L1 | JSON Schema syntactic validation | `'99.0.0' does not match '^0\\.1\\.0$'` |
| L2 | Referential integrity (ids resolve uniquely) | `dangling reference path='path-missing' (no attack-paths with that id)` |
| L3 | Semantic rules (layer-ordered paths, timestamps, contract coverage, freshness warnings) | `attack-path lacks assurance-contract with interruption-type blocks or detects` |
| L4 | Signature verification (with keyring), evidence digest binding, artifact attestation | `artifact digest drift: cmp-foundation-model` |
| L5 | Policy (threat coverage, failed-evidence findings, expired decisions, stale required evidence) | `threat lacks assurance-contract reference` |
| L6 | Collector version strings | `evidence collector lacks explicit version (expected name:major.minor.patch)` |

Warnings (stale evidence at L3, empty subject-digests at L4, missing artifact file at L4) do not affect the `validate` exit code. Errors do.

## CLI reference

```
python -m meaf [-h] {validate,run-tests,lifecycle,export-oscal,attest} ...
```

### `validate`

```
python -m meaf validate [-h] [--json] [--keyring KEYRING] package
```

| Flag | Description |
|------|-------------|
| `package` | Path to package JSON (positional) |
| `--json` | Emit machine-readable JSON findings array |
| `--keyring KEYRING` | Ed25519 public keyring for L4 signature verification |

### `run-tests`

```
python -m meaf run-tests [-h] [--test TEST] [--sign-with SIGN_WITH] [--output OUTPUT] package
```

| Flag | Description |
|------|-------------|
| `package` | Path to package JSON (positional) |
| `--test TEST` | Run only the test with this id |
| `--sign-with SIGN_WITH` | Ed25519 private key PEM for signing emitted evidence |
| `--output OUTPUT` | Write package with merged evidence to this path |

### `lifecycle`

```
python -m meaf lifecycle [-h] [--to TO] [--actor ACTOR] [--reason REASON] [--output OUTPUT] [--keyring KEYRING] package
```

| Flag | Description |
|------|-------------|
| `package` | Path to package JSON (positional) |
| `--to TO` | Target lifecycle state (omit to inspect only) |
| `--actor ACTOR` | Actor recorded in history (default: `unknown`) |
| `--reason REASON` | Reason recorded in history (default: empty) |
| `--output OUTPUT` | Write updated package on successful transition |
| `--keyring KEYRING` | Public keyring passed to validation guards |

### `export-oscal`

```
python -m meaf export-oscal [-h] --out-dir OUT_DIR package
```

| Flag | Description |
|------|-------------|
| `package` | Path to package JSON (positional) |
| `--out-dir OUT_DIR` | Output directory (required) |

### `attest`

```
python -m meaf attest [-h] [--root ROOT] [--update] [--json] package
```

| Flag | Description |
|------|-------------|
| `package` | Path to package JSON (positional) |
| `--root ROOT` | Repo root for `artifact-path` resolution |
| `--update` | Rewrite digests and evidence subject-digests in place |
| `--json` | Emit machine-readable JSON attestation records |

### Exit codes

| Command | `0` | `1` | other |
|---------|-----|-----|-------|
| `validate` | No errors | One or more errors | argparse failure: `2` |
| `run-tests` | Always (results printed) | | |
| `lifecycle` | Transition granted, or inspect mode | Transition refused | |
| `export-oscal` | Always | | |
| `attest` | No drift/missing-file (check mode); always (update mode) | Drift or missing-file (check mode) | |

## Library use

Importable entry points:

```python
from pathlib import Path
from datetime import datetime, timezone
from meaf.validator import load_package, validate_package, format_findings, has_errors
from meaf.attest import check_attestation, update_attestation
from meaf.testpack import run_tests
from meaf.lifecycle import attempt_transition, current_state, legal_next_states
from meaf.oscal import export_oscal
from meaf.signing import sign_evidence, verify_evidence, load_keyring
```

### `validate_package`

```python
validate_package(
    package: dict,
    *,
    now: datetime | None = None,
    schema: dict | None = None,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> list[Finding]
```

### `check_attestation`

```python
check_attestation(package: dict, root: Path) -> list[dict]
```

### `update_attestation`

```python
update_attestation(package: dict, root: Path) -> tuple[dict, list[str]]
```

### `run_tests`

```python
run_tests(
    package: dict,
    *,
    test_id: str | None = None,
    sign_with: Ed25519PrivateKey | None = None,
    now: datetime | None = None,
    cwd: Path | None = None,
) -> list[TestRunResult]
```

### `attempt_transition`

```python
attempt_transition(
    package: dict,
    to_state: str,
    *,
    actor: str = "unknown",
    reason: str = "",
    now: datetime | None = None,
    keyring: dict[str, bytes] | None = None,
    root: Path | None = None,
) -> tuple[TransitionResult, dict]
```

### `export_oscal`

```python
export_oscal(package: dict, out_dir: Path) -> list[Path]
```

### `sign_evidence` / `verify_evidence`

```python
sign_evidence(evidence: dict, private_key: Ed25519PrivateKey, *, key_id: str | None = None) -> dict
verify_evidence(evidence: dict, keyring: dict[str, bytes]) -> bool
```

### Example

```python
from pathlib import Path
from meaf.validator import load_package, validate_package, format_findings
from meaf.signing import load_keyring

root = Path(".")
package = load_package(root / "meaf/examples/covert-influence.json")
keyring = load_keyring(root / "meaf/examples/keyring.json")
findings = validate_package(package, keyring=keyring, root=root)
print(format_findings(findings))
```

## Testing

Run the full suite from the repository root:

```bash
python -m pytest meaf/test_meaf.py -q
```

Run a single test:

```bash
python -m pytest meaf/test_meaf.py::test_broken_has_errors_at_each_level -q
```

### What the 23 tests cover

| Area | Tests |
|------|-------|
| Validation | `test_covert_influence_validates_clean`, `test_broken_has_errors_at_each_level`, `test_stale_evidence_is_warning_not_error`, `test_injectable_now_changes_freshness_outcome`, `test_level5_and_level6_findings_fire`, `test_format_findings_groups_levels_4_through_6`, `test_validate_package_accepts_keyring_kwarg` |
| Evidence freshness | `test_evidence_freshness_frozen_now` |
| Signing / L4 | `test_ed25519_signature_round_trip`, `test_missing_keyring_produces_one_l4_warning`, `test_artifact_binding_unbound_digest_is_l4_error`, `test_unsigned_evidence_with_keyring_reports_unsigned_not_verify_failed` |
| Test pack | `test_counterfactual_symmetry_runner_passes`, `test_bad_runner_yields_indeterminate_not_fail`, `test_run_tests_without_sign_with_emits_no_signature` |
| Lifecycle | `test_lifecycle_legal_transitions_granted`, `test_lifecycle_illegal_transitions_refused`, `test_lifecycle_degraded_requires_attestation_drift_when_root_supplied` |
| Attestation | `test_example_artifact_digests_match_recorded_values`, `test_attestation_drift_detected_and_validated`, `test_missing_artifact_file_is_warning_not_error`, `test_attest_update_repairs_drift_and_preserves_evidence_bindings` |
| OSCAL | `test_oscal_export_is_deterministic` |

### Adding a test for a new rule

1. Add or extend a validator function in `meaf/validator.py` (or `meaf/signing.py` for L4).
2. Create a minimal package fragment in a test using `copy.deepcopy` on `covert-influence.json` or a inline dict.
3. Call `validate_package()` with `now=FROZEN_NOW` when timestamps matter (`FROZEN_NOW` is defined in `test_meaf.py`).
4. Assert on `Finding.level`, `severity`, `object_id`, and `message` strings exactly as emitted.

### Measurement-validity traps

Two issues this codebase already encountered generalize to any assurance harness:

1. **Tautological defenses.** A control evaluated by the same predicate that defines ground truth is tautologically effective. Separate the claim (contract), the measurement procedure (test/runner), and the acceptance rule (decision-rule) so the runner does not reuse the contract text as its oracle.

2. **Scoring rationale instead of parameters.** A harness that grades an action's free-text rationale rather than operative parameters (metric values, digests, timestamps) will silently inflate measured success. Runners must emit structured `metrics`; decision-rules must reference those keys, not prose fields from the package.

Check both when adding rules or runners.

## Limitations and non-goals

- **Pilot status.** Schema version `0.1.0`, API unstable, example data synthetic.
- **OSCAL export only.** No importer; round-tripping from OSCAL back into MEAF is not supported.
- **No adversarial robustness evaluation.** The framework checks package consistency and binding, not whether an agent resists attack.
- **Illustrative thresholds.** Decision-rule numbers in the example (for example `source-inclusion-asymmetry-max: 0.1`) are deployment policy placeholders, not universal safety constants.
- **No aggregate security score.** By design. A single number would hide whether weak assurance comes from missing threats, stale evidence, or explicitly accepted residual risk recorded in `decisions`.

## Provenance

This pilot implements the MEAF appendix of a research paper applying the CSA MAESTRO framework to assurance for long-running agentic systems.

External references:

- [CSA MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) (Multi-Agent Environment, Security, Threat, Risk, and Outcome)
- [NIST OSCAL](https://pages.nist.gov/OSCAL/) (Open Security Controls Assessment Language)
