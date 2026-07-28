# MEAF Pilot

MEAF (MAESTRO Executable Assurance Framework) is a machine-readable assurance layer over the Cloud Security Alliance MAESTRO 7-layer agentic-AI threat taxonomy. Packages link system boundaries, components, threats, attack paths, assurance contracts, tests, evidence, findings, and gate decisions into a single verifiable artifact.

## Validate a package

```bash
pip install -r requirements.txt
python -m meaf validate meaf/examples/covert-influence.json
```

With Ed25519 signature verification (public keyring only):

```bash
python -m meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json
```

Machine-readable output:

```bash
python -m meaf validate meaf/examples/covert-influence.json --json
```

Exit code `0` means no errors; `1` means one or more errors were found. Warnings do not affect the exit code.

## Attest artifacts

Check that component digests match hashed artifact files on disk:

```bash
python -m meaf attest meaf/examples/covert-influence.json
```

Rewrite recorded digests (and matching evidence `subject-digests`) when artifacts have changed:

```bash
python -m meaf attest meaf/examples/covert-influence.json --update
```

### Attestation

The example package binds each component digest to a real file under `meaf/examples/artifacts/`. Each component may declare an optional `artifact-path` (repo-root-relative POSIX path). Digests are computed over the raw file bytes with CRLF normalized to LF before hashing, so Windows checkouts with `git autocrlf` do not spuriously report drift.

## Run test packs

Execute tests that declare a `runner` and emit evidence from the results:

```bash
python -m meaf run-tests meaf/examples/covert-influence.json
```

## Lifecycle transitions

Inspect current state and legal next transitions:

```bash
python -m meaf lifecycle meaf/examples/covert-influence.json
```

Attempt a transition (writes updated package on success):

```bash
python -m meaf lifecycle meaf/examples/covert-influence.json --to validated --actor reviewer --reason "L1-L3 clean" --output /tmp/updated.json
```

## OSCAL export

Export seven OSCAL 1.1.2 JSON artifacts with deterministic UUIDs and timestamps:

```bash
python -m meaf export-oscal meaf/examples/covert-influence.json --out-dir /tmp/oscal-out
```

## Conformance levels

| Level | Scope |
|-------|-------|
| L1 | Syntactic validation against `schema/meaf-0.1.0.schema.json` |
| L2 | Referential integrity — every id-reference resolves to exactly one object |
| L3 | Semantic rules — layer-ordered attack paths, evidence timestamp coherence, persistent-threat contract coverage, high-impact-path detect+contain contracts, evidence freshness warnings |
| L4 | Evidence validity — Ed25519 signature verification (when `--keyring` supplied), artifact binding of `subject-digests` to component inventory, artifact digest attestation against `artifact-path` files |
| L5 | Policy validity — threat contract coverage, failed-evidence findings linkage, expired decisions, contracts with entirely stale required evidence |
| L6 | Reproducibility — evidence collectors carry explicit version strings (`name:major.minor.patch`) |

Pass `--keyring` to `validate` to enable L4 signature checks. Without it, L4 emits one warning that signature verification was not performed.

## Tests

```bash
python -m pytest meaf/test_meaf.py -q
```
