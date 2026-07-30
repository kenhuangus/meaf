# MEAF developer guide

How the implementation is put together, and how to extend it without breaking
the properties that make it worth using.

Read [OBJECT-MODEL.md](OBJECT-MODEL.md) and [CONFORMANCE.md](CONFORMANCE.md)
first. This guide assumes you know what a control implementation is and why it
is not an assurance contract.

---

## 1. Module map

```
meaf/
├── model.py        primitives: Finding, Currency, timestamps, durations,
│                   evidence_currency, index helpers. Imports nothing from meaf.
├── policy.py       policy bundle loading and typed accessors
├── packs.py        the nine standard test packs of A.7
├── contract.py     the four contract states and the gate            (model, policy)
├── attest.py       artifact digests, drift, path containment
├── signing.py      Ed25519 and conformance level 4                  (model, policy, attest)
├── validator.py    levels 1,2,3,5,6 and orchestration               (model, policy, packs,
│                                                                     contract, signing)
├── testpack.py     runner execution, rule evaluation, evidence      (model, signing, contract)
├── lifecycle.py    the A.8 state machine                            (model, policy, contract,
│                                                                     validator, attest)
├── summary.py      the eight A.5 summary dimensions                 (model, policy, contract)
├── report.py       Markdown and Mermaid projections                 (everything above)
├── oscal.py        OSCAL 1.1.2 export                               (model, contract)
├── impact.py       change-impact analysis                           (model, policy, contract)
├── adoption.py     the non-normative A.9 adoption level             (model, policy, validator)
├── migrate.py      1.0.0 to 2.0.0                                   (model)
├── __main__.py     CLI. Argument parsing and formatting only.
└── __init__.py     public API
```

### The layering rule

Dependencies point downwards in that list and never sideways or up. `model.py`
is the floor: it imports nothing else from the package, which is what lets the
validator, the contract evaluator, the signer and the lifecycle all agree on
what a `Finding` is and what currency means.

**Every import is at module scope.** There are no function-level imports
anywhere in `meaf/`, because the ordering above has no cycles to break. A
function-level import is therefore a signal, not a technique: if you need one,
the dependency you are adding points the wrong way and the code belongs at a
different layer. `python -m pyflakes meaf/*.py` and a plain `import meaf` are
enough to catch a mistake here.

### The CLI holds no logic

`__main__.py` parses arguments, calls library functions, and formats output.
Anything that decides whether a claim holds belongs in a library module, so it
can be tested without a subprocess and reused without a shell. A pull request
that puts an assurance rule in the CLI will be asked to move it.

---

## 2. How a validation runs

```python
validate_package(package, now=..., keyring=..., root=..., policy=...)
```

1. `now` is normalised to UTC. **It is injectable on purpose.** A gate result
   that depends on when the job ran is not reproducible, and level 6 is about
   reproducibility.
2. The schema is loaded and level 1 runs with a `FormatChecker`, so `format`
   keywords are actually enforced.
3. If the package is not a `dict`, return: nothing below can run.
4. Levels 2, 3, 4, 5, 6 all run, **even when level 1 failed**. A validator that
   stops at the first malformed object hides the rest of the work from the person
   fixing it.

### Structural robustness is a requirement, not a nicety

Levels 2 through 6 receive arbitrary input. They must never raise. The discipline
that makes this hold:

- Iterate collections with `model.objects(package, "name")`, which tolerates a
  non-dict package, a missing collection, a collection that is not a list, and
  drops non-dict members.
- Read fields with `.get()`, never `[]`.
- Guard the type before using a value: `if isinstance(value, str)`.

`tests/test_validator.py` deletes each required field of each object type in
turn and asserts no call raises. Add to that loop when you add an object type.

### Severity model

| Situation | Severity |
|---|---|
| A check ran and the package violated it | `error` |
| A check **could not run** | `warning`, always. Never a silent pass |
| A condition that is informational at this level but consequential at another | `warning` here, `error` there |

The third row is why evidence past its validity window is a level 4 warning and a
level 5 error: `validate` output should distinguish "this aged out" from "the
claim it supports therefore failed".

---

## 3. Core invariants

Do not break these. Each names the test that guards it.

| Invariant | Why | Guard |
|---|---|---|
| `indeterminate` is never coerced to `pass` or `fail` | Confuses "could not measure" with success or violation | `test_contract_states.py`, `test_testpack.py` |
| A check that cannot run warns; it never silently passes | An unrunnable check is indistinguishable from a passing one in the output | `test_signing.py` |
| Unsigned is structurally distinct from invalid | Different problems, different responses | `test_signing.py` |
| Signature `key-id` equals the evidence `collector` | Otherwise one keyring holder can sign as every collector | `test_signing.py` |
| Artifact binding is a conjunct of currency | A.5: binding takes precedence over calendar freshness | `test_model.py` |
| `attest --update` rebinds digests and never evidence bindings | Rewriting them would let old evidence claim to be about the new artifact | `test_attest.py` |
| Digests are the plain hash of the artifact bytes | `sha256:<hex>` must actually be the SHA-256 of the file | `test_attest.py` |
| Every legal transition has a registered guard | The original defect let `degraded -> authorized` through unguarded | `test_lifecycle.py` |
| Containment transitions are never gated | A containment control a stale package can block is not one | `test_lifecycle.py` |
| The summary contains no aggregate score | A.5 refuses one, for a good reason | `test_summary.py` |
| Exports and reports are deterministic | Diffable in review; reproducible across evaluators | `test_oscal.py`, `test_report.py` |
| `meaf.__all__` is exact | API stability contract | `test_public_api.py` |
| The shipped examples are reproducible from the demo seed | A hand-edited example that forgot to re-sign would otherwise ship | `test_examples.py` |

---

## 4. Adding a conformance check

Decide the level first, using A.5's own definitions:

| Level | Answers |
|---|---|
| 1 | Is it well-formed? |
| 2 | Does every reference resolve to exactly one object? |
| 3 | Is it internally coherent — layers, ordering, timestamps, roles, exceptions? |
| 4 | May this observation be believed? |
| 5 | Does the organisation's policy permit this state? |
| 6 | Would a second evaluator get the same answer? |

Then:

1. Write the check as a private function in `validator.py` taking the package
   (and `now` or `policy` if needed) and returning `list[Finding]`. Use the
   `_error` / `_warning` helpers.
2. Call it from the level's aggregator.
3. Write the test **first**, with a fixture that isolates the violation — deep
   copy `covert` and mutate one field. A test that needs a bespoke 200-line
   package is testing too much at once.
4. If the check encodes an organisational choice rather than a framework rule,
   it belongs in the policy bundle, not in Python. Add the key to
   `meaf-policy-2.0.0.schema.json`, an accessor to `Policy`, and read it in the
   check.

The last point is the one people get wrong. "Evidence must be less than 30 days
old" is a policy. "Evidence must be bound to the deployed artifact" is the
framework.

---

## 5. Adding a lifecycle state or transition

1. Add the state to `STATES` and its outgoing edges to `LEGAL_TRANSITIONS`.
2. Add a guard function and register it in `GUARDS` for **every** new pair.
   `test_lifecycle.py` asserts `set(GUARDS) == every pair in LEGAL_TRANSITIONS`,
   so an unregistered pair fails the suite rather than inheriting a permissive
   default. That test exists because the original implementation ended in a bare
   `return True` and let a degraded package return to service with no evidence.
3. A guard returns `(granted, reason)`. The reason is user-facing and shows up in
   lifecycle history; write it as a sentence a reviewer would accept.
4. Guards receive a `GuardContext` with the package, `now`, policy, keyring and
   root. Do not read the clock inside one.
5. Test both the granted and the refused path, and assert the refusal reason.

---

## 6. Extending the schema

Additive changes — a new optional field, a new enum member, a new component type
— are minor. Anything that can make a previously valid package invalid is major:
a new required field, a removed enum member, a tightened pattern.

Update in lockstep:

1. `meaf/schema/meaf-2.0.0.schema.json`
2. `meaf/__init__.py` (`__version__`, `SCHEMA_VERSION`)
3. Both example packages, then `python meaf/examples/tools/regenerate.py`
4. `tests/test_object_model.py` if the change touches the manuscript's object model
5. `docs/OBJECT-MODEL.md`
6. `meaf/migrate.py` if a package from the previous version needs converting
7. `README.md` version references

`tests/test_object_model.py` transcribes the manuscript rather than the schema,
so a schema edit that diverges from appendix A.2 or A.3 fails there. If you
believe the manuscript is wrong, that is a conversation to have before changing
the schema, not after.

---

## 7. Writing a runner in another language

The contract is a subprocess that writes one JSON object to stdout and exits 0.
Nothing else is required — no library, no import, no Python.

```sh
#!/bin/sh
printf '{"result":"pass","metrics":{"unreviewed-recommendations":0}}\n'
```

Rules:

- Exit non-zero, time out, or print anything unparseable, and the result is
  `indeterminate`. Never exit non-zero to signal a security failure; report
  `{"result": "fail"}` and exit 0.
- Write diagnostics to stderr or to the `diagnostics` member. Stdout must be
  exactly one JSON object.
- Report every metric your contract's `decision-rule` names. A missing metric is
  `indeterminate`, not a pass.
- If the test is adversarial, report `utility-metrics` too.
- If the test declares `evidence-class: probabilistic-inference`, return
  `model-metadata` with every field A.5 requires.
- A leading `python` or `python3` in `runner.command` is rewritten to the
  interpreter running MEAF. Anything else is executed as given, resolved from the
  package file's directory.
- A runner invoking `sh -c` produces a level 6 warning: the executed command is
  not pinned by the package.

---

## 8. The pilot end to end

A.9 says success is not a valid JSON document but a demonstrated loop. This
sequence runs it, and CI runs a version of it on every push.

```bash
NOW=2026-07-28T12:00:00Z
cp -r meaf/examples /tmp/demo && cd /tmp/demo

# 1. Author and validate
meaf validate covert-influence.json --keyring keyring.json --now $NOW

# 2. Assess: run the test pack, link the evidence, create findings from failures
# Exits 1: test-containment-playbook-001 declares no runner, and a test that was
# never executed must not look like a test that passed.
meaf run-tests covert-influence.json --now $NOW \
  --link-evidence --create-findings --output assessed.json

# 3. Authorize
meaf lifecycle assessed.json --to validated --actor role-ai-assurance-lead --now $NOW --output s1.json
meaf lifecycle s1.json --to assessed  --actor role-ai-assurance-lead --now $NOW --output s2.json
meaf lifecycle s2.json --to authorized --actor role-assurance-review-board --now $NOW --output s3.json

# 4. Monitor: what would a model change cost?
meaf impact s3.json --changed cmp-foundation-model --now $NOW

# 5. A real change arrives
printf '\n' >> artifacts/model-card.json
meaf attest s3.json                                    # drift; exits 1
meaf lifecycle s3.json --to degraded --actor role-incident-response-lead --now $NOW --output s4.json

# 6. Recover, and observe that returning to service is guarded
meaf lifecycle s4.json --to authorized --actor role-assurance-review-board --now $NOW  # refused; exits 1
```

Three commands in that sequence exit non-zero, and all three are meant to: an
unrun test, a drifted artifact, and a refused return to service. A pipeline that
treats any of them as success has switched the framework off.

---

## 9. Testing practice

- **Time is injected.** Use `FROZEN_NOW` from `tests/conftest.py` wherever
  freshness, expiry or currency matters. A test whose result changes with the
  calendar is not a test.
- **The shipped examples are never mutated.** Use the `example_tree` fixture,
  which copies `meaf/examples` into `tmp_path`. `test_examples.py` asserts the
  real tree is unmodified after the whole run.
- **Build negative fixtures by mutating a deep copy** of `covert` or `memory`,
  not by writing a large JSON literal inline. The mutation is the test's
  subject; everything else is noise.
- **One behaviour per test**, with a name that is a sentence. Use
  `pytest.mark.parametrize` for tabular cases.
- **Ephemeral keys.** Generate an `Ed25519PrivateKey` in the test. The only
  committed key is the published demo seed, which exists so the examples are
  reproducible and proves nothing about anything.

```bash
pytest -q                                        # the suite
pytest --cov=meaf --cov-branch --cov-report=term-missing
pytest tests/test_contract_states.py -q          # one module
python meaf/examples/tools/regenerate.py --check # examples still canonical
```

---

## 10. Measurement-validity traps

These are the ways an assurance framework lies to you. The implementation
resists each one; do not reintroduce them.

**Tautological defences.** A control that refuses every contested topic scores
perfectly on symmetry. That is why adversarial tests must report benign-task
utility, and why meeting security while missing utility reports `fail`.

**Coercing indeterminate.** The single most tempting change in this codebase is
to make a missing metric count as a pass so a pipeline goes green. Every layer
refuses: the runner, the contract state, the gate, and the lifecycle guard.

**Scoring the rationale instead of the parameter.** An evaluator that reads a
control's *description* and judges it well-written has measured prose. Evidence
must bind to artifact digests, and a claim's subject must resolve to a component
or the system.

**Ground-truth leakage.** A test harness that can see the labels it is scoring
will report excellent detection. Keep the oracle and the sampling plan in the
package where a reviewer can see them, and pin the pack version.

**Aggregate scores.** A single number hides which of the eight summary
dimensions is weak. There is a test that fails if one appears.

---

## 11. Release process

A major bump is forced by any of:

- removing or renaming a `meaf.__all__` export, or changing its signature;
- changing a CLI subcommand, flag, or exit code;
- a breaking schema change;
- changing `canonical_payload` bytes or the runner stdout contract.

Update in lockstep, then verify:

```bash
pytest -q
python meaf/examples/tools/regenerate.py --check
meaf validate meaf/examples/covert-influence.json --keyring meaf/examples/keyring.json --now 2026-07-28T12:00:00Z
meaf validate meaf/examples/memory-poisoning.json --keyring meaf/examples/keyring.json --now 2026-07-28T12:00:00Z
meaf validate meaf/examples/broken.json --now 2026-07-28T12:00:00Z   # must exit 1
meaf attest   meaf/examples/covert-influence.json
git status --porcelain                                                # must be empty
```

Then tag the commit that bumped the versions.

---

## 12. Contribution checklist

- [ ] Logic lives in a library module, not `__main__.py`
- [ ] New checks use the right conformance level and the right severity
- [ ] A check that cannot run emits a warning, never a silent pass
- [ ] Organisational choices went into the policy bundle, not into Python
- [ ] Tests use `FROZEN_NOW`; file mutations use `example_tree` or `tmp_path`
- [ ] New lifecycle pairs are registered in `GUARDS`
- [ ] Schema changes updated the examples, the object-model test, and the docs
- [ ] `git status --porcelain` is empty after the full suite
