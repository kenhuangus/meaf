# Migrating a package from MEAF 1.0.0 to 2.0.0

2.0.0 is a breaking change. It adds required top-level members and required
fields, which the project's own release rules make a major bump.

The migration is deliberately not fully automatic. `python -m meaf migrate` does
the structural half and **omits** every field it cannot derive, so that
`validate` names the exact gaps. Each of those gaps is a risk judgment — how bad
is this attack path, does this control fail open, is this test adversarial —
and filling them with a plausible default would put a number on somebody's risk
register that nobody chose.

## Run it

```bash
python -m meaf migrate old-package.json --output new-package.json
python -m meaf validate new-package.json
```

`migrate` exits `1` while decisions remain outstanding, so it cannot pass a CI
step by accident. The list of outstanding decisions goes to standard error; the
migrated package goes to `--output` (or standard output).

## What changed

### The object model split

`assurance-contracts` in 1.0.0 carried both the mitigation and its verification.
2.0.0 separates them; see [OBJECT-MODEL.md](OBJECT-MODEL.md#the-one-distinction-that-matters).

`migrate` splits one `control-implementations` entry out of each contract,
points the contract's new `control` member at it, and moves
`interruption-point` and `interruption-type` onto the control. It cannot know
the control's `enforcement-mode` or `failure-behavior`, so it omits them.

### New required fields

| Object | Field | Why it cannot be derived |
|---|---|---|
| `system` | `responsible-roles` | Derived from existing owners and decision-makers; review the titles |
| `components` | `provider` | Nobody but you knows who supplies the artifact |
| `components` | `dependencies` | Defaults to `[]`, which asserts none; correct it if untrue |
| `threats` | `stage`, `preconditions`, `target` | New tuple positions with no 1.0.0 source |
| `attack-paths` | `impact` | A risk rating. The policy bundle keys interruption requirements off it |
| `control-implementations` | `enforcement-mode`, `failure-behavior` | Facts about the mechanism, not about the claim |
| `assurance-contracts` | `evidence-classes`, `evidence-max-age` | Derived from the required evidence: classes from their `class`, freshness from the **shortest** window among them |
| `tests` | `adversarial` | Determines whether utility thresholds are required |
| `tests` | `utility-metrics`, `utility-thresholds` | Required for adversarial tests only |
| `evidence` | `source` | The system of record |
| `decisions` | `decision-type` | Authorization, exception, or not-applicable |

### Tightened vocabularies

Free-text fields that the manuscript enumerates became enums, so two packages
can be compared:

- `temporal-profile.persistence`, `exposure-unit`, `compounding-rule`,
  `reversibility`, `dormancy` — `migrate` maps the values it recognises and
  reports the rest.
- `temporal-profile.detection-horizon` became
  `{minimum-observations, observation-period}`; `recovery-objective` became
  `{max-containment-time, max-acceptable-loss}`. Both were prose in 1.0.0 and
  cannot be parsed into quantities.
- `finding.severity` and `decision.gate-decision` became enums.
- `assurance-contract.failure-action` became the six enumerated assurance
  responses of A.3. Your 1.0.0 prose is moved to `failure-action-detail`.

### Semantics that changed underneath you

These do not show up as schema errors, so read them even if `validate` is clean.

**`artifact-path` is now relative to the package file**, not the repository root,
and is refused if it escapes that directory. Move your artifacts next to the
package, or shorten the paths.

**Runner commands resolve relative to the package file** for the same reason. A
leading `python` or `python3` is rewritten to the interpreter running MEAF, so a
bare `python` no longer fails on hosts that only ship `python3`.

**Digests are the plain hash of the artifact's bytes.** 1.0.0 normalised CRLF to
LF before hashing, so the recorded `sha256:` value was not the SHA-256 of the
file. Re-run `python -m meaf attest --update --output ...` and commit the
`.gitattributes` in this repository, which pins line endings instead.

**`attest --update` no longer rewrites evidence `subject-digests`.** It rebinds
component digests and reports which evidence has become unbound. The old
behaviour inverted the artifact-binding rule: evidence collected against the old
artifact silently claimed to be about the new one.

**Placeholder digests are gone.** `sha256:REPLACE_WITH_ATTESTED_DIGEST` was
schema-legal in 1.0.0 and passed all six levels. Use `attest --update`.

**Evidence must be re-signed.** The signed payload includes the new fields, so
every 1.0.0 signature is now invalid. This is correct: the evidence object
changed.

**`--now` is available everywhere it matters.** Pass it in CI so that a gate
result is reproducible rather than a function of when the job ran.

### New capabilities you did not have

| Command | What it gives you |
|---|---|
| `meaf gate` | The four contract states and a deployment decision under an explicit policy bundle |
| `meaf summary` | The eight conformance-summary dimensions A.5 requires |
| `meaf report` | A Markdown assurance report with attack-path diagrams, generated from the package |
| `meaf impact --changed X` | What a component change would invalidate, before you make it |
| `meaf adoption` | Where you are in the A.9 adoption sequence |
| `meaf testpacks` | The nine standard test packs |
| `--policy` | Every organisational risk choice, in a versioned file instead of in the validator's source |

## A worked migration

`meaf/examples/legacy/covert-influence-1.0.0.json` is the 1.0.0 reference
package, kept so the migration path is exercised by the test suite. Migrating it
produces the structural skeleton of `meaf/examples/covert-influence.json`: the
same boundary, threats and paths, with one control implementation split out of
each contract.

The shipped 2.0.0 example then goes further than any migration could. It adds a
`cmp-evaluator-prompt` component and its attestation, so the probabilistic
evidence can bind its evaluator prompt to a real digest; and it rewrites each
split-out control's description to describe the mechanism rather than repeating
the contract's claim, because a control that describes itself in the words of
its own proof is the confusion 2.0.0 exists to remove.

Diff the two to see both: the risk decisions the migration could not make, and
the modelling work that only a human familiar with the system can do.
