# 00 — Formal specification of the PQC assurance model

Code: [pqcheck/verdict.py](../pqcheck/verdict.py) (the model),
[pqcheck/relations/base.py](../pqcheck/relations/base.py) (the runner),
[pqcheck/target.py](../pqcheck/target.py) (the target seam).

## 1. Objects

- A **Subject** is `(target, commit, algorithm)`. The commit must be a
  concrete revision; moving references (`main`, `latest`, `HEAD`, …)
  are refused at construction.
- A **Method** names the relation that produced a claim and the
  independent oracle used, if any (`None` means the check was
  self-referential, and the report says so).
- **Coverage** is `(exercised surface, units, runner-observed calls)`.
  Units are counted only when the runner observed the calls
  (`watched.calls > 0`); a relation that claims coverage with zero
  observed calls is demoted to `NOT_REACHED`.
- A **Claim** binds subject, property, verdict, method, ceiling,
  coverage, evidence, reproduce instructions, notes, premises, and
  the `one_sided` flag.
- A **Report** is a tuple of claims. It has no score:
  `Report.score()` raises `NotImplementedError`, permanently.

## 2. The five reported outcomes

The `Verdict` enum has four members; one of them splits in reporting,
giving five honest outcomes:

| Outcome | Construction rule |
| --- | --- |
| `DEFECT_FOUND` | Property tested and violated, or a corroborated target-attributable fault/hang. Requires a non-stub `reproduce` string. |
| `NO_DEFECT_FOUND` | Property tested, runner-observed calls > 0, did not fire. Requires non-empty `Coverage`. |
| `NO_WITNESS_ESTABLISHES_NOTHING` | A one-sided relation (`kem-fo-liveness`) found no witness. Counted separately, never as clean. |
| `NOT_REACHED` | The check could not exercise the target (control failed, target unopenable, crash adjudication inconclusive). Requires evidence or notes. Never counted as clean. |
| `NOT_ANSWERABLE` | The relation does not apply to this target's API/geometry (missing capability, wrong layout). Requires an explanatory note. |

There is no `PASS` verdict, no percentage, and no grade arithmetic
anywhere in the tool. The backtest grades
([04_BACKTEST.md](04_BACKTEST.md)) are likewise never summed.

## 3. Epistemic refusal rules (unconstructible reassurance)

`Claim.__post_init__` raises `ClaimError` when:

- the verdict is a plain string instead of the `Verdict` enum;
- `property` or `ceiling` is empty — every claim must state what it
  does **not** establish;
- `NO_DEFECT_FOUND` carries no coverage or zero units;
- `DEFECT_FOUND` carries a stub reproduce string;
- `NOT_REACHED` / `NOT_ANSWERABLE` carry no explanation;
- `premises` is a bare string instead of a tuple;
- any text field contains secret-shaped material (a contiguous
  hex/base64 blob long enough to be key material). Reports must be
  safe to paste into public bug trackers; target output is passed
  through `redact_target_output` before quoting.

A relation whose positive control fails returns `NOT_REACHED`
("positive control failed: …"). Relations with `needs_control=False`
(the round-trip and declared-size relations) are the loud reporters:
they can still fire `DEFECT_FOUND` on a target so broken that every
controlled relation honestly declines.

## 4. Crash and timeout adjudication

The runner wraps the target in a crash watch. Post-mortem repeats,
external kills, and pqcheck's own deadline kills are attributed in
[pqcheck/target.py](../pqcheck/target.py) (`[post-mortem]`,
`NOT attributable to the target`, `killed by pqcheck's own deadline`)
and never converted into defects. A single uncorroborated fault while
the process lives is `NOT_REACHED`. Corroborated hard faults, and
reproducible hangs, are `DEFECT_FOUND` (a hang is reported as an
availability defect, not memory unsafety).

## 5. Failure taxonomy (`class_refs` idents)

Defect claims classify into these families:

| Ident | Family |
| --- | --- |
| `X-FO-LIVE` | FO transform not live: a corrupted ciphertext decapsulates to the honest secret. |
| `X-REJECT-*` | Implicit-rejection defects: secret does not bind the full ciphertext (`X-REJECT-CT`), does not bind `z`/the key, is non-deterministic, or ignores the ciphertext. |
| `X-CANON-*` | Encoding canonicality: non-canonical `ek` coefficients, signed zero, non-zero padding, non-strict hint order/tail. |
| `X-BIND-*` | Binding failures: message, context (unframed `ctx||msg`), prehash domain, public-key argument. |
| `X-DOM-*` | Domain-separation failures between signing modes. |
| `X-LEN-*` | Length exactness and declared-length wrap (16/32/64-bit) failures. |
| `X-CRASH` | Corroborated target-attributable crash or reproducible hang. |

## 6. Exit codes

`Report.exit_code()`: 1 if any defect, else 2 if nothing conclusive
anywhere, else 0. CLI/manifest misuse is exit 3 and is never a verdict.
