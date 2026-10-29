# 02 — Validation methodology: precision and recall

Code: [pqcheck/selftest.py](../pqcheck/selftest.py) (acceptance),
[pqcheck/testing/precision.py](../pqcheck/testing/precision.py)
(boundary suite), [pqcheck/testing/](../pqcheck/testing/) (targets).

## Precision: no false positives on correct targets

Three layers, all must be green before any recall number is read:

1. **Clean reference toys (8).** `ToyKem`, `ToySig`, `ToyCodec`,
   `ToyStreamCodec` (via the codec group clean target), `ToyLweKem`,
   `PackedEkKem`, `ToyFalconSig`, `ToyMldsaSig` — run through
   `CLEAN_TARGETS` in selftest. Any `DEFECT_FOUND`, and any
   `NOT_REACHED`, on a clean toy is a failure: a correct target the
   tool cannot even ask its question of is a tool bug.
2. **Adversarial boundary targets (8).**
   [precision.py](../pqcheck/testing/precision.py) `CASES`:
   `ExplicitRejectKem` (explicit rejection instead of an implicit
   secret), `WideByteSlackCtKem`, `InterleavedPadCtKem`,
   `AlignedCoeffCtKem` (declared ciphertext slack/padding/nibble
   shapes), `NoPinnedRandomnessKem`, `VariableLengthSig`,
   `NoPreHashSig`, `HedgedSig`. These are correct implementations
   that are **not** ML-KEM/ML-DSA shaped. A relation may fire only
   where the case declares `may_fire` (real malleability), must not
   use the forbidden evidence phrases in `must_not_say` (e.g. it must
   not call declared slack a dead FO check), and must decline where
   `must_decline` says the question does not apply.
3. **Legacy precision fixtures (8)** in `PRECISION_TARGETS`
   (variable-length sig, no-context sig, no-guard sig, codec-variable,
   small sig, large-ct KEM, ML-DSA without the hint capability).

## Recall: every mutant caught, every relation firing

The 43 planted mutants are the canonical Appendix A keys:

| Group | Count | Target |
| --- | --- | --- |
| `KEM_MUTANTS` | 10 | `ToyKem` |
| `SIG_MUTANTS` | 15 | `ToySig` |
| `CODEC_MUTANTS` | 8 | `ToyStreamCodec` |
| `LWE_MUTANTS` | 3 | `ToyLweKem` |
| `PACKED_EK_MUTANTS` | 2 | `PackedEkKem` |
| `FALCON_MUTANTS` | 1 | `ToyFalconSig` |
| `MLDSA_MUTANTS` | 2 | `ToyMldsaSig` |

For every mutant, selftest requires both:

- **Liveness**: `probe_behaviour` (a behavioural fingerprint built
  outside the relations) differs from the clean target. An inert
  mutant proves nothing and fails the suite.
- **Recall**: at least one relation returns `DEFECT_FOUND`.

And globally: every one of the 32 relations must fire on at least
one mutant (`relations with recall: 34/34`).

## Seed discipline

Relations are randomised; verdicts must not be seed luck.

- Default run: seed base `pqcheck-selftest`.
- `python -m pqcheck.selftest --seeds 10` sweeps 10 deterministic
  seeds; every seed must show 100% precision and 100% recall with
  zero seed-dependent flakiness.
- The **seed discrimination gate** (`seed_discrimination_gate`)
  additionally proves the unread-bits sweep is seed-honest: the full
  8-signature sweep catches the Falcon minus-zero mutant under the
  gate seeds, while a deliberately degraded 1-signature variant does
  not — so the sweep's power comes from its budget, not from a lucky
  seed.

## What "green" means

```sh
python -m pqcheck.selftest            # exit 0
python -m pqcheck.selftest --seeds 10 # exit 0, 10/10 seeds ok
python -m pqcheck.testing.precision   # exit 0
```

Any failure prints the exact target, relation, and evidence. A green
selftest is a statement about pqcheck's own toys and mutants — see
[06_LIMITATIONS.md](06_LIMITATIONS.md) for what it does not say
about real libraries; real-target evidence is the backtest
([04_BACKTEST.md](04_BACKTEST.md)) and the shipped manifests.
