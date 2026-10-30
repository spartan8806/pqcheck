# 06 — Limitations: what pqcheck cannot see

An honest list, in roughly descending order of how often it matters.
Anything not listed here that pqcheck also cannot do is a bug in
this document; please file it.

## Side channels

- **Timing.** The functional relations say nothing about
  constant-time behaviour. The dudect-style instrument in
  [pqcheck/adapters/timing_probe.py](../pqcheck/adapters/timing_probe.py)
  reports a *bound on this instrument* (Welch's t on this machine,
  this load), never a certificate. KyberSlash-class secret-dependent
  divisions are OUT_OF_SCOPE in the backtest for exactly this reason.
- **Cache, power, EM, fault injection.** Not measured. No relation
  models a physical attacker.
- **ctgrind triage** ([pqcheck/adapters/ctgrind_triage.py](../pqcheck/adapters/ctgrind_triage.py))
  reports Valgrind secret-poisoning *leads*; an uninitialised-value
  warning marked UNEXPLAINED is a starting point for a human, not a
  finding.

## Distribution-level defects

- **Sampler precision and distribution shape.** A sampler that is
  subtly biased, or a noise distribution with wrong tails (the
  `GHSA-25rm-9wvm-m38v` shape), produces perfectly well-formed keys
  and signatures that pass every functional relation here. pqcheck
  tests relations between calls, not distributions over outputs.
  Statistical distribution testing is a different tool.
- **Randomness quality.** A weak RNG that still produces distinct,
  well-formed outputs is invisible to these relations.
  `NoPinnedRandomnessKem` support means pqcheck does not even require
  caller-supplied randomness to exist.

## State and lifecycle

- **Stateful hash-based signatures.** XMSS/LMS/HSS key reuse across
  state updates — including multi-tree HSS where the reuse is in a
  subtree — needs state modelling the stateless relation runner does
  not have. Recorded as MISSED (`clib-xmss-key-reuse`) rather than
  argued around.
- **Key lifecycle.** Generation entropy ceremonies, storage,
  backup/restore state rollback, and HSM behaviour are out of scope.

## API surface limits

- **Unexposed `RAW_DECODE`.** Codec relations need a raw
  encode/decode surface. A library that only exposes sign/verify
  gets the verifier-side hint relations (ML-DSA) but not the codec
  canonicality relations.
- **Unexposed `DECLARED_LENGTH`.** The declared-length wrap relation
  (`core-declared-length-overflow`) only applies where the API takes
  an explicit length. The historical `CVE-2022-37454` overflow sits
  below such an API in C size arithmetic and is recorded MISSED.
- **No guard-fill surface, no C harness.** Bit-exclusion relations
  need `GUARD_FILL` (64 bytes past the buffer). Pure high-level APIs
  decline honestly instead of approximating memory safety.
- **Streaming APIs.** Incremental hash update chunking (the Mouha
  class) and streaming codec decode are not modelled;
  `codec-stream-truncation` is PARTIAL for this reason.

## Assurance limits

- **One-sided relations.** `kem-fo-liveness` can only convict, never
  acquit. Its clean result is reported as
  `NO_WITNESS_ESTABLISHES_NOTHING` and counts toward nothing.
- **Witness budgets.** Unread-bits sweeps and FO witness searches
  have finite budgets (`n_signatures`, bit/combo caps). Absence of a
  witness inside the budget is stated as exactly that.
- **Toys are not libraries.** Selftest green means pqcheck's
  relations behave on pqcheck's own reference toys and 43 planted
  mutants. Real-library assurance comes only from running the
  shipped manifests against real builds (see
  [04_BACKTEST.md](04_BACKTEST.md) for what is demonstrated versus
  merely argued).
- **Muse AI expansion is a proposer, not an oracle.** Candidate
  probes are restricted to four built-in compound strategies,
  are gated against a clean reference fixture, and execute only
  inside a wiped ephemeral directory — but a candidate that
  survives the gate is still just a probe result under its stated
  ceiling, not a proof. The simulated client is deterministic and
  offline; live mode depends on the configured Muse endpoint.
  Muse claims carry an oracle label naming muse-wonder-1.0 as
  execution-verified proposer; that is not an independent
  implementation oracle.
- **The C/Rust harnesses need a first compile** on a machine with a
  toolchain before their evidence counts; the Python-side protocol
  logic is unit-tested, the compiled artefacts are not verified in
  every environment (see [DEVIATIONS.md](../DEVIATIONS.md)).
