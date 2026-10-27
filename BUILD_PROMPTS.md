# `pqcheck` — Phased Clean-Room Build Prompts

These six prompts are designed to build `pqcheck` (`blueteam`) from an empty directory in dependency order, matching the tone and structure of other tools I made. Each phase produces a self-contained, testable layer before the next layer is introduced.

---

## Phase 1: Core Verdict, Claim & Report Engine (`pqcheck/verdict.py`)
*(Expands [`CORE_PROMPT.txt`](CORE_PROMPT.txt) with the exact data contracts of `pqcheck/verdict.py`)*

```text
Start with the core decision and reporting engine (`pqcheck/verdict.py`). I want the system to take evidence from a cryptographic test and represent whether it found a real defect (`DEFECT_FOUND`), genuinely found no defect (`NO_DEFECT_FOUND`), could not reach an answer (`NOT_REACHED`), or could not ask the question on that target (`NOT_ANSWERABLE`).

The important part is structural honesty enforced inside dataclass constructors (`__post_init__`), raising `ClaimError(ValueError)` whenever a reassuring or uncheckable claim would be constructed:
1. `Subject(target, commit, algorithm=None, component=None)`: Refuse empty commits or moving references (`latest`, `head`, `main`, `master`, `dev`, `unknown`, `vendored`, `local`, `wip`, `test`, `temp`, `placeholder`, etc.).
2. `Verdict(str, Enum)`: Must be checked by enum identity (`isinstance(self.verdict, Verdict)`), refusing plain strings so JSON deserialization mistakes cannot bypass rules.
3. `Coverage(exercised, units=0, observed="")`: `NO_DEFECT_FOUND` must refuse to construct if `coverage` is `None`, `units <= 0`, or `exercised` is blank. `observed` records the runner's own call tally.
4. `Claim`:
   - Require non-empty `property` and `ceiling` (what the claim does NOT establish) on every verdict.
   - Require a non-stub `reproduce` instruction on `DEFECT_FOUND` (at least 12 chars and either >= 3 words or a file path).
   - Require `notes` on `NOT_ANSWERABLE` and `evidence` or `notes` on `NOT_REACHED`.
   - Require `premises` to be a `tuple[str, ...]`, never a bare string.
   - Support `one_sided: bool = False` for witness-search checks whose clean result establishes nothing.
   - Refuse to construct if `property`, `ceiling`, `evidence`, `reproduce`, `notes`, or `premises` contains contiguous secret-shaped blobs (`>= 48` hex chars or `>= 40` mixed-case-and-digit base64 chars via `looks_like_secret_material`), while providing `redact_target_output(text)` to redact blobs in target-authored crash stderr.
5. `Report`:
   - `score()` must exist and raise `NotImplementedError` explaining why dividing by the number of implemented checks measures tool effort rather than target risk.
   - `counts()` must break out one-sided `NO_DEFECT_FOUND` claims under `"NO_WITNESS_ESTABLISHES_NOTHING"`.
   - `is_conclusive_anywhere()` returns `True` only if there is at least one `DEFECT_FOUND` or two-sided `NO_DEFECT_FOUND`.
   - `exit_code()` returns `1` if defects exist, `2` if `not is_conclusive_anywhere()`, and `0` otherwise.
   - `to_text()` renders a prominent `*** THIS RUN ESTABLISHED NOTHING ***` banner when inconclusive, and orders sections: `DEFECTS FOUND`, `NOT REACHED`, `NO DEFECT FOUND`, `NO WITNESS FOUND — ESTABLISHES NOTHING`, and `OUT OF SCOPE FOR THIS TOOL`.

Include a `__main__` self-check in `pqcheck/verdict.py` that tests both refused and accepted claims and verifies `Report.score()` raises. Do not build the target seam, relations, adapters, or CLI yet.
```

---

## Phase 2: Target Seam, Process Death Attribution & Relation Runner (`pqcheck/target.py`, `pqcheck/relations/base.py`)

```text
Now build the seam between relations and targets (`pqcheck/target.py`) and the relation runner (`pqcheck/relations/base.py`).

In `pqcheck/target.py`:
1. Define `Status(str, Enum)` (`OK`, `REJECTED`, `CRASHED`, `TIMEOUT`) and `Outcome(status, value=None, detail="")` where `.ok` is `status is Status.OK` and `.is_finding` is `status in (Status.CRASHED, Status.TIMEOUT)`. Controlled rejection (`REJECTED`) is the target working, never a crash.
2. Define `Capability(str, Enum)` (`kem`, `sig`, `pinned_randomness`, `detached_sig`, `external_mu`, `ctx_string`, `explicit_sig_length`, `raw_decode`, `mldsa_hint_encoding`, `declared_length`, `guard_fill`).
3. Define `HarnessProtocolError(RuntimeError)` for harness/bridge limits so they are never misclassified as `REJECTED` or `CRASHED`.
4. Implement process death attribution helpers (`classify_exit`, `post_mortem`, `readline_deadline`) and the three death-contract markers:
   - `POST_MORTEM = "[post-mortem]"` (so post-death calls on a dead child do not self-corroborate a single crash into hundreds).
   - `NOT_ATTRIBUTABLE = "NOT attributable to the target"` (for external signals like `SIGTERM`/`SIGKILL`).
   - `DEADLINE_KILLED = "killed by pqcheck's own deadline"` (so a timeout kill in one relation is not misreported as an external CI kill in the next relation).

In `pqcheck/relations/base.py`:
1. Define `NotApplicable(Exception)` and `Finding(held: bool | None, evidence: str, units: int, exercised: str, reproduce: str = "", notes: str = "")`.
2. Implement `_CrashWatch(target)` which wraps the target, blocks direct access to `_t`/`__target`, counts `calls` and per-op `ops` (for `Coverage.observed`), and records every `out.is_finding` in `crashes`.
3. Implement `Relation` and `@register`:
   - Enforce applicability (`requires` capabilities -> `NOT_ANSWERABLE`).
   - Enforce `needs_control` via `control(target)` (`False` -> `NOT_REACHED`; `NotApplicable` -> `NOT_ANSWERABLE`; unexpected exception -> `NOT_REACHED` with a neutral note that does not exonerate the target).
   - Enforce `constructs_probes`: require `probe_control(target)` to be overridden at `@register` time, and return `NOT_ANSWERABLE` if the benign twin of the constructed probe is rejected by the target.
   - Adjudicate crashes and timeouts after `check(watched, rng)`:
     * Separate `DEADLINE_KILLED` and `NOT_ATTRIBUTABLE` into `NOT_REACHED`.
     * Separate `Status.TIMEOUT` from memory faults: 1 timeout -> `NOT_REACHED`; `>1` timeouts -> `DEFECT_FOUND` (reproducible hang, explicitly not memory unsafety).
     * If `probes_lie_about_length` is True, report crashes as `NOT_REACHED` (ambiguous between target overflow and adapter promise violation).
     * Partition remaining fresh faults into assertion aborts (`assert`, `panicked at`, `debug_assert` -> `NOT_REACHED`) and hard faults (`SIGSEGV`, ASan, etc.). Require corroboration (`len(hard) > 1` or process confirmed dead) before emitting a memory-safety `DEFECT_FOUND`.
     * If `f.held is False` when a crash/timeout overrides the verdict, preserve the relation's finding in a `withheld` note.
   - Enforce the zero-call gate (`f.units > 0 and watched.calls == 0` -> `NOT_REACHED`) and zero-observation gate (`f.held is None or f.units <= 0` -> `NOT_REACHED`).

Write focused tests verifying clean execution, defect detection, failed control, zero-call spoofing, one-sided witness miss, external signal crash, assertion abort, corroborated hard crash, and timeout attribution.
```

---

## Phase 3: Toy Targets, Planted Mutants & The Relation Library (`pqcheck/testing/`, `pqcheck/relations/`, `pqcheck/selftest.py`)

```text
Now build the relation library (`pqcheck/relations/`), the in-process reference toys and planted mutants (`pqcheck/testing/`), and the acceptance suite (`pqcheck/selftest.py`).

1. Implement the 9 relation modules (auto-imported in `pqcheck/relations/__init__.py`):
   - `core_invariants.py`: `core-kem-round-trip` (uncontrolled loud reporter), `core-sig-round-trip` (uncontrolled loud reporter; reports `DEFECT_FOUND` if keygen succeeds and all 5 messages are refused), `core-input-length-boundaries` (B-1/B/B+1 around sponge rates and powers of two), `core-declared-sizes-match-produced` (fails closed unless `measured_sizes` is declared).
   - `kem_reject.py`: `kem-reject-ct-bit-contribution`, `kem-reject-binds-full-ciphertext` (2 masks per byte to catch single-byte omissions and distinguish contiguous truncation from scattered PCO leaks), `kem-reject-binds-z-accept-path-does-not`, `kem-reject-determinism`, `kem-fo-liveness` (`one_sided=True`, classifies witness mask shapes), `kem-degenerate-ciphertext`, `kem-decaps-length-exact`.
   - `kem_encoding.py`: `kem-ek-modulus-canonical` (`constructs_probes=True`, 12-bit +q probes across all k polynomials) and `kem-dk-hash-consistency` (`constructs_probes=True`, FIPS 203 Alg 16 H(ek) tampering).
   - `sig_generic.py`: `sig-wrong-key-rejection`, `sig-message-binding`, `sig-degenerate-values`, `sig-ctx-binding` (including ctx||msg length-ambiguity pairs), `sig-mode-domain-separation`, `sig-verify-length-exact` (fails closed on `fixed_sig_len`).
   - `malleability.py`: `sig-unread-bits` (backwards bit-flip sweep across `n_signatures=8` signatures bucketed by length, plus `max_combos=512` combination probing on the witness signature).
   - `encoding.py`: `core-codec-round-trip` (uncontrolled loud reporter), `sig-encoding-signed-zero` (`constructs_probes=True`), `sig-encoding-pad-bits-zero` (monotone binary search for `pad_start`), `sig-encoding-length-exact` (including unpadded zero-stripped truncation), `sig-encoding-decode-reencode-identity`, `mldsa-hint-strict-order`, `mldsa-hint-tail-zero`.
   - `mldsa_encoding.py`: Verifier-side `mldsa-verify-hint-strict-order` and `mldsa-verify-hint-tail-zero` using `Capability.MLDSA_HINT_ENCODING`.
   - `bit_exclusion.py`: `kem-declared-length-bit-exclusion` and `sig-declared-length-bit-exclusion` using 64-byte guard fills (`0x00`, `0xFF`, random, `0x00` determinism repeat) and zero-fill control rescue.
   - `length_overflow.py`: `core-declared-length-overflow` (`probes_lie_about_length=True`, probing 16/32/64-bit byte and bit-length wrap points).

2. Implement the clean reference toys, planted mutants, and adversarial precision fixtures in `pqcheck/testing/` (`toy.py`, `toylwe.py`, `toyfalcon.py`, `toymldsa.py`, `toycodec.py`, `precision.py`).

3. Implement `pqcheck/selftest.py` verifying:
   - 0 false positives across all clean toys and all 8 precision fixtures;
   - every mutant is behaviourally live (`_differs_from_clean`);
   - 100% recall across all registered relations;
   - the two-sided seed-discrimination gate on `sig-unread-bits`.
```

---

## Phase 4: C & JavaScript Adapters and Harnesses (`pqcheck/adapters/`)

```text
Build the external target adapters and harnesses in `pqcheck/adapters/`:

1. `c_harness.c` & `cbridge.py` (`CTarget`):
   - Line protocol on stdin/stdout: `info`, `keygen`, `sign`, `verify`, `encaps`, `decaps`, `guard <hex|->`.
   - Exact-sized `malloc` on every input and output buffer (never stack-allocated or rounded), appending `guard` bytes past the declared input length when set.
   - Separate `REJ` (library refused input -> `Status.REJECTED`) from `ERR` (harness error -> raises `HarnessProtocolError`).
   - In `CTarget`: route child `stderr` to a `TemporaryFile` to avoid pipe deadlocks, verify `kind` and `alg` in `info`, decline stateful hash-based signatures (`LMS`, `XMSS`, etc.), infer `fixed_sig_len` over 6 message lengths, and parse hex replies defensively (unparseable target output -> `Status.CRASHED`).
2. `noble_bridge.mjs` & `noble.py` (`NobleTarget`):
   - JSON-lines bridge driving `@noble/post-quantum` (`ML-KEM`, `ML-DSA`, `SLH-DSA`, `Falcon`).
   - Expose `PINNED_RANDOMNESS` where seed is supported, `EXPLICIT_SIG_LENGTH`, `DETACHED_SIG`, `CTX_STRING` (probed for expressibility), `MLDSA_HINT_ENCODING`, and `prehash` mode switching.
3. `codec_harness.c` / `codec_bridge.py` (`CodecTarget`) and `hint_harness.c` / `hint_bridge.py` (`HintTarget`):
   - Drive raw `comp_encode`/`comp_decode` and ML-DSA hint decode surfaces (`Capability.RAW_DECODE`), stamping `target.oracle` with the reference implementation identity.
```

---

## Phase 5: Declarative Manifests, Safe Discovery, CLI & Terminal UI (`manifest.py`, `discover.py`, `cli.py`, `tui.py`)

```text
Build the user-facing orchestration layer:

1. `pqcheck/manifest.py`:
   - `Manifest` loader validating `target`, `version` (via `Subject`), `adapter` (`c`, `noble`, `codec`, `hint`), `algorithms`, and boolean flags (`wsl`, `padded`).
   - Portable path resolution relative to the manifest's directory (`~` and `${ENV}` expanded), `--set key=value` overrides routed back through validation, `missing_paths()`, and `wrong_version()` (checking `package.json` for `noble`).
2. `pqcheck/discover.py`:
   - Zero-execution directory scanner (`pqcheck run <folder>`) walking up to depth 5 (including `build/`, `target/`, `out/`, `bin/`).
   - Detect manifests, installed `@noble/post-quantum`, compiled ELF/PE/Mach-O harness binaries (by magic bytes, excluding Cargo/CMake build-script intermediates), and unbuilt source trees.
   - Never invent a `version` for a compiled binary (`missing=("version", ...)`), and never execute an unknown binary without operator confirmation.
3. `pqcheck/cli.py` & `pqcheck/__main__.py`:
   - Subcommands: `run`, `reproduce`, `relations`, `adapters`, `ui`.
   - Generate standalone reproducer scripts (`--reproducers DIR`) and exact `pqcheck reproduce` commands preserving `--set` overrides and `--seed`.
   - Enforce the exit code contract (`0` clean & conclusive, `1` defect found, `2` established nothing / missing harness / version mismatch, `3` bad CLI/manifest).
4. `pqcheck/tui.py`:
   - Dependency-free interactive terminal UI using ANSI escapes + `msvcrt`/`termios`.
   - Five visual states ordered worst-first (`DEFECT_FOUND` in bold red, `NOT_REACHED` and `NO_WITNESS_ESTABLISHES_NOTHING` in amber, `NO_DEFECT_FOUND` in plain white—never green—and `NOT_ANSWERABLE` in dim).
```

---

## Phase 6: Historical Backtest Corpus & Standing Regression Probes (`pqcheck/backtest/`, `pqcheck/probes.py`, `probes/`)

```text
Finish with the historical backtest accounting and standing regression probe runner:

1. `pqcheck/backtest/corpus.py` & `pqcheck/backtest/report.py`:
   - Catalogue 22 historical defects (21 real-world shipped vulnerabilities across LibOQS, PQClean, @noble/post-quantum, XKCP, Go/Java crypto, plus 1 planted control), deriving `COVERED`, `PARTIAL`, `MISSED`, and `OUT_OF_SCOPE` directly from `pqcheck.relations.base.REGISTRY`.
2. `pqcheck/probes.py` & `probes/verify_*.py`:
   - Runner for standalone regression probes (`verify_*.py`), enforcing exit codes `0` (pass), `77` (skipped with reason), and `78` (partial), and failing closed if any probe prints `SKIP` while exiting `0`.
```
