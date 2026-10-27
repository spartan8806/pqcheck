# `pqcheck` — Sequential Build Prompts (Set 2: Phases 7–10)

> **Instructions for `muse-wonder-1.0`:**
> Now that Phases 1–6 (`SPEC_FROM_SCRATCH.md`) are complete, read `SPEC_SET_2.md` and execute Phases 7 through 10 in order to complete the full repository inside `C:\Muse pqcheck`.
> Keep all 3 rules in force:
> 1. Stay strictly inside `C:\Muse pqcheck`.
> 2. Maintain 100% defensive assurance / zero red-team utility (no exploit payloads, no remote targets, secret-material floor enforced).
> 3. Document any deviations if needed.

---

## Prompt 7 — Phase 7: Adversarial Precision Boundary Suite & Real-Code Regression Fixtures (`pqcheck/testing/precision.py` & `pqcheck/testing/fixtures.py`)

```markdown
Read `SPEC_SET_2.md` Phase 7 and implement:

1. `pqcheck/testing/precision.py`:
   - Implement the 8 non-ML-KEM / non-ML-DSA reference-correct boundary targets (`ExplicitRejectKem`, `WideByteSlackCtKem`, `InterleavedPadCtKem`, `AlignedCoeffCtKem`, `NoPinnedRandomnessKem`, `VariableLengthSig`, `NoPreHashSig`, `HedgedSig`) plus the documented counterexample `RandomizedRejectKem`.
   - Implement `PrecisionCase` (`make`, `label`, `why_correct`, `kind`, `may_fire`, `must_not_say`, `must_decline`) and `CASES`.
   - Implement the runner that verifies the honest round-trip on each target, runs all 32 registered relations against all 8 `CASES`, and enforces default-deny on `DEFECT_FOUND`, staleness checking on `may_fire`, phrase exclusion on `must_not_say`, and mandatory `NOT_REACHED`/`NOT_ANSWERABLE` on `must_decline`.
   - Run `python pqcheck/testing/precision.py` and verify it exits `0` (`PRECISION: PASS`).

2. `pqcheck/testing/fixtures.py`:
   - Implement `NOBLE_061` pinning `@noble/post-quantum` `0.6.1`, `expected_claims = 10 * len(base.REGISTRY)`, `expected_defects`, and `expected_reach` with minimum coverage unit floors per algorithm.
   - Implement `run_noble(node_cwd)` with fault-isolated `NobleTarget` opening (`base.unopened_claims(subj, exc)`), `one_sided_reach` separation, and `--node-cwd` CLI entry point.
```

---

## Prompt 8 — Phase 8: Extended Adapters, Constant-Time (`ctgrind`), & Statistical Timing (`dudect`) Harnesses (`pqcheck/adapters/`)

```markdown
Read `SPEC_SET_2.md` Phase 8 and implement the extended adapter & side-channel/timing suite in `pqcheck/adapters/`:

1. Target-Specific C & Rust Line-Protocol Harnesses:
   - `pqcheck/adapters/pqclean_mlkem_harness.c` (serving ML-KEM-512/768/1024 in one binary from PQClean's `clean/` trees, with the `fgets` truncation guard emitting `ERR`).
   - `pqcheck/adapters/oqs_kem_harness.c` (linking `<oqs/oqs.h>` with pre-decode arity check and `fgets` truncation guard).
   - `pqcheck/adapters/falcon_compdecode_fixture.c` & `falcon_compdecode_fixture.sh`.
   - `pqcheck/adapters/rust/codec_harness.rs` & `pqcheck/adapters/rust/README.md` (Rust implementation of the `codec_bridge.py` line protocol over `falcon-rust`).

2. Constant-Time Secret-Poisoning (`ctgrind_*`):
   - `pqcheck/adapters/ctgrind_kem.c` and `pqcheck/adapters/ctgrind_clib.c` (using `VALGRIND_MAKE_MEM_UNDEFINED` on secret inputs and `VALGRIND_MAKE_MEM_DEFINED` on public inputs).
   - `pqcheck/adapters/ctgrind_triage.py` (parsing Valgrind memcheck frames and classifying them against upstream `issues.json` and `passes.json` into `KNOWN ISSUE`, `BENIGN`, and `UNEXPLAINED` with wildcard `fun:` matching).

3. Statistical Timing (`dudect`) Harnesses:
   - `pqcheck/adapters/timing_harness.c` (randomized interleaved measurement order across class A and class B ciphertexts).
   - `pqcheck/adapters/timing_probe.py` (implementing `welch_t`, `crop`, `scan_t` over `CROPS = (0.10, 0.20, 0.30, 0.40, 0.50, 0.70, 0.90, 1.00)`, testing `"honest vs random"`, `"honest vs all-zero"`, and mandatory negative control `"random vs random"`, and calibrating `floor = max(4.5, control)`).
   - `pqcheck/adapters/leakzoo_stat.py` (reading `CLASS` lines on `stdin` and applying `timing_probe.scan_t`).
```

---

## Prompt 9 — Phase 9: Standing Regression Probe Suite (`probes/`)

```markdown
Read `SPEC_SET_2.md` Phase 9 and implement the standing regression probe suite in `probes/` (`probes/README.md` and `probes/verify_*.py`):

1. Ensure every probe follows the status protocol enforced by `pqcheck/probes.py`:
   - Exits `0` when all assertions pass.
   - Exits `77` (`EXIT_SKIPPED`) after printing `SKIP: <reason>` when an external build/binary is absent (never exits `0` after printing `SKIP`).
   - Exits `78` (`EXIT_PARTIAL`) when only a subset of assertions could run.
2. Implement all pure-Python standing probes in `probes/` (`verify_no_key_material.py`, `verify_claim_type_gate.py`, `verify_unearned_claim_gates.py`, `verify_coverage_measured.py`, `verify_coverage_receipt.py`, `verify_cli_contract.py`, `verify_ui_honesty.py`, `verify_report_text.py`, `verify_report_encoding.py`, `verify_crash.py`, `verify_crash_attrib.py`, `verify_crash_and_zeroobs.py`, `verify_assertion_partition.py`, `verify_deadline_attribution.py`, `verify_declared_length_crash.py`, `verify_adapter_death_contract.py`, `verify_harness_channel.py`, `verify_harness_line_limit.py`, `verify_fo_shape.py`, `verify_single_ignored_byte.py`, `verify_ignored_suffix.py`, `verify_ctbit_n.py`, `verify_kem_attrib.py`, `verify_dk_regions.py`, `verify_unread.py`, `verify_varlen.py`, `verify_combos.py`, `verify_padbits.py`, `verify_padbits_region.py`, `verify_codec_contract.py`, `verify_codec_start.py`, `verify_encoding_reach.py`, `verify_encoding_shape.py`, `verify_probe_control.py`, `verify_precision_boundary.py`, `verify_inertness_reach.py`, `verify_discovery.py`, `verify_multitarget_abort.py`, `verify_unopened_target_noble.py`, `verify_reproducer_roundtrip.py`, `verify_shipped_manifests.py`, `verify_paths_resolve.py`, `verify_tree_compiles.py`, `verify_oracle_disclosure.py`, `verify_premises.py`) plus the conditional probes in `CONDITIONAL`.
3. Run `python -m pqcheck.probes` and verify `PROBES: PASS` with `failed: 0`.
```

---

## Prompt 10 — Phase 10: Shipped Manifests, Build Scripts, Packaging & CI (`manifests/`, `tools/`, `pyproject.toml`, `.github/workflows/ci.yml`, `SECURITY.md`, `README.md`)

```markdown
Read `SPEC_SET_2.md` Phase 10 and complete the repository packaging and operational files:

1. `manifests/`:
   - Create `manifests/README.md`, `manifests/noble.json`, `manifests/pqclean.json`, `manifests/liboqs.json`, `manifests/falcon-codec.json`, and `manifests/c-library.json`.
2. `tools/`:
   - Create `tools/README.md`, `tools/build_pqclean.sh`, `tools/build_liboqs.sh`, `tools/build_clib.sh`, `tools/rebuild_harness.sh`, and `tools/break_mlkem.sh`.
3. Root Packaging, CI & Docs:
   - Create `pyproject.toml` (zero runtime dependencies, `pqcheck = "pqcheck.cli:main"`), `.github/workflows/ci.yml`, `SECURITY.md`, and `README.md`.
4. Final End-to-End Verification Gate:
   - Run all verification commands from `.github/workflows/ci.yml`:
     - `python -m compileall -q pqcheck probes`
     - `python pqcheck/verdict.py`
     - `python pqcheck/selftest.py`
     - `python pqcheck/testing/precision.py`
     - `python -m pqcheck.backtest.report`
     - `python -m pqcheck.probes`
     - `python -m pqcheck relations`
     - `python -m pqcheck adapters`
     - Verify `python -m pqcheck run manifests/c-library.json` exits with code `2` (never `0`).
```
