# `pqcheck` — Clean-Room Engineering Specification (Set 2: Phases 7–10)

> **Purpose of Set 2:** Once Phases 1–6 in `SPEC_FROM_SCRATCH.md` are complete, the core `pqcheck` Python engine is operational. **Set 2 (`SPEC_SET_2.md`)** specifies the remaining ~40% of the repository:
> - **Phase 7:** Adversarial Precision Boundary Suite (`pqcheck/testing/precision.py`) & Real-Code Regression Pin (`pqcheck/testing/fixtures.py`)
> - **Phase 8:** Target-Specific C/Rust Harnesses, Valgrind Secret-Poisoning (`ctgrind`), and Welch's t-Test Statistical Timing (`dudect`) Instruments (`pqcheck/adapters/`)
> - **Phase 9:** The Standing Regression Probe Suite (`probes/verify_*.py` & ` probes/README.md`)
> - **Phase 10:** Shipped Target Manifests (`manifests/`), Build/Operational Scripts (`tools/`), Zero-Dependency Packaging (`pyproject.toml`), CI Workflow (`.github/workflows/ci.yml`), and Security Policy (`SECURITY.md`)

All Set 1 rules remain strictly in force:
1. Stay strictly inside the workspace folder (`C:\Muse pqcheck`).
2. **100% Defensive / Zero Red-Team Utility:** Every harness, probe, and timing/constant-time instrument is strictly a local diagnostic assurance check for a maintainer testing their own build. Never output exploit payloads, recovered keys, or valid forgeries; enforce the secret-material floor everywhere.
3. Zero third-party Python dependencies (`dependencies = []` in `pyproject.toml`).

---

## Phase 7: Adversarial Precision Boundary Suite & Real-Code Regression Fixtures (`pqcheck/testing/`)

### 7.1 `pqcheck/testing/precision.py` — Correct Implementations That Are NOT ML-KEM / ML-DSA
`selftest.py` measures precision against reference-correct toys that match the exact FIPS 203 / FIPS 204 shape (bit-packed, implicitly rejecting, deterministic, fixed-length). A relation that fires `DEFECT_FOUND` on a **correct** implementation with a different wire format or API contract is a false positive—worse than a missed defect because it sends a maintainer hunting a bug that does not exist.

#### Target Classes to Implement in `pqcheck/testing/precision.py`
1. **`ExplicitRejectKem(ToyLweKem)`** (`name = "explicit-reject-kem"`):
   - Performs the intact FO re-encryption check (`pack(ct2)[0] == ct`), but on failure returns `Outcome(Status.REJECTED, None, "ciphertext failed re-encryption check")` instead of an implicit-rejection shared secret.
   - All four `kem-reject-*` relations (`kem-reject-determinism`, `kem-reject-binds-full-ciphertext`, `kem-reject-binds-z-accept-path-does-not`, `kem-reject-ct-bit-contribution`) **must decline** (`NOT_REACHED` or `NOT_ANSWERABLE`) and must never return `DEFECT_FOUND` or `NO_DEFECT_FOUND`.
2. **`WideByteSlackCtKem(ToyLweKem)`** (`name = "wide-byte-slack-ct-kem"`, `SLACK = 6`):
   - Appends 6 reserved zero bytes (`ct = sizes["ct"] + 6`) that the decoder ignores (`body = ct[:-6]`), while keeping the FO re-encryption check intact over `body`.
   - Tests that `kem-fo-liveness` may fire (since two distinct byte-strings yield the same shared secret, which is real `X-BIND-K-CT` ciphertext malleability), but its evidence string **must not** contain false attribution phrases claiming the FO re-encryption check is absent (`"exclude the one benign explanation"`, `"Which bits leak DIFFERS between bytes"`, `"check is ABSENT"`, `"cannot span that many bytes"`).
3. **`RandomizedRejectKem(ToyLweKem)`** (`name = "randomized-reject-kem"`):
   - Kept in the module as a documented **broken counterexample** (not in `CASES`): randomizing the implicit-rejection secret (`_h(b"J", z, ct, os.urandom(16))`) creates a trivial 2-query validity oracle (valid ciphertexts return identical output twice; invalid ciphertexts return different outputs). `kem-reject-determinism` firing on it is a true positive.
4. **`InterleavedPadCtKem(ToyLweKem)`** (`name = "interleaved-pad-ct-kem"`):
   - Doubles `sizes["ct"]`; every even byte (`ct[0::2]`) carries the packed ciphertext and every odd byte is reserved 16-bit alignment padding, sitting at `0.5` bound fraction.
   - `kem-fo-liveness` may fire for malleability, but `must_not_say` forbids `"Which bits leak DIFFERS between bytes"` and `"check is ABSENT"`.
5. **`AlignedCoeffCtKem(ToyLweKem)`** (`name = "aligned-coeff-ct-kem"`):
   - Doubles `sizes["ct"]`; every odd byte keeps only its low nibble (`b & 0x0F`), leaving the top 4 bits of every odd byte unused while keeping the FO check intact over the canonicalized bytes (`_canon(ct)`).
   - Attacks mixed-byte discriminators: every odd byte is mixed, yet the leaking bit-mask (`0xF0`) is uniform across witness bytes. `kem-fo-liveness` may fire for malleability, but `must_not_say` forbids `"Which bits leak DIFFERS between bytes"`, `"check is ABSENT"`, and `"exclude the one benign explanation"`.
6. **`NoPinnedRandomnessKem(ToyLweKem)`** (`name = "no-pinned-randomness-kem"`):
   - `encaps(ek, m=None)` discards `m` and calls `super().encaps(ek, None)`, modeling C KEM APIs with no caller-supplied randomness. Declares no `Capability.PINNED_RANDOMNESS`. Must produce zero `DEFECT_FOUND` across all relations.
7. **`VariableLengthSig(ToySig)`** (`name = "variable-length-sig"`):
   - Drops `Capability.EXPLICIT_SIG_LENGTH`, sets `fixed_sig_len = False`, `size_semantics = {"sig": "max"}`, `measured_sizes = ("pk", "sk", "sig")`, and appends a self-describing `0..3` byte zero tail (`bytes([n]) + bytes(n)` where `n = _h_sig(b"padlen", msg, ctx)[0] % 4`).
   - `sig-verify-length-exact` **must decline** (`must_decline`).
8. **`NoPreHashSig(ToySig)`** (`name = "no-prehash-sig"`):
   - Threads `declared_len` through `sign` and `verify`, and returns `Outcome(Status.REJECTED, None, "this scheme has no pre-hash mode")` whenever `prehash=True`.
   - `sig-mode-domain-separation` **must decline** (`must_decline`).
9. **`HedgedSig(ToySig)`** (`name = "hedged-sig"`):
   - Drops `Capability.PINNED_RANDOMNESS` and mixes `os.urandom(32)` into the Schnorr nonce `k`, modeling FIPS 204's default hedged signing mode. Must produce zero `DEFECT_FOUND`.

#### `PrecisionCase` Dataclass & Runner (`run_precision()`)
- `@dataclass(frozen=True) class PrecisionCase`:
  - `make: object`, `label: str`, `why_correct: str`, `kind: str = "kem"`
  - `may_fire: dict[str, str]` (relation ID -> justification why firing is legitimate)
  - `must_not_say: dict[str, tuple[str, ...]]` (relation ID -> forbidden substrings in `evidence + notes`)
  - `must_decline: dict[str, str]` (relation ID -> justification why verdict must be `NOT_REACHED` or `NOT_ANSWERABLE`)
- **Runner (`main()`):**
  - First verifies the honest round-trip on each fixture (`keygen` -> `encaps` -> `decaps` for KEM; `keygen` -> `sign` -> `verify` for SIG).
  - Runs every registered relation in `base.REGISTRY` against each of the 8 `CASES`.
  - Fails if:
    1. Any relation not in `may_fire` returns `DEFECT_FOUND`.
    2. Any relation in `may_fire` **stops** firing `DEFECT_FOUND` (stale permission check!).
    3. Any relation in `must_not_say` emits any forbidden phrase in `claim.evidence` or `claim.notes`.
    4. Any relation in `must_decline` returns a verdict other than `NOT_REACHED` or `NOT_ANSWERABLE`.

---

### 7.2 `pqcheck/testing/fixtures.py` — Real-Code Regression Fixture (`NOBLE_061`)
Validates `pqcheck` against a pinned third-party package (`@noble/post-quantum` version `0.6.1`) when `--node-cwd <dir>` is supplied.

- **`NOBLE_061` Configuration Dict:**
  - `"package": "@noble/post-quantum"`, `"version": "0.6.1"`
  - `"algorithms"`: `["falcon512", "falcon512padded", "falcon1024", "falcon1024padded", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "ml-kem-512", "ml-kem-768", "ml-kem-1024"]`
  - `"expected_claims"`: `10 * len(base.REGISTRY)`
  - `"expected_defects"`: `{("sig-verify-length-exact", "falcon512padded"), ("sig-verify-length-exact", "falcon1024padded")}`
  - `"expected_reach"`: Per-algorithm dictionary mapping each relation that must reach a `CONCLUSIVE` verdict to its minimum `coverage.units` floor:
    - `falcon512` & `falcon1024`: `{"core-input-length-boundaries": 46, "sig-message-binding": 48, "sig-degenerate-values": 3, "sig-unread-bits": 32768, "sig-wrong-key-rejection": 8, "core-declared-sizes-match-produced": 2, "core-sig-round-trip": 5}`
    - `falcon512padded` & `falcon1024padded`: same + `"sig-verify-length-exact": 4`, `"core-declared-sizes-match-produced": 3`
    - `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`: `{"core-input-length-boundaries": 46, "sig-message-binding": 48, "sig-ctx-binding": 4, "sig-mode-domain-separation": 2, "sig-degenerate-values": 3, "sig-unread-bits": 32768, "sig-verify-length-exact": 4, "sig-wrong-key-rejection": 8, "core-declared-sizes-match-produced": 3, "core-sig-round-trip": 5}`
    - `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`: `{"kem-fo-liveness": 2304/3264/4704, "kem-reject-binds-full-ciphertext": 768/1088/1568, "kem-reject-binds-z-accept-path-does-not": 4, "kem-reject-ct-bit-contribution": 21, "kem-reject-determinism": 8, "core-declared-sizes-match-produced": 4, "core-kem-round-trip": 4, "kem-ek-modulus-canonical": 8/13/16, "kem-degenerate-ciphertext": 4, "kem-decaps-length-exact": 5, "kem-dk-hash-consistency": 5}`
- **Checks in `run_noble(node_cwd)`:**
  - Reads `<node_cwd>/node_modules/@noble/post-quantum/package.json` and verifies `version == "0.6.1"`.
  - Wraps `NobleTarget(alg, node_cwd)` construction in `try/except Exception as exc`, yielding `base.unopened_claims(subj, exc)` on failure rather than aborting the whole run with a traceback.
  - Tracks `found` (`DEFECT_FOUND`), `reached` (`c.verdict in CONCLUSIVE`), `one_sided_reach` (`NO_DEFECT_FOUND and c.one_sided`), `thin` (`units < floor`), and `unreached` (`NOT_REACHED`).
  - Fails (returns `1`) if `missing` (`exp - found`), `extra` (`found - exp`), `lost` (`exp_reach - reached`), `gained` (`reached - exp_reach`), `thin`, `unreached`, or `total != expected_claims`.

---

## Phase 8: Extended Adapters, Constant-Time (`ctgrind`), & Timing (`dudect`) Harnesses (`pqcheck/adapters/`)

### 8.1 Target-Specific C & Rust Harnesses
All target-specific harnesses speak the exact line protocol from Phase 4 (`SPEC_FROM_SCRATCH.md` §5), never validate inputs on behalf of the library (`REJ` = library refused; `ERR` = harness declined, including the `fgets` line-truncation guard draining to `\n`), and allocate exact-sized buffers:
1. **`pqcheck/adapters/pqclean_mlkem_harness.c`:**
   - Serves `ML-KEM-512`, `ML-KEM-768`, and `ML-KEM-1024` in a single binary from PQClean's `clean/` trees (`PQCLEAN_MLKEM512_CLEAN_*`, `PQCLEAN_MLKEM768_CLEAN_*`, `PQCLEAN_MLKEM1024_CLEAN_*`).
   - Reproduces `PQClean#601` (`kem-ek-modulus-canonical`).
2. **`pqcheck/adapters/oqs_kem_harness.c`:**
   - Links against `<oqs/oqs.h>` (`OQS_KEM_new(alg)`, `OQS_KEM_keypair`, `OQS_KEM_encaps`, `OQS_KEM_decaps`).
   - Checks command arity before decoding hex; includes the `fgets` truncation guard (`ERR line exceeds this harness's ... buffer`).
3. **`pqcheck/adapters/falcon_compdecode_fixture.c` & `.sh`:**
   - Standalone C harness exposing Falcon's `comp_encode` / `comp_decode` over the codec line protocol (`info`, `encode`, `decode`) for `codec_bridge.py`.
4. **`pqcheck/adapters/rust/codec_harness.rs` & `pqcheck/adapters/rust/README.md`:**
   - Rust implementation of the `codec_bridge.py` line protocol over `falcon_rust::encoding::{compress, decompress}` (`N = 512, SLEN = 625`), proving the line-protocol contract is language-independent.

### 8.2 Constant-Time Secret-Poisoning Tools (`ctgrind_*`)
1. **`pqcheck/adapters/ctgrind_kem.c` & `ctgrind_clib.c` (`+ .sh` scripts):**
   - Uses `<valgrind/memcheck.h>` (`VALGRIND_MAKE_MEM_UNDEFINED` / `VALGRIND_MAKE_MEM_DEFINED`) to mark secret key `sk` and shared secret `ss` as undefined (poisoned) while keeping public key `pk` and ciphertext `ct` defined, so Valgrind memcheck flags any secret-dependent branch or table lookup during `encaps` / `decaps`.
2. **`pqcheck/adapters/ctgrind_triage.py`:**
   - CLI: `python ctgrind_triage.py <valgrind.log> <ALG>`
   - Parses `uninitialised value` stack frames (`report_frames(log)`) from a Valgrind log and matches them against upstream's `issues.json` (`KNOWN ISSUE`) and `passes.json` (`BENIGN`, supporting `*` wildcards in `fun:` symbols).
   - Any report matching neither is tagged `UNEXPLAINED` with the warning: `"UNEXPLAINED reports are not findings. Check the harness first -- marking a public value as secret produces exactly this shape."`

### 8.3 Statistical Timing (`dudect`) Harnesses (`timing_probe.py`, `timing_harness.c`, `leakzoo_stat.py`)
1. **`pqcheck/adapters/timing_harness.c`:**
   - Line-protocol binary accepting `info`, `keygen`, `encaps <pk>`, and `measure <sk_hex> <ct_a_hex> <ct_b_hex> <iters>`.
   - In `measure`, runs `2 * iters` decapsulations of equal-length ciphertexts `ct_a` and `ct_b` in **randomized order** (crucial: fixed `ABAB` order creates a position bias that scores `|t| = 17-22` at tight percentile crops on constant-time code), reading hardware cycle counters around each call and returning `OK <comma_sep_cycles_A> <comma_sep_cycles_B>`.
2. **`pqcheck/adapters/timing_probe.py`:**
   - Implements `welch_t(a, b)` (Welch's two-sample t-test without equal-variance assumption, returning `0.0` if `denom == 0`).
   - Implements `crop(xs, lo=0.0, hi=0.90)` and `scan_t(a, b)` across `CROPS = (0.10, 0.20, 0.30, 0.40, 0.50, 0.70, 0.90, 1.00)`, returning `(max_abs_t, crop_at_max)`.
   - Tests three classes of equal length `ct_n`:
     1. `"honest vs random"` (`honest`, `os.urandom(ct_n)`)
     2. `"honest vs all-zero"` (`honest`, `bytes(ct_n)`)
     3. `"random vs random"` (`os.urandom(ct_n)`, `os.urandom(ct_n)`) — **mandatory negative control**.
   - Calibrates the noise floor using the negative control: `floor = max(4.5, control)`.
   - Reports:
     - `worst > floor`: `"POSITIVE: |t| = ... exceeds the floor. A LEAD, not a finding -- re-measure on isolated, frequency-pinned hardware before believing it."`
     - `4.5 < worst <= floor`: `"INCONCLUSIVE: |t| = ... clears 4.5 but NOT the negative control..."`
     - `worst <= 4.5`: `"No separation detected ... This is a BOUND ON THIS INSTRUMENT, not a certificate of constant-time behaviour."`
3. **`pqcheck/adapters/leakzoo_stat.py`:**
   - Reads a `CLASS <name> <cycles_A> <cycles_B>` line from `stdin`, applies `scan_t(A, B)` imported from `timing_probe`, and prints `FIRES` (`t > 4.5`) or `silent` with `|t|`, `@crop`, and medians.

---

## Phase 9: The Standing Regression Probe Suite (`probes/`)

`python -m pqcheck.probes` runs every `probes/verify_*.py` script and classifies its result by exit code (`0` = ok, `77` = skipped, `78` = partial; printing a line starting with `SKIP` while exiting `0` fails as a `skip-protocol` violation).

### Core Pure-Python Standing Probes to Implement in `probes/`
Every probe below must be a standalone executable Python script (`#!/usr/bin/env python3`) that prints a clear diagnostic narrative of what it tested (checking both false-positive silence and true-positive detection where applicable) and exits `0` on pass, `1` on failure, or `77` (`EXIT_SKIPPED`) when an external binary/package it needs is absent:

1. **`probes/verify_no_key_material.py`:** Verifies that `Claim` construction and `Relation.run` reject secret key bytes (`dk`, `sk`), honest shared secrets (`ss`), and valid forged signatures in `evidence`, `notes`, and `reproducer` via `_check_no_secret_material`.
2. **`probes/verify_claim_type_gate.py`:** Verifies that `Claim` rejects a string verdict (e.g. `"NO_DEFECT_FOUND"` instead of `Verdict.NO_DEFECT_FOUND`) with `TypeError`.
3. **`probes/verify_unearned_claim_gates.py`:** Verifies the constructor gates in `verdict.py`:
   - `NO_DEFECT_FOUND` requires non-empty `Coverage(units >= 1, basis != "")`.
   - `DEFECT_FOUND` requires non-empty `reproducer` (rejecting placeholders like `"TBD"`, `"none"`, `"n/a"`), `ceiling`, and `false_positive_modes`.
   - `NOT_REACHED`, `NOT_ANSWERABLE`, and `INCONCLUSIVE` require an explanation in `notes` or `evidence`.
   - `Report.score()` raises `RuntimeError`.
4. **`probes/verify_coverage_measured.py` & `probes/verify_coverage_receipt.py`:** Verifies that `Relation.run` counts actual target calls via `_CrashWatch`, refuses `NO_DEFECT_FOUND` if `watch.calls == 0`, reconciles `Coverage.units` with `Coverage.exercised` and `watch.calls` (`runner_calls`), and renders both in `to_text()`.
5. **`probes/verify_cli_contract.py`:** Verifies the CLI exit-code contract (`0` = conclusive & clean, `1` = `DEFECT_FOUND`, `2` = established nothing / all `NOT_REACHED` or `NOT_ANSWERABLE`, `3` = unusable manifest / bad args) and verifies that a run with only `one_sided=True` passes exits `2`, never `0`.
6. **`probes/verify_ui_honesty.py`:** Verifies that `pqcheck/tui.py` and `Report.counts()` separate `no_defect_one_sided` from `no_defect`, render `NOT REACHED` before `NO DEFECT FOUND`, and never display a percentage score.
7. **`probes/verify_report_text.py` & `probes/verify_report_encoding.py`:** Verifies that `Report.to_text()` prints `c.subject` on every claim across all 5 sections, includes `ceiling` and `false_positive_modes` on defects, and survives a `cp437`/`cp1252` console without `UnicodeEncodeError` via `emit()` / `use_utf8_stdout()`.
8. **`probes/verify_crash.py`, `probes/verify_crash_attrib.py`, `probes/verify_crash_and_zeroobs.py`, `probes/verify_assertion_partition.py`, `probes/verify_deadline_attribution.py`, `probes/verify_declared_length_crash.py`, `probes/verify_adapter_death_contract.py`:**
   - Verifies that `_CrashWatch` distinguishes:
     - `[post-mortem]` calls after process death (never inflating crash counts),
     - `NOT attributable to the target` external signals (`SIGTERM`/`SIGKILL`) and deadline timeouts (`killed by pqcheck after the per-call deadline`) -> `NOT_REACHED`,
     - Assertion aborts (`"assertion"` in detail) -> controlled precondition enforcement, partitioned separately from real faults so an assertion abort cannot hide a real crash or steal its evidence sentence,
     - Crashes under `DECLARED_LENGTH` lying-length probes -> `NOT_REACHED` rather than memory-safety `DEFECT_FOUND`,
     - Real corroborated target crashes -> `DEFECT_FOUND` (`X-CRASH`).
9. **`probes/verify_harness_channel.py` & `probes/verify_harness_line_limit.py`:** Verifies that `ERR ...` lines from a harness map to `Status.ERROR` (never `Status.REJECTED`) and that the C harnesses contain the `fgets` truncation / `getline` guard so over-long lines emit `ERR`, never `REJ bad hex`.
10. **`probes/verify_fo_shape.py`, `probes/verify_single_ignored_byte.py`, `probes/verify_ignored_suffix.py`, `probes/verify_ctbit_n.py`, `probes/verify_kem_attrib.py`, `probes/verify_dk_regions.py`:**
    - Verifies the KEM relation edge cases: `kem-fo-liveness` separating narrow slack (`SlackCtKem`) from wide absence (`ToyLweKem[no_reencryption_check]`), `kem-reject-binds-full-ciphertext` catching a single ignored ciphertext byte and an ignored suffix, `kem-reject-ct-bit-contribution` counting comparable observations rather than skipped attempts, and `ToyKem`/`ToyLweKem` deriving secrets from `dk` bytes rather than dict handles.
11. **`probes/verify_unread.py`, `probes/verify_varlen.py`, `probes/verify_combos.py`, `probes/verify_padbits.py`, `probes/verify_padbits_region.py`, `probes/verify_codec_contract.py`, `probes/verify_codec_start.py`, `probes/verify_encoding_reach.py`, `probes/verify_encoding_shape.py`, `probes/verify_probe_control.py`:**
    - Verifies the signature & codec relation invariants: multi-signature sweep (`n_signatures = 8`) working on both fixed- and variable-length signatures, exact combination enumeration up to 8 unread bits (`2^k` measured, not assumed), `PadBitsZero` sweeping the entire padding region on padded formats and declining on variable-length formats, and `probe_control` enforcement on `constructs_probes = True` relations.
12. **`probes/verify_precision_boundary.py`:** Runs `pqcheck/testing/precision.py` and exits `0` iff all 8 non-ML-KEM / non-ML-DSA precision boundary targets pass.
13. **`probes/verify_inertness_reach.py`:** Verifies that `selftest._mutant_differs_from_clean` probes both the front and back halves of large signatures (`ML-DSA-87` 4627B geometry) as well as `ek`, `dk`, `declared_len`, and `guard` fills.
14. **`probes/verify_discovery.py`, `probes/verify_multitarget_abort.py`, `probes/verify_unopened_target_noble.py`, `probes/verify_reproducer_roundtrip.py`, `probes/verify_shipped_manifests.py`, `probes/verify_paths_resolve.py`, `probes/verify_tree_compiles.py`, `probes/verify_oracle_disclosure.py`, `probes/verify_premises.py`:**
    - Verifies folder discovery, unopened-target fault isolation, reproducer CLI round-tripping, shipped manifests exiting `2` when harnesses are unbuilt, `compileall` across `pqcheck/` and `probes/`, `Method.oracle` rendering, and `premises` rendering.
15. **Conditional Probes (listed in `pqcheck/probes.py` `CONDITIONAL`):**
    - `probes/verify_snova.py`, `probes/verify_snova_count.py`, `probes/verify_stateful_gate.py`, `probes/verify_codec_oracle.py`, `probes/verify_roundtrip_order.py`, `probes/verify_hint_oracle.py`: exit `77` (`SKIP: ...`) when their C harness binary is not present on disk.
    - Also create `probes/README.md` documenting the standing probe rules.

---

## Phase 10: Shipped Manifests, Build Scripts, Packaging & CI

### 10.1 `manifests/`
Create `manifests/README.md` and the 5 JSON manifests:
1. **`manifests/noble.json`:**
   ```json
   {
     "target": "@noble/post-quantum",
     "version": "0.6.1",
     "adapter": "noble",
     "node_cwd": "${NOBLE_DIR}",
     "algorithms": ["falcon512", "falcon512padded", "ml-dsa-44", "ml-kem-768"]
   }
   ```
2. **`manifests/pqclean.json`:**
   ```json
   {
     "target": "PQClean ML-KEM (clean)",
     "version": "0586a82",
     "adapter": "c",
     "harness": "../pqcheck/adapters/harness_pqclean",
     "wsl": false,
     "algorithms": ["kem:ML-KEM-512", "kem:ML-KEM-768", "kem:ML-KEM-1024"]
   }
   ```
3. **`manifests/liboqs.json`:**
   ```json
   {
     "target": "liboqs",
     "version": "0.16.0",
     "adapter": "c",
     "harness": "../pqcheck/adapters/harness_liboqs",
     "wsl": false,
     "algorithms": ["kem:ML-KEM-512", "kem:ML-KEM-768", "kem:ML-KEM-1024"]
   }
   ```
4. **`manifests/falcon-codec.json`:**
   ```json
   {
     "target": "PQClean falcon codec (as vendored in liboqs)",
     "version": "0.16.0",
     "adapter": "codec",
     "harness": "../pqcheck/adapters/codec_falcon512",
     "wsl": false
   }
   ```
5. **`manifests/c-library.json`:**
   ```json
   {
     "target": "your-c-library",
     "version": "0000000",
     "adapter": "c",
     "harness": "../pqcheck/adapters/harness_yourlib",
     "wsl": false,
     "algorithms": ["sig:ML-DSA-65", "kem:ML-KEM-768"]
   }
   ```

### 10.2 `tools/`
Create `tools/README.md` and the 5 operational shell scripts (`#!/usr/bin/env bash`, `set -euo pipefail`):
1. `tools/build_pqclean.sh`: Clones or verifies PQClean at commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (refusing any other commit), compiles `pqcheck/adapters/pqclean_mlkem_harness.c` with all three ML-KEM `clean/` trees into `pqcheck/adapters/harness_pqclean`, and smoke-tests `info` on all three parameter sets.
2. `tools/build_liboqs.sh`: Builds static OpenSSL-free `liboqs`, links `pqcheck/adapters/oqs_kem_harness.c` into `pqcheck/adapters/harness_liboqs`, smoke-tests ML-KEM-512/768/1024, and prints the version for `manifests/liboqs.json`.
3. `tools/build_clib.sh` & `tools/rebuild_harness.sh`: Compiles `pqcheck/adapters/c_harness.c` against `LIB_SRC` and smoke-tests `info` plus an over-long hex line check (confirming `ERR`, not `REJ`).
4. `tools/break_mlkem.sh`: Controlled positive-control plant script requiring `BREAK_FILE`, `BREAK_AFTER`, and `BREAK_INSERT` environment variables; refuses a dirty git tree, plants a one-line FO re-encryption bypass in a local checkout, builds, runs `pqcheck` to verify `kem-fo-liveness` fires `DEFECT_FOUND`, reverts via `trap`, rebuilds, and verifies the clean build passes.

### 10.3 Root Packaging, CI & Documentation (`pyproject.toml`, `.github/workflows/ci.yml`, `SECURITY.md`, `README.md`)
1. **`pyproject.toml`:**
   - `name = "pqcheck"`, `version = "0.1.0b1"`, `requires-python = ">=3.10"`, `dependencies = []`
   - `[project.scripts] pqcheck = "pqcheck.cli:main"`
   - `[tool.setuptools] packages = ["pqcheck", "pqcheck.adapters", "pqcheck.backtest", "pqcheck.relations", "pqcheck.testing"]`
   - `[tool.setuptools.package-data] "pqcheck.adapters" = ["*.c", "*.h", "*.sh", "*.mjs", "rust/*"]`
2. **`.github/workflows/ci.yml`:**
   - Matrix over `ubuntu-latest` and `windows-latest` (`python: ["3.10", "3.14"]` plus `"3.11"`, `"3.12"` on Ubuntu).
   - Steps: verify zero third-party imports, `python -m compileall -q pqcheck probes`, `python pqcheck/selftest.py`, `python pqcheck/verdict.py`, `python -m pqcheck.backtest.report`, `python -m pqcheck.probes`, `python -m pqcheck relations`, `python -m pqcheck adapters`, and verify `python -m pqcheck run manifests/c-library.json` exits `2` (never `0`).
3. **`SECURITY.md` & `README.md`:**
   - `SECURITY.md` documenting coordinated vulnerability disclosure guidelines (verify by execution, lead with reproducer, state the ceiling, never overclaim severity) and naming false reassurance (`NO_DEFECT_FOUND` on an unexercised surface) as an in-scope security bug in `pqcheck`.
   - `README.md` providing the quickstart, architecture overview, CLI commands, exit-code table, and honesty guarantees.
