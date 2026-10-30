# Deviations from the build prompts

Recorded under the rule: if building to spec requires breaking form from
the prompts, write a doc and say so. Everything below is a case where the
implementation differs from, or could not be verified against,
[BUILD_PROMPTS.md](BUILD_PROMPTS.md) / [SPEC_FROM_SCRATCH.md](SPEC_FROM_SCRATCH.md).

1. **Missing `CORE_PROMPT.txt`.** Phase 1 of BUILD_PROMPTS.md references
   `CORE_PROMPT.txt`, which was not in the folder. `pqcheck/verdict.py` was
   built from the Phase 1 prompt text plus SPEC §3, which the prompt says
   it expands.

2. **Package location.** SPEC §2 lays the package out under a `blueteam/`
   root. Under the stay-in-folder rule it lives directly in the workspace
   root (`pqcheck/…`, `manifests/…`, `probes/…`). No `blueteam/` wrapper.

3. **Backtest corpus provenance (Phase 6).** The original 22-case list
   came from the author's internal tool and was not in the docs.
   [pqcheck/backtest/corpus.py](pqcheck/backtest/corpus.py) is a
   reconstruction from public defect classes (CVE-2022-37454,
   CVE-2022-21449, FIPS 203/204 canonicality and hint classes, FO/PCO
   classes, KyberSlash, plus one planted control). Statuses are *derived
   from the live registry* — i.e. "this tool can ask about this class" —
   and are **not** a re-run of the tool against the vulnerable versions.
   Do not present the counts as empirical backtest results.

4. **C harness not compile-verified in this environment.** No C compiler
   (gcc/clang/cc) and no usable WSL was available on the build machine, so
   [tests/test_adapters.py](tests/test_adapters.py) skips the two
   compile-and-run tests with an explicit reason. The Python bridges
   (CTarget/CodecTarget/HintTarget) are verified end-to-end against a
   fake line-protocol harness in [tests/fake_harness.py](tests/fake_harness.py).
   The C sources follow the spec's exact-sized-malloc and REJ/ERR rules but
   still need a real compile (`gcc -O1 -o harness pqcheck/adapters/c_harness.c`)
   on a machine with a compiler before being trusted.

5. **Noble verification scope.** `@noble/post-quantum` 0.7.1 was installed
   into a scratch folder inside the workspace and pqcheck was run against
   real ML-KEM-768 (9 clean, 1 no-witness, 0 defects) and ML-DSA-65
   (11 clean, 0 defects, 0 not-reached). Other algorithms (ML-KEM-512/1024,
   ML-DSA-44/87, SLH-DSA, Falcon) use the same bridge paths but were not
   individually run. The scratch install was removed afterwards.

6. **ML-DSA hint layouts.** The `mldsa-verify-*` relations support both
   the toy hint layout and the real FIPS 204 layout
   (`ctilde || z || h`, `h` = omega index bytes + k cumulative offsets).
   The FIPS path was verified on ML-DSA-65 only; ML-DSA-44/87 share the
   code path and declared geometries but were not individually run.

7. **`CTarget` accepts a `.py` harness path.** As a small extension, a
   harness path ending in `.py` is run with the current Python
   interpreter. This exists so the bridge can be tested without a C
   compiler and so users can prototype a harness in Python. The spec only
   requires compiled binaries (and `wsl.exe`).

8. **Example manifests are examples.** Versions in
   [manifests/](manifests/) are exact-form pins so the files validate,
   but they are not verified release numbers for those projects; set the
   real version (or commit) before running.

9. **Toy cryptography is not cryptography.** Everything in
   [pqcheck/testing/](pqcheck/testing/) is hash-based fixtures for testing
   the relations. It must never be used as a cryptographic implementation.

## Set 2 additions

10. **`BUILD_PROMPTS_SET_2.md` was not in the folder.** Set 2 was built
    from [SPEC_SET_2.md](SPEC_SET_2.md) alone. If the prompts file adds
    contracts the spec does not, they are not implemented.

11. **Set 2 probe vocabulary adapted to the Set 1 API.** Several Phase 9
    probe descriptions name concepts from a different revision
    (`reproducer`, `false_positive_modes`, an `INCONCLUSIVE` verdict,
    `Status.ERROR`, `RuntimeError` from `score()`, `TypeError` from the
    claim gate, a different deadline-marker sentence). Set 1's API wins:
    probes verify the actual behaviour (`reproduce`, `ClaimError`,
    `NotImplementedError`, `HarnessProtocolError`, four verdicts) and
    [probes/README.md](probes/README.md) records the mapping.

12. **Noble 0.6.1 fixture `gained` reach is informational, not a
    failure.** SPEC_SET_2 §7.2 defines `expected_reach` as the relations
    that *must* reach a floor (minimums) but also lists `gained` as a
    failure; those contradict once `kem-dk-hash-consistency` and the
    ML-DSA verifier hint relations legitimately reach. `run_noble`
    fails on missing/extra defects, lost reach, thin coverage, and
    unreached relations, and prints gained reach as a note.

13. **`kem-ek-modulus-canonical` measures key equivalence, not mere
    acceptance.** Against real Noble 0.6.1, a +q-bumped ek is sometimes
    accepted as a *different* key (which FIPS 203 input validation
    should reject, but which is not a second byte string for the same
    key). The relation defects only when the bumped ek decapsulates
    under the original dk to the bumped secret, and its ceiling now
    says so. This matches the fixture's expected-defect set.

14. **Phase 8 C/Rust harnesses and Phase 10 shell scripts are
    unexecuted in this environment.** No C compiler, Valgrind, Rust
    toolchain, PQClean/liboqs checkout, or bash was available on the
    build machine. The Python instruments (Welch scan, ctgrind triage,
    leakzoo) are unit-tested; the C sources follow the protocol
    (exact-sized malloc, REJ/ERR separation, line-truncation guard) but
    still need a first compile on a real toolchain.

15. **The Noble 0.6.1 scratch install (`noble061/`) was a local test
    fixture, not shipped code.** It existed so the Phase 7 fixture could
    be re-run (`python -m pqcheck.testing.fixtures noble061`); the full
    fixture passed (320 claims, defects exactly the two expected
    Falcon-padded ones) and the directory was deleted afterwards;
    nothing in `pqcheck/` depends on it.

16. **Post-build audit tightening (3 items).** (a) The backtest corpus
    was rebuilt on the 5 incommensurable grades (DEMONSTRATED 7, ARGUED
    5, PARTIAL 4, MISSED 2, OUT_OF_SCOPE 4); the previous COVERED/PARTIAL/
    MISSED/OUT_OF_SCOPE registry-derived accounting is gone and no grade
    sum is computed anywhere. Note the audit text said "21 entries" but
    its own grade counts sum to 22, so the corpus has 22 entries.
    Four former entries (psychic-signatures, prehash-domain-confusion,
    mldsa-hint-tail, unread-signature-bits) were dropped to make room
    for the named MISSED/OUT_OF_SCOPE entries. (b) The 12-bit ek codec
    in kem_encoding.py and toylwe.py was big-endian bit order; it is now
    FIPS 203 little-endian ByteEncode/ByteDecode_12, unpacking only
    ek[:-32] and leaving the rho tail untouched (verified against real
    @noble/post-quantum 0.6.1: LE-bumped eks are Status.REJECTED for
    ml-kem-512/768/1024). (c) probes.py now classifies strictly via
    EXIT_SKIPPED=77 / EXIT_PARTIAL=78 and _classify(), with the
    SKIP-line-plus-exit-0 case reported as
    "skip-protocol: printed a SKIP line and exited 0"; a unit test
    covers both that and the exit-77 path.

17. **Judge-readiness pass.** (a) PackedEkKem's 12-bit codec is now
    `_bitpack12`/`_bitunpack12`, a big-integer accumulator implementation
    in toylwe.py that shares no code with kem_encoding.py's byte-pair
    codec, so probe_control cross-checks two independent implementations
    (a unit test asserts agreement on 128 coefficients and that toylwe
    imports nothing from kem_encoding). (b) Five Appendix A co-mutants
    were added (decaps_reads_past_ct_dirty, refuses_every_message,
    no_ctx_length_prefix, msg_prefix_only, hint_order_row0_only),
    bringing the mutant total from 36 to 41; selftest verifies each is
    live and caught. Note the audit's per-group breakdown
    (10/15/8/3/2/1/2) does not match the shipped tables, which are
    KEM 12, SIG 16, CODEC 6, LWE 2, PACKED_EK 1, FALCON 2, MLDSA 2 = 41;
    no existing mutant was deleted to force the breakdown. Also,
    `refuses_every_message` (sign refuses all messages) overlaps in
    behaviour with the older `refuses_all_sign`; it is kept as the
    named Appendix A co-mutant.

18. **Canonical Appendix A mutant matrix (supersedes item 17(b)).**
    All mutant tables were renamed to the exact Appendix A keys
    (KEM 10, SIG 15, CODEC 8, LWE 3, PACKED_EK 2, FALCON 1, MLDSA 2
    = 41). The interim names from item 17 (`fo_absent`, `z_not_bound`,
    `unread_last_byte`, `modulus_lax`, …) no longer exist; standing
    probes were updated to the canonical keys. CODEC mutants now live
    on a dedicated Falcon-shaped `ToyStreamCodec`, because the codec
    relations' canonicality questions (signed zero, padding) only
    exist on a sign-magnitude stream surface. `selftest --seeds N`
    (default 1) sweeps N deterministic seeds; `--seeds 10` passes
    with 100% precision and 100% recall on every seed. A `demo`
    subcommand (`python -m pqcheck demo`, ~1.5 s) and a `docs/`
    suite were added; documentation paths and README numbers are
    locked by `probes/verify_paths_resolve.py` and
    `probes/verify_readme_claims.py`.

19. **Phase 11 + independent-audit fix pass (2026-10-27).**
    (a) Phase 11 added universal language adapters, an HTML report,
    and a localhost-only (127.0.0.1) web workbench; zero third-party
    dependencies retained. (b) Audit finding 1: the C/exec adapter
    cannot express prehash mode, so CTarget now reports
    supports_prehash=False and sig-mode-domain-separation declines
    NOT_ANSWERABLE instead of accusing a direct-signing harness.
    (c) Finding 2: the +1 allocation slack was removed from all C
    harnesses (payload + guard exactly); the ASan boundary regression
    skips explicitly on machines without a C compiler (this machine
    has none, so the ASan run itself is unexecuted here).
    (d) Finding 3: NobleTarget.oracle is None; a single-implementation
    run is self-referential, never an independent oracle.
    (e) Finding 4: reproduce shares run''s manifest/version validation.
    (f) Finding 5: reproducer filenames are sanitized (kem:/sig:
    colons become underscores; no NTFS alternate data streams).
    (g) Finding 6: the Rust Falcon codec harness no longer imports
    falcon-rust''s private encoding module; it implements the Falcon
    compression format from spec with compress(coeffs, byte_length),
    and the pinned-upstream facts are recorded in its Cargo.toml.
    No cargo/rustc exists on this machine, so the Rust build itself
    is unexecuted here. (h) Finding 7: probes and manifests ship as
    bundled wheel assets (pqcheck/assets/...), kept byte-identical
    to the checkout by a unit test; checkout-only probes now SKIP
    explicitly (exit 77) under an installed wheel instead of failing.
    (i) Finding 8: the PQClean harness comment no longer contains a
    glob that closes the comment early, and per-algorithm WRAP()
    wrappers keep function-pointer types exact.
    Regression coverage: tests/test_audit_fixes.py (10 tests).
    (j) Verification rerun after the fixes: full Noble 0.6.1 fixture
    passed � 320 claims across ten algorithms, defects exactly the
    two expected padded-Falcon sig-verify-length-exact findings
    (falcon512padded, falcon1024padded), nothing else. Isolated
    wheel install: pqcheck.probes exits 0 (checkout-only probes SKIP
    explicitly). Windows reproducer for a colon-form algorithm name
    is a normal discoverable .py file and replays. NOT executed on
    this machine (no gcc/clang/cc, no cargo/rustc): ASan boundary
    run, native C harness builds, Rust harness build, and the
    external enc_rust vulnerable/fixed comparison (not in this
    workspace) � these remain explicitly unexecuted, not passed.

20. **Item 6 reopened and corrected (supersedes item 19(g)).**
    The audit-fix replacement codec in adapters/rust/ was withdrawn:
    it tested pqcheck''s own newly written code instead of the pinned
    upstream target, and its bit layout did not match Falcon''s
    (8 low bits, 1-run unary) versus the real format (7 low bits,
    0-run unary terminated by 1). Restored: the harness now compiles
    falcon-rust v0.3.0''s own encoding.rs, vendored byte-identical
    (commit 8845fe573b2108a1a84eced6c438a4aeb6b3773c, SHA-256
    f42364d13ccc0449815aab931966a7ffef6158120d55573332c11c228686dcc1,
    enforced by test) because upstream marks the module pub(crate)
    and no external crate can import it. codec_harness.rs is only
    the protocol shell calling upstream compress(coeffs, 625) /
    decompress(stream, 512); a no-op falcon-profiler shim supplies
    upstream''s instrumentation attribute. Added cross-implementation
    encoding vectors (pqcheck/testing/falcon_vectors.json): four real
    Noble falcon512 signature encodings, eight hand-computed spec
    vectors, five negative vectors; pqcheck''s independent spec codec
    (pqcheck/testing/falcon_codec.py) reproduces Noble''s bytes
    exactly on all four signatures. The Rust build itself remains
    unexecuted on this machine (no cargo/rustc); probes and tests
    skip that side explicitly (exit 77 / skipTest) until the binary
    is built, and never claim it passed.

21. **Completion pass: hash portability, enc_rust kit, native CI,
    workbench reports.** (a) The vendored Falcon file was CRLF on
    Windows; it is now LF-normalized, .gitattributes pins eol=lf,
    and the canonical pin is the upstream Git blob
    d8dee7cc5606d6fef1ff9c61e734d25b15136969 (SHA-256 of the LF file
    a6eb5fd5e891c69627b76cd6ef249a54392730000624b5afa6aec78032eae02a);
    verified in a fresh local clone (0 CRLF, both hashes match).
    Supersedes the CRLF hash recorded in item 20. (b) enc_rust
    regression shipped in regressions/enc_rust/ with manifests
    pinning 121385c (vulnerable) and 572a37f (fixed); not executed
    locally (no cargo) - the native CI job executes it. (c) Native
    CI (tools/native_ci.sh) fails on missing tools or skipped
    required checks by design. (d) Workbench gained a Generated
    Reports tab labelling real manifest targets vs toy/reference
    fixtures.
22. **Set 3 (Phases 11-13): detection coverage expansion.**
    (a) `sig-message-binding` extended in place (same relation id):
    lengths around 256/512/1024/4096/65536, max message 65,537
    bytes, max 1,024 altered verifications per algorithm; ToySig
    gained `truncate_message_at` mutants at 4096/8192 for self-test
    recall. (b) Manifests gained optional `validation` metadata
    (FIPS 203 standard/format, ek/dk responsibility
    validate-on-entry|prevalidated-input|unspecified, basis);
    invalid metadata is a manifest error, omitted means
    unspecified. New relations `kem-ek-rejects-noncanonical`
    (<=32 probes) and `kem-dk-rejects-hash-mismatch` decline
    NOT_ANSWERABLE without a validate-on-entry declaration; the
    declaration is recorded as declared, never as proven.
    PackedEkKem (toy) now returns explicit REJ for a dk hash
    mismatch in its clean form (strict contract semantics);
    `kem-dk-hash-consistency` and `kem-ek-modulus-canonical` are
    unchanged. Registry 32 -> 34 relations; counts derive from the
    registry. `manifests/noble.json` now declares validate-on-entry
    for Noble. (c) Noble mutation kit in regressions/noble-mutations
    imports the audit's 13 cases plus an 8192 truncation control and
    two contract controls; mutations patch the pinned BUILT
    JavaScript (hash- and anchor-count-pinned) because that is what
    the adapter executes, rather than rebuilding TypeScript.
    run_kit.py exits 2 on missing/mismatched prerequisites so the
    new CI `noble-kit` job fails loudly; ordinary pqcheck runs keep
    verdict semantics (NOT_REACHED). (d) Wheel packaging needed no
    change: shipped manifest count is 8 (test updated), and the
    shipped-manifests probe now only requires a conclusive run from
    a harness binary runnable on the current platform (an ELF built
    under WSL is not runnable from Windows).
    (e) ToySig gained msg_truncates_at_4096 / msg_truncates_at_8192
    mutants (planted-mutant total 41 -> 43; selftest liveness now
    probes a 9,000-byte message so cutoff mutants are live), and the
    shipped-manifests probe only demands a conclusive run from a
    harness binary runnable on the current platform.
23. **Set 3 follow-up corrections.** (a) Kit replay now validates
    results, not exit codes: a replay counts only on exit 1 plus a
    JSON report naming the filename's relation DEFECT_FOUND;
    stdout/stderr are preserved beside each script; the exit-3
    retry is removed (exit 3 is invalid invocation/manifest).
    Generated reproducers now request `--json` (new reproduce flag).
    (b) Kit acceptance requires consistent report/exit pairs:
    defect cases need exit exactly 1 and validated replays; clean
    and contract controls need zero findings and exit 0;
    kem-reject-truncated-ct again expects both
    kem-reject-binds-full-ciphertext and
    kem-reject-ct-bit-contribution. (c) Manifest validation rejects
    non-string ek/dk values (JSON arrays/objects) with ManifestError
    instead of an unhandled TypeError. (d) sig-message-binding no
    longer infers signing control from PINNED_RANDOMNESS (that
    capability only proves seed-deterministic key generation; Noble
    signing is hedged): signing determinism is observed by signing
    one message twice under one key and reported as observed.
24. **Muse AI Expansion Engine (pqcheck/ai.py).** (a) The spec
    text says "32 deterministic relations"; the registry has 34
    since Set 3, so every count (footer, digest, receipt) derives
    from REGISTRY and reads 34. (b) The secret-material floor the
    spec calls _check_no_secret_material is implemented in ai.py
    over looks_like_secret_material (Claim construction enforces
    the same floor). (c) Two simulated-candidate strategies were
    corrected after the Clean-Reference Precision Gate fired on
    them during development: dk cross-region tampering now targets
    early dk regions (a trailing rejection-seed flip legitimately
    keeps the honest secret), and the multi-bit ciphertext probe
    flips one bit in each of two spread bytes. (d) Muse claims
    carry the spec's oracle label; report footers therefore list
    muse-wonder-1.0 as the oracle for those claims, qualified by
    the label's own execution-verified/clean-control-gated wording.
    It is not an independent implementation oracle.
