# `pqcheck` — Clean-Room Architecture & Engineering Specification

## 1. Executive Summary & Core Thesis

`pqcheck` is a zero-dependency Python 3.10+ assurance and property-testing framework for Post-Quantum Cryptographic (PQC) implementations (KEMs, digital signatures, and wire-format codecs).

Unlike Known-Answer Test (KAT) runners—which fail to catch self-consistent bugs where the same flawed logic produces and checks an artifact—`pqcheck` tests **metamorphic relations and specification invariants** (such as Fujisaki–Okamoto implicit-rejection liveness, Mouha bit-exclusion over guard fills, length-arithmetic wrap boundaries, and signature/key encoding canonicality) that must hold regardless of the specific cryptographic output bytes.

### The Foundational Design Law: Structural Honesty
The primary failure mode of security assurance tools is **reporting a reassuring result over a surface that was never actually tested** (e.g., returning `PASS` when a parser failed, a harness crashed, a positive control failed, or a witness search found no counterexample). `pqcheck` makes unearned reassurance **unconstructible in code**:

1. **Four-Valued Verdict Vocabulary (No `PASS`/`FAIL`):** Every check emits a `Claim` carrying one of four `Verdict` enum values:
   - `DEFECT_FOUND`: The property was tested and violated, or a corroborated, target-attributable memory-safety fault/hang occurred.
   - `NO_DEFECT_FOUND`: The property was tested, reached the target (`Coverage.units > 0` and runner-observed target calls `> 0`), and did not fire.
   - `NOT_REACHED`: The check could not exercise the target (missing build artifact, failed positive control, uncorroborated single crash, assertion abort in a debug build, or external signal). **Never counted as clean.**
   - `NOT_ANSWERABLE`: The relation does not apply to the target's API shape or format geometry (missing `Capability` or raised `NotApplicable`).
2. **No Score, Grade, or Percentage:** `Report.score()` exists solely to raise `NotImplementedError`. Any percentage would divide by the arbitrary count of implemented relations, measuring tool-author effort rather than target security.
3. **One-Sided Witness Checks:** Relations that search for a counterexample witness (such as `kem-fo-liveness`) set `one_sided = True`. When they find no witness, their `NO_DEFECT_FOUND` claim is segregated into `NO_WITNESS_ESTABLISHES_NOTHING` in both human-readable reports and machine-readable `counts()`, and **does not** make a report count as conclusive.
4. **Constructor-Enforced Gates:** `Subject`, `ClassRef`, `Coverage`, and `Claim` validate all honesty invariants inside `__post_init__`, raising `ClaimError` on any violation.
5. **Process Exit Code Contract:**
   - `0`: At least one conclusive result (`DEFECT_FOUND` or two-sided `NO_DEFECT_FOUND`) was reached, and zero `DEFECT_FOUND` claims exist.
   - `1`: At least one `DEFECT_FOUND` claim was emitted.
   - `2`: **The run established nothing** (every claim is `NOT_REACHED`, `NOT_ANSWERABLE`, or one-sided `NO_DEFECT_FOUND`, or the target could not be opened).
   - `3`: The manifest or CLI invocation is invalid before any target is opened.

---

## 2. Repository & Package Layout

```text
blueteam/
├── pyproject.toml                  # Zero runtime dependencies; Python >= 3.10; entry point `pqcheck = pqcheck.cli:main`
├── manifests/                      # Declarative JSON target manifests (noble, c-library, liboqs, pqclean, falcon-codec)
├── pqcheck/
│   ├── __init__.py
│   ├── __main__.py                 # Entry point invoking `pqcheck.cli.main()`
│   ├── verdict.py                  # Verdict, Subject, Method, ClassRef, Coverage, Claim, Report, secret-material guards
│   ├── target.py                   # Status, Outcome, Capability, HarnessProtocolError, process/death/timeout helpers
│   ├── manifest.py                 # Manifest, AdapterSpec, ADAPTERS registry, path/version validation, `--set` overrides
│   ├── discover.py                 # Zero-execution folder discovery (manifests, @noble/post-quantum, ELF/PE/Mach-O binaries)
│   ├── cli.py                      # `pqcheck run | reproduce | relations | adapters | ui`
│   ├── tui.py                      # Dependency-free ANSI + msvcrt/termios interactive terminal UI
│   ├── selftest.py                 # Precision, mutant inertness, recall, and two-sided seed-discrimination gate
│   ├── probes.py                   # Runner for standing regression probes in `probes/verify_*.py`
│   ├── relations/
│   │   ├── __init__.py             # Auto-imports all relation modules so `REGISTRY` is always complete
│   │   ├── base.py                 # Relation base class, Finding, NotApplicable, _CrashWatch, REGISTRY
│   │   ├── core_invariants.py      # C1 (KEM round-trip), C2 (SIG round-trip), C5 (size agreement & length boundaries)
│   │   ├── kem_reject.py           # FO implicit rejection semantics, FO liveness, degenerate ct, ct length check
│   │   ├── kem_encoding.py         # ML-KEM ek modulus canonicality (FIPS 203 §7.2) & dk H(ek) consistency (§7.3)
│   │   ├── sig_generic.py          # Wrong-key, message-binding, degenerate values, ctx-binding, mode separation, exact length
│   │   ├── malleability.py         # Scheme-agnostic length-preserving bit-flip sweep (`sig-unread-bits`)
│   │   ├── encoding.py             # Raw codec round-trip, signed-zero, padding-bits-zero, exact length, decode-reencode, hints
│   │   ├── mldsa_encoding.py       # Verifier-side ML-DSA hint strict order & zero tail (`Capability.MLDSA_HINT_ENCODING`)
│   │   ├── bit_exclusion.py        # Mouha bit-exclusion via 64-byte post-buffer guard fills (KEM & SIG)
│   │   └── length_overflow.py      # CVE-2022-37454 declared-length integer wrap probe (`Capability.DECLARED_LENGTH`)
│   ├── adapters/
│   │   ├── c_harness.c             # Stdin/stdout hex line-protocol C harness with exact-sized malloc & guard-fill support
│   │   ├── cbridge.py              # `CTarget` driver for `c_harness.c`
│   │   ├── codec_harness.c         # Stdin/stdout C harness for raw signature/hint codecs (`RAW_DECODE`)
│   │   ├── codec_bridge.py         # `CodecTarget` driver
│   │   ├── hint_harness.c          # Stdin/stdout C harness for ML-DSA `unpack_sig` hint decoding
│   │   ├── hint_bridge.py          # `HintTarget` driver
│   │   ├── noble_bridge.mjs        # Node.js JSON-lines bridge for `@noble/post-quantum`
│   │   └── noble.py                # `NobleTarget` driver
│   ├── testing/
│   │   ├── toy.py                  # `ToyKem`, `ToySig` and their planted defect mutant tables
│   │   ├── toylwe.py               # `ToyLweKem` (real compression fibers for FO liveness) & `PackedEkKem` (12-bit mod q)
│   │   ├── toyfalcon.py            # `ToyFalconSig` (sign-magnitude + unary codec inside sign/verify)
│   │   ├── toymldsa.py             # `ToyMldsaSig` (FIPS 204 detached signature with hint block)
│   │   ├── toycodec.py             # `ToyCodec` (standalone `RAW_DECODE` + hint codec fixture)
│   │   ├── precision.py            # 8 spec-compliant non-ML-KEM/non-Falcon targets to catch false-positive relations
│   │   └── fiber_probe.py          # Empirical measurement of decryption-fiber collision rates
│   └── backtest/
│       ├── corpus.py               # 22 historical PQC/crypto implementation defects mapped to relations
│       └── report.py               # Backtest coverage accounting (`COVERED`, `PARTIAL`, `MISSED`, `OUT_OF_SCOPE`)
└── probes/
    └── verify_*.py                 # Standing bidirectional regression probes (exit 0 = pass, 77 = skip, 78 = partial)
```

---

## 3. Layer 1: The Verdict & Claim Engine (`pqcheck/verdict.py`)

### 3.1 `Verdict` Enum
```python
class Verdict(str, Enum):
    DEFECT_FOUND = "DEFECT_FOUND"
    NO_DEFECT_FOUND = "NO_DEFECT_FOUND"
    NOT_REACHED = "NOT_REACHED"
    NOT_ANSWERABLE = "NOT_ANSWERABLE"

CONCLUSIVE = frozenset({Verdict.DEFECT_FOUND, Verdict.NO_DEFECT_FOUND})
```
*Identity Rule:* `Claim.__post_init__` checks `isinstance(self.verdict, Verdict)`. Passing the raw string `"NO_DEFECT_FOUND"` (which is `==` to `Verdict.NO_DEFECT_FOUND` because `Verdict` subclasses `str`, but fails `is` checks) MUST raise `ClaimError`.

### 3.2 `Subject` & Moving-Reference Denylist
```python
@dataclass(frozen=True)
class Subject:
    target: str                  # e.g. "@noble/post-quantum", "liboqs"
    commit: str                  # Resolved commit SHA or exact release tag; NEVER a moving ref
    algorithm: str | None = None # e.g. "ML-KEM-768"
    component: str | None = None
```
- **Validation (`__post_init__`):**
  - `commit` must be non-empty after stripping.
  - `commit.lower()` must not be in `MOVING_REFS`:
    `{"latest", "head", "main", "master", "trunk", "tip", "default", "dev", "devel", "develop", "current", "newest", "stable", "release", "unknown", "unspecified", "n/a", "na", "none", "null", "tbd", "?", "*", "-", "vendored", "liboqs-vendored", "bundled", "local", "wip", "test", "temp", "placeholder"}`.
  - String representation: `" / ".join([target, commit[:12], algorithm?, component?])`.

### 3.3 `Method`, `ClassRef`, and `Coverage`
- **`Method(name: str, oracle: str | None, version: str | None = None)`**:
  - `oracle` names the independent reference implementation when differential testing is used, or `None` when the check is an internal invariant.
- **`ClassRef(ident: str, url: str, what: str)`**:
  - Links a relation to the public CVE/GHSA/issue that established the bug class.
  - **Validation:** If `ident.startswith("GHSA-")` and `"/advisories/"` is in `url` without `"/security/advisories/"`, raise `ClaimError` (repository-level GHSAs 404 on the global GitHub advisory URL).
- **`Coverage(exercised: str, units: int = 0, observed: str = "")`**:
  - `is_empty()` returns `True` if `self.units <= 0 or not self.exercised.strip()`.
  - `observed` is populated exclusively by the relation runner (`_CrashWatch` call counter) and never by the relation itself, preventing a relation from claiming `units=50000` while making `0` target calls.

### 3.4 Secret-Material Floor (`looks_like_secret_material` & `redact_target_output`)
Reports are designed to be pasted into public bug trackers.
- **`looks_like_secret_material(text: str) -> str | None`**:
  - Scans for contiguous hexadecimal runs of length `>= 48` (24+ bytes; above a 40-char git SHA, below a 32-byte shared secret or SHA-256 digest—no carve-out for digests) via `r"[0-9a-fA-F]{48,}"`.
  - Scans for contiguous base64 runs of length `>= 40` (`r"[A-Za-z0-9+/]{40,}={0,2}"`) that contain at least one lowercase letter, one uppercase letter, and one digit.
- **Refusal vs. Redaction:**
  - Text authored by `pqcheck` relations (`property`, `ceiling`, `evidence`, `reproduce`, `notes`, and every element of `premises`) is checked in `Claim.__post_init__`; any match raises `ClaimError` so a leaky relation breaks the build immediately.
  - Text quoted from a target's own `stderr` or crash detail is passed through `redact_target_output(text)` at the adapter boundary, replacing matching runs with `[N hex/base64 chars redacted by pqcheck: quoted from the target]` so a crashing library that dumps keys to `stderr` still produces a valid crash report.

### 3.5 `Claim` Validation Rules (`Claim.__post_init__`)
```python
@dataclass(frozen=True)
class Claim:
    subject: Subject
    property: str
    verdict: Verdict
    method: Method
    ceiling: str
    coverage: Coverage | None = None
    evidence: str = ""
    reproduce: str = ""
    notes: str = ""
    class_refs: tuple[ClassRef, ...] = ()
    premises: tuple[str, ...] = ()
    one_sided: bool = False
```
`Claim.__post_init__` MUST enforce:
1. `isinstance(self.verdict, Verdict)` (reject plain strings).
2. `self.property.strip()` is non-empty.
3. `self.ceiling.strip()` is non-empty (every claim states what it does **not** establish).
4. If `verdict is Verdict.NO_DEFECT_FOUND`: `coverage` must not be `None` and `not coverage.is_empty()`.
5. If `verdict is Verdict.DEFECT_FOUND`: `reproduce.strip()` must be at least 12 characters (`_REPRODUCE_MIN_CHARS = 12`) AND either contain at least 3 whitespace-separated words (`_REPRODUCE_MIN_WORDS = 3`) or contain a path separator (`/` or `\`).
6. `premises` must not be a bare `str` (must be a `tuple[str, ...]`).
7. If `verdict is Verdict.NOT_ANSWERABLE`: `notes.strip()` must be non-empty.
8. If `verdict is Verdict.NOT_REACHED`: `evidence.strip() or notes.strip()` must be non-empty.
9. None of `property`, `ceiling`, `evidence`, `reproduce`, `notes`, or `premises` may trigger `looks_like_secret_material` (handling `None` safely via `or ""`).

### 3.6 `Report` Aggregation & Rendering
- `counts() -> dict[str, int]`: Returns counts for each `Verdict` value plus `"NO_WITNESS_ESTABLISHES_NOTHING"`. Any claim with `verdict is Verdict.NO_DEFECT_FOUND and one_sided is True` increments `"NO_WITNESS_ESTABLISHES_NOTHING"` instead of `"NO_DEFECT_FOUND"`.
- `is_conclusive_anywhere() -> bool`: `True` iff at least one claim has `verdict is Verdict.DEFECT_FOUND` or (`verdict is Verdict.NO_DEFECT_FOUND and not one_sided`).
- `exit_code() -> int`:
  - `1` if `self.defects()` is non-empty.
  - `2` if `not self.is_conclusive_anywhere()`.
  - `0` otherwise.
- `to_text() -> str`:
  - If `not is_conclusive_anywhere()`, prints a prominent banner: `*** THIS RUN ESTABLISHED NOTHING ***`.
  - Renders five sections in strict order so gaps are seen before clean results:
    1. `DEFECTS FOUND: <N>` (marker `!`)
    2. `NOT REACHED: <N>  <- these are NOT clean; nothing was established here` (marker `?`)
    3. `NO DEFECT FOUND: <N>` (marker `.`)
    4. `NO WITNESS FOUND — ESTABLISHES NOTHING: <N>` (marker `~`, when non-empty)
    5. `OUT OF SCOPE FOR THIS TOOL: <N>` (marker `-`, when non-empty)
  - Every entry in every section prints the full `Subject`, the `property`, any `oracle:` line, any `rests on:` premises, and (where coverage is present) `units: <U> | observed by the runner: <O>`.
  - Footer explicitly states whether an independent oracle was used or whether all checks were self-referential invariants.
- `emit(text, stream=None)`: Safely writes UTF-8 reports even on legacy Windows consoles (`cp437`/`cp1252`) by testing encoding up front and falling back to `stream.buffer.write(payload.encode("utf-8"))` after flushing.

---

## 4. Layer 2: The Target Seam & Death Contract (`pqcheck/target.py`)

### 4.1 `Status` and `Outcome`
```python
class Status(str, Enum):
    OK = "OK"
    REJECTED = "REJECTED"   # Controlled refusal (error return, exception). Target is WORKING.
    CRASHED = "CRASHED"     # Uncontrolled failure (segfault, ASan report, malformed protocol output).
    TIMEOUT = "TIMEOUT"     # Per-call deadline exceeded.

@dataclass(frozen=True)
class Outcome:
    status: Status
    value: bytes | tuple[bytes, ...] | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is Status.OK

    @property
    def is_finding(self) -> bool:
        return self.status in (Status.CRASHED, Status.TIMEOUT)
```
- **`HarnessProtocolError(RuntimeError)`**: Raised when the *adapter/harness* cannot marshal or execute a request (e.g., `ERR` reply from C harness). Never mapped to `Status.REJECTED` (which would falsely credit the target with rejecting bad input) or `Status.CRASHED` (which would falsely accuse the target of memory unsafety).

### 4.2 `Capability` Enum
Targets declare `caps: frozenset[Capability]`:
- `KEM = "kem"`: Target exposes `keygen(seed) -> (ek, dk)`, `encaps(ek, m?) -> (ss, ct)`, `decaps(dk, ct) -> ss`.
- `SIG = "sig"`: Target exposes `keygen(seed) -> (pk, sk)`, `sign(sk, msg, ctx=b"", **kw) -> sig`, `verify(pk, msg, sig, ctx=b"", **kw) -> None`.
- `PINNED_RANDOMNESS = "pinned_randomness"`: Target exposes deterministic keygen/encaps/sign when given a seed/tape.
- `DETACHED_SIG = "detached_sig"`: `sign()` returns a detached signature rather than `sig || msg`.
- `EXTERNAL_MU = "external_mu"`: Verify takes precomputed $\mu$ rather than message $M$.
- `CTX_STRING = "ctx_string"`: Target and adapter can express a FIPS 204 context string on `sign`/`verify`.
- `EXPLICIT_SIG_LENGTH = "explicit_sig_length"`: Target API receives explicit buffer lengths from the caller so length mutations are observable.
- `RAW_DECODE = "raw_decode"`: Target exposes standalone `encode(coeffs)` and `decode(sig_bytes)` (and optionally `encode_hints`/`decode_hints`).
- `MLDSA_HINT_ENCODING = "mldsa_hint_encoding"`: Target declares exact FIPS 204 hint-block geometry (`mldsa_hint = {"ctilde": ..., "z": ..., "omega": ..., "k": ...}`) on detached signatures.
- `DECLARED_LENGTH = "declared_length"`: Memory-safe target accepts `declared_len=` on `sign`/`verify` independently of the supplied byte buffer length.
- `GUARD_FILL = "guard_fill"`: Adapter supports placing caller-chosen bytes (`target.guard(fill)`) immediately past the declared length of every input buffer.

### 4.3 Process Death Attribution & Deadline Contract
Three string markers in `target.py` govern how child-process failures are classified across all adapters:
- `POST_MORTEM = "[post-mortem]"`: Attached by `post_mortem(proc, stderr_text)` to every call made *after* a child process has already died. Prevents a single crash from being counted $N$ times across subsequent loop iterations and self-corroborating past the `> 1` crash gate.
- `NOT_ATTRIBUTABLE = "NOT attributable to the target"`: Attached by `classify_exit(rc)` when a child dies from an external signal (`SIGHUP=1`, `SIGINT=2`, `SIGKILL=9`, `SIGPIPE=13`, `SIGTERM=15`, or WSL status `1`) rather than a fault signal (`SIGILL=4`, `SIGABRT=6`, `SIGBUS=7`, `SIGFPE=8`, `SIGSEGV=11`) or sanitizer exit.
- `DEADLINE_KILLED = "killed by pqcheck's own deadline"`: Attached when `readline_deadline(proc, timeout_s)` kills a hung child (`proc._pqcheck_deadline_killed = True`). Subsequent relations on the same target see `DEADLINE_KILLED` and report `NOT_REACHED` attributing the kill to the earlier relation's timeout rather than blaming the user's CI environment.

---

## 5. Layer 3: The Relation Runner & Crash State Machine (`pqcheck/relations/base.py`)

### 5.1 `_CrashWatch` Proxy
Every relation's `check(watched, rng)` receives a `_CrashWatch(target)` proxy, never the raw target:
- Stores the underlying target in name-mangled `_CrashWatch__target` and raises `AttributeError` on any attempt to access `_t`, `__target`, or `_CrashWatch__target`.
- Counts total invocations in `watched.calls` and per-operation tallies in `watched.ops`.
- Records `(op_name, out.status, out.detail)` in `watched.crashes` whenever `out.is_finding` is `True`.
- Uses `functools.wraps` so `inspect.signature(watched.sign)` preserves parameter introspection (e.g., `prehash`).

### 5.2 `Relation.run(target, subject, rng) -> Claim` Execution Order
1. **Premise & Oracle Collection:** Collects target attributes listed in `self.premise_attrs` and reads `oracle = getattr(target, "oracle", None)`.
2. **Applicability Gate:** If `missing = self.requires - set(target.caps)` is non-empty, returns `Verdict.NOT_ANSWERABLE` naming the missing capabilities in `notes`.
3. **Positive Control Gate (`if self.needs_control`):**
   - Calls `passed, desc = self.control(target)`.
   - If `NotApplicable` is raised -> `Verdict.NOT_ANSWERABLE`.
   - If any other `Exception` is raised -> `Verdict.NOT_REACHED` with neutral attribution: `"EITHER pqcheck could not use this target's reply, OR the target produced a reply it should not have. This runner cannot tell which; do not read it as exonerating the target"`.
   - If `not passed` -> `Verdict.NOT_REACHED` (`"positive control failed: ..."`).
4. **Constructed-Probe Control Gate (`if self.constructs_probes`):**
   - Enforced at `@register` time: any relation with `constructs_probes = True` MUST override `probe_control(target)`.
   - `probe_control` builds the benign twin of the relation's constructed probe (same packing logic with the defect removed) and verifies the target accepts it and decodes it to the expected structure.
   - If `probe_control` returns `False` or raises -> `Verdict.NOT_ANSWERABLE` (the assumed layout does not describe this target).
5. **Execute `f = self.check(watched, rng)`:**
   - `NotApplicable` -> `Verdict.NOT_ANSWERABLE`.
   - Any other `Exception` -> `Verdict.NOT_REACHED` with neutral attribution note.
6. **Crash & Timeout Adjudication (Outranks `f`):**
   - Partition `watched.crashes` into `fresh` (excluding `POST_MORTEM`), `external` (containing `NOT_ATTRIBUTABLE`), and `deadline` (containing `DEADLINE_KILLED`).
   - If `deadline` and not `fresh` -> `Verdict.NOT_REACHED` (harness was killed by `pqcheck`'s deadline during an earlier relation).
   - If `external` and not `fresh` -> `Verdict.NOT_REACHED` (process killed by external signal).
   - Separate `fresh` into `timeouts` (`Status.TIMEOUT`) and `faults`. If `f.held is False`, preserve the relation's own defect conclusion in a `withheld` note attached to the claim.
   - **Timeouts (`if timeouts and not faults`):** Single timeout -> `Verdict.NOT_REACHED` (uncorroborated hang/stall). Multiple timeouts (`len(timeouts) > 1`) -> `Verdict.DEFECT_FOUND` reporting a reproducible hang (explicitly stating in `ceiling` and `notes` that a hang is an availability defect, not memory unsafety).
   - **Lying-Length Probes (`if watched.crashes and self.probes_lie_about_length`):** Returns `Verdict.NOT_REACHED` explaining the crash is ambiguous between a CVE-2022-37454 target overflow and an adapter falsely declaring `Capability.DECLARED_LENGTH`.
   - **Corroboration Gate:** `confirmed = len(faults) > 1 or (callable(alive) and not alive() and bool(faults))`. Uncorroborated single fault while process remains alive -> `Verdict.NOT_REACHED`.
   - **Assertion Partition:** Partition `pool` into `soft` (matching `\bassert(ion)?\b(?!\w)|\bpanicked at\b|\bdebug_assert\b`) and `hard` (non-assertion crashes such as `AddressSanitizer` or `SIGSEGV`).
     - If `soft` and not `hard` -> `Verdict.NOT_REACHED` (debug precondition assertion abort, not memory unsafety).
     - Re-corroborate `hard` on its own (`len(hard) > 1 or (not alive() and hard)`). If uncorroborated -> `Verdict.NOT_REACHED`.
     - Otherwise -> `Verdict.DEFECT_FOUND` (memory-safety fault), reporting `len(hard)` deaths (never post-mortem repeats).
7. **Zero-Call Honesty Gate:**
   - If `f.held is not None and f.units > 0 and watched.calls == 0` -> `Verdict.NOT_REACHED` (relation claimed coverage while making zero calls to the target).
8. **Zero-Observation Gate:**
   - If `f.held is None or f.units <= 0` -> `Verdict.NOT_REACHED` (no comparable observation obtained).
9. **Conclusive Verdict Construction:**
   - `f.held is True` -> `Verdict.NO_DEFECT_FOUND` with `Coverage(f.exercised, f.units, _observed(watched))` and `one_sided=self.one_sided`.
   - `f.held is False` -> `Verdict.DEFECT_FOUND` with `Coverage(f.exercised, f.units, _observed(watched))` and fallback reproducer if `f.reproduce` is empty.

---

## 6. Layer 4: The 32 Registered Relations (`pqcheck/relations/`)

All relations are registered via `@register` in `pqcheck.relations.base.REGISTRY` and auto-imported by `pqcheck/relations/__init__.py`.

### 6.1 Core Invariants (`core_invariants.py`, `length_overflow.py`, `encoding.py`)
| Relation ID | Requires | Control? | Property & Probe Mechanics |
|---|---|---|---|
| `core-kem-round-trip` | `KEM` | **No** (Loud Reporter) | Generates 2 keypairs, 2 encapsulations each; verifies `decaps(dk, ct) == ss`. |
| `core-sig-round-trip` | `SIG` | **No** (Loud Reporter) | Signs & verifies 5 message shapes (`0`, `1`, `32`, `137`, `1024` bytes). If keygen succeeds and all 5 signing calls are refused, emits `DEFECT_FOUND` (a signer that refuses all messages cannot hide behind `NOT_REACHED`). |
| `core-codec-round-trip` | `RAW_DECODE` | **No** (Loud Reporter) | Encodes reference coefficient vector (with byte-misalignment bump `1 << lowbits` at index 0) and plain vector, verifies `decode(encode(v))` succeeds and recovers `v` across the 4 modelled coefficient views (`as returned`, `signed bytes`, `2-byte LE`, `2-byte BE`). |
| `core-declared-sizes-match-produced` | `frozenset()` | No | Compares `target.sizes` against produced byte lengths for keys in `target.measured_sizes` (fails closed to `NOT_REACHED` if `measured_sizes` is `None`). Respects `size_semantics` (`"exact"` vs `"max"`). |
| `core-input-length-boundaries` | `SIG` | Yes | Sweeps `B-1, B, B+1` around 15 boundaries (`16, 32, 64, 72, 104, 128, 136, 144, 168, 255, 256, 512, 1024, 4096, 65536`) plus `0, 1, 2`. Distinguishes isolated boundary arithmetic failures (`B` fails while `B-1` and `B+1` pass) from contiguous size caps. |
| `core-declared-length-overflow` | `SIG`, `DECLARED_LENGTH` | Yes (checks parameter liveness) | Sets `probes_lie_about_length = True`. Supplies a 32-byte buffer while declaring lengths `m + 2^k` (byte wrap), `m + 2^(k-3)` (`len*8` bit wrap), and `2^k - 1` for `k in (16, 32, 64)` on `sign` and `verify`. Any `OK` return is a `DEFECT_FOUND` (CVE-2022-37454 class). |

### 6.2 KEM Implicit Rejection & Input Validation (`kem_reject.py`, `kem_encoding.py`)
| Relation ID | Requires | Control / Flags | Property & Probe Mechanics |
|---|---|---|---|
| `kem-reject-ct-bit-contribution` | `KEM` | `needs_control=True` | Flips bits `(0, 3, 7)` at 7 offsets across `ct`. Excludes honest-secret returns (owned by `kem-fo-liveness`). Requires `>= 2` comparable rejection values, global variation (`len(seen) > 1`), and per-offset variation (no byte offset returning the same rejection secret across all 3 bit flips). |
| `kem-reject-binds-full-ciphertext` | `KEM` | `needs_control=True` | Flips masks `0x01` and `0x02` at every byte `0..len(ct)-1`. Flags any byte where both masks produce the same rejection secret (distinguishing contiguous truncated-absorb runs from scattered plaintext-checking-oracle leaks) or where two byte positions collide. |
| `kem-reject-binds-z-accept-path-does-not` | `KEM` | `needs_control=True` | Generates two keypairs (verifying `ek1 != ek2` and `dk1 != dk2` to avoid misattributing broken keygen RNG to `z`), corrupts `ct` at 4 positions, and checks that `decaps(dk1, bad) != decaps(dk2, bad)`. |
| `kem-reject-determinism` | `KEM` | `needs_control=True` | Decapsulates a corrupted ciphertext twice per iteration across 8 iterations; requires `a.value == b.value`. |
| `kem-fo-liveness` | `KEM` | `needs_control=True`, `one_sided=True` | Flips bits `(0, 1, 7)` across ciphertext bytes checking if `decaps(dk, bad) == ss` (the honest secret). Stops only when `len(wbytes) > 4` AND at least one bound byte (`swept - len(wbytes) > 0`) is observed. Classifies witness sets by bit-leakage mask diversity (`len(shapes) > 1` -> absent/partial FO check; uniform mask with bound bytes -> unverified region/malleability; narrow `<= 4` bytes -> slack vs truncated compare). |
| `kem-degenerate-ciphertext` | `KEM` | `needs_control=True` | Probes `all-zero`, `all-0xFF`, `first half zeroed`, and `second half zeroed` ciphertexts twice each; requires deterministic, pairwise-distinct outputs unequal to `ss`. |
| `kem-decaps-length-exact` | `KEM`, `EXPLICIT_SIG_LENGTH` | `needs_control=True` | Probes `ct[:-1]`, `ct + b"\x00"`, `ct[:len//2]`, `b""`, and `ct + ct`; requires all 5 to be rejected. |
| `kem-ek-modulus-canonical` | `KEM` | `needs_control=True`, `constructs_probes=True` | Unpacks 12-bit ML-KEM `ek` coefficients ($k \in \{2,3,4\}$). `probe_control` verifies unpack/repack is byte-identical. Raises one bumpable coefficient (`c + 3329 <= 4095`) per spread anchor across all $k$ polynomials; checks if `encaps(bad_ek)` is accepted and whether `decaps(dk, ct2) == ss2`. |
| `kem-dk-hash-consistency` | `KEM` | `needs_control=True`, `constructs_probes=True` | Splits FIPS 203 Algorithm 16 `dk` into `(dk_PKE, ek, h, z)`. `probe_control` verifies embedded `ek` matches `keygen`'s `ek` and `h == SHA3-256(ek)`. Alters `h` (3 single-bit flips, all-zero, all-0xFF) and verifies `decaps(bad_dk, ct)` never returns the honest `ss` and remains deterministic. |

### 6.3 Signature Soundness, Malleability & Bit-Exclusion (`sig_generic.py`, `malleability.py`, `bit_exclusion.py`)
| Relation ID | Requires | Control / Flags | Property & Probe Mechanics |
|---|---|---|---|
| `sig-wrong-key-rejection` | `SIG` | `needs_control=True` | Over 8 messages, establishes a verified baseline `(pk1, sk1, msg, sig)` via `_baseline()`, generates independent `pk2 != pk1`, and requires `verify(pk2, msg, sig)` to be rejected. |
| `sig-message-binding` | `SIG` | `needs_control=True` | Across 8 lengths (`1, 8, 9, 16, 33, 64, 137, 300`), signs `msg`, confirms baseline verify, and probes 6 message edits (random same-length, last byte flipped, first byte flipped, `msg[:-1]`, `b""`, `msg + b"\x00"`). |
| `sig-degenerate-values` | `SIG` | `needs_control=True` | Sizes probes from a baseline-verified signature (and declared size if different); tests `all-zero sig`, `all-0xFF sig`, and `all-zero sig under all-zero pk` (CVE-2022-21449 Psychic Signatures class). |
| `sig-ctx-binding` | `SIG`, `CTX_STRING` | `needs_control=True` | Tests 4 context-only variations and 2 `(ctx, msg)` length-ambiguity splits (`ctx="a", msg="bc"` vs `ctx="ab", msg="c"`; `ctx="", msg="ab"` vs `ctx="a", msg="b"`) to verify `len(ctx)` framing in FIPS 204 $M'$. |
| `sig-mode-domain-separation` | `SIG` | `needs_control=True` | Inspects `target.sign` for `prehash` parameter; requires both `False -> True` and `True -> False` directions to be usable (`n == 2`) and rejected on cross-mode verification. |
| `sig-verify-length-exact` | `SIG`, `EXPLICIT_SIG_LENGTH`, `DETACHED_SIG` | `needs_control=True` | Fails closed (`NotApplicable`) if `target.fixed_sig_len` is `None` or `False`. Probes `+1 zero byte`, `+1 0xFF byte`, `+50 zero bytes`, and `truncated by 1`. Discloses `sig_len_basis` premise. |
| `sig-unread-bits` | `SIG` | `needs_control=True` | Sweeps up to `max_probes=4096` bits from the end of the signature backwards across up to `n_signatures=8` independent signatures (bucketed by signature bit-length). When unread bit positions `w_pos` are found in a witness signature, tests up to `max_combos=512` multi-bit combinations on that witness signature to measure exact encoding multiplicity ($2^N$ vs bounded Hamming weight). |
| `kem-declared-length-bit-exclusion` | `KEM`, `GUARD_FILL` | `needs_control=True` | Runs `decaps(honest ct)`, `decaps(first-byte-flipped ct)`, `decaps(last-byte-flipped ct)` (plus `encaps` if `PINNED_RANDOMNESS`) under 64-byte guard fills `0x00`, `0xFF`, `pseudo-random`, and `0x00 again` (determinism check). Rescues control under zero-fill if dirty heap broke exact-sized control. Always clears `target.guard(None)` in `finally`. |
| `sig-declared-length-bit-exclusion` | `SIG`, `GUARD_FILL` | `needs_control=True` | Runs `verify` on honest signatures at 5 lengths (`1, 33, 135, 136, 137` straddling the SHA3-256 136-byte rate), `verify` on 1 corrupted signature, and `sign` (when deterministic) across the four 64-byte guard fills. |

### 6.4 Signature & Hint Codecs (`encoding.py`, `mldsa_encoding.py`)
| Relation ID | Requires | Control / Flags | Property & Probe Mechanics |
|---|---|---|---|
| `sig-encoding-signed-zero` | `RAW_DECODE` | `needs_control=True`, `constructs_probes=True` | Builds a Falcon-shaped stream `[sign] + [0]*lowbits + [1]`. `probe_control` verifies canonical all-zero stream (`first_sign=0`) decodes to `ncoef` zeros under `_view()` AND verifies the `-0` probe (`first_sign=1`) is not produced by `target.encode` for small vectors. Checks that `decode(stream(1))` is rejected. |
| `sig-encoding-pad-bits-zero` | `RAW_DECODE` | `needs_control=True` | Binary-searches `pad_start` using monotonicity of `holds(j)` ("zeroing bits `j..total` decodes to the same coefficients under `_view`"), verifies midpoint monotonicity, and flips bits/bytes across the measured padding region (`<= 512` bits: every bit; `> 512` bits: up to 64 spread bytes including both ends). |
| `sig-encoding-length-exact` | `RAW_DECODE` | `needs_control=True` | Requires `target.fixed_sig_len is True`. Probes `ref[:-1]`, `ref + b"\x00"`, `ref + b"\xff"`, `ref + ref`, and `ref.rstrip(b"\x00")` (exact-fit unpadded truncation). |
| `sig-encoding-decode-reencode-identity` | `RAW_DECODE` | `needs_control=True` | Calibrates coefficient view at small magnitudes `_CAL`, finds max realistic Gaussian-shaped magnitude `_span()`, and tests `encode(view(decode(encode(coeffs)))) == encode(coeffs)` across 6 scaled magnitudes `span >> k`. |
| `mldsa-hint-strict-order` | `RAW_DECODE` | `needs_control=True` | Encodes `[[1, 3]] * rows` across all polynomial rows (`min(k, omega // 2)`), mutates each row to `[1, 1]` (repeated) and `[3, 1]` (descending), and requires `decode_hints` to reject all. |
| `mldsa-hint-tail-zero` | `RAW_DECODE` | `needs_control=True` | Encodes `[[1, 3], [5]]` (3 used hints), sets each unused byte `3..omega-1` to `0x7F`, and requires `decode_hints` to reject all. |
| `mldsa-verify-hint-strict-order` | `SIG`, `DETACHED_SIG`, `MLDSA_HINT_ENCODING` | `needs_control=True` | Verifier-side twin: signs up to 8 messages until an honest signature has a polynomial row with `>= 2` hint indices; swaps/repeats those two indices in the signature's hint block and requires `verify()` to reject. |
| `mldsa-verify-hint-tail-zero` | `SIG`, `DETACHED_SIG`, `MLDSA_HINT_ENCODING` | `needs_control=True` | Verifier-side twin: takes an honest signature with `used < omega`, sets each unused hint-index byte `start + pos` (`pos in used..omega-1`) to `0x7F`, and requires `verify()` to reject. |

---

## 7. Layer 5: Adapters & Wire Protocols (`pqcheck/adapters/`)

### 7.1 Generic C Adapter (`c_harness.c` & `cbridge.py`)
- **Invocation:** `./harness <kem|sig> <algorithm>` (or via `wsl.exe` on Windows when `wsl=True`).
- **Stdin/Stdout Line Protocol:**
  - `info` -> `OK kind=<kem|sig> alg=<name> pk=<N> sk=<N> [ct=<N> ss=<N> | sig=<N>] guard=1`
  - `keygen <seed_hex>` -> `OK <pk_hex> <sk_hex>` (note: `pqc_kem_keygen`/`pqc_sig_keygen` take no seed; `cbridge.py` records this in `randomness_basis`).
  - `sign <sk_hex> <msg_hex>` -> `OK <sig_hex>` | `REJ <reason>` | `ERR <reason>` (empty buffer is sent as `-`).
  - `verify <pk_hex> <msg_hex> <sig_hex>` -> `OK` | `REJ <reason>` | `ERR <reason>`
  - `encaps <ek_hex>` -> `OK <ss_hex> <ct_hex>` | `REJ <reason>` | `ERR <reason>`
  - `decaps <dk_hex> <ct_hex>` -> `OK <ss_hex>` | `REJ <reason>` | `ERR <reason>`
  - `guard <fill_hex>` | `guard -` -> `OK guard=<n>`
- **Exact-Sized Buffer Rule:** Every input and output buffer in `c_harness.c` is `malloc`'d to the exact byte length (plus `guard_n` on inputs when a guard fill is active). Never stack-allocated or rounded up, so AddressSanitizer catches 1-byte over-reads/over-writes.
- **Driver Guarantees (`CTarget`):**
  - Routes child `stderr` to a `tempfile.TemporaryFile` (never an undrained pipe, which deadlocks after 64 KB of sanitizer output).
  - Confirms `info` reports matching `kind` and `alg` (casefolded).
  - Refuses stateful hash-based signature schemes (`LMS`, `HSS`, `XMSS`, `XMSSMT`) at startup because the stateless line protocol does not persist advancing secret-key state across `sign` calls.
  - Infers `fixed_sig_len` on `SIG` targets by signing 6 messages of lengths `(0, 1, 31, 32, 100, 513)` and checking whether all 6 equal `sizes["sig"]`, recording the reasoning in `self.sig_len_basis`.

### 7.2 JavaScript Adapter (`noble_bridge.mjs` & `noble.py`)
- **Invocation:** `node noble_bridge.mjs <algorithm>` with `cwd=node_cwd` and `PQCHECK_NODE_CWD=node_cwd`.
- **Protocol:** JSON-lines over stdin/stdout supporting `info`, `keygen`, `encaps`, `decaps`, `sign` (with optional `ctx`, `prehash`, `seed`), and `verify`.
- **Capabilities:** Declares `PINNED_RANDOMNESS` (when `seed` length is published and deterministic), `EXPLICIT_SIG_LENGTH`, `DETACHED_SIG` (for `SIG`), `CTX_STRING` (probed for expressibility at startup), and `MLDSA_HINT_ENCODING` (for `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`).

### 7.3 Raw Codec & Hint Adapters (`codec_harness.c` / `codec_bridge.py` & `hint_harness.c` / `hint_bridge.py`)
- **`CodecTarget`:** Drives PQClean's Falcon `comp_encode`/`comp_decode` over a line protocol (`info`, `encode <c0> <c1> ...`, `decode <hex>`), declaring `Capability.RAW_DECODE` and setting `oracle` to the reference implementation label.
- **`HintTarget`:** Drives `mldsa-native`'s `polyeta`/`unpack_sig` over a line protocol (`info`, `encode_hints`, `decode_hints`), declaring `Capability.RAW_DECODE` and setting `oracle`.

---

## 8. Layer 6: Manifests, Folder Discovery, CLI & TUI

### 8.1 Declarative Manifests (`pqcheck/manifest.py`)
JSON file with fields:
- Required: `"target"` (string), `"version"` (string, validated via `Subject` to reject moving refs), `"adapter"` (`"c" | "noble" | "codec" | "hint"`), plus adapter-specific required fields (`"harness"` or `"node_cwd"`), and `"algorithms"` (non-empty list of strings for `"c"` and `"noble"`; forbidden for `"codec"` and `"hint"`).
- Relative paths in `"harness"` and `"node_cwd"` resolve relative to the **manifest file's directory**, with `~` and `${ENV}` expanded.
- `missing_paths()` and `wrong_version()` (which cross-checks `@noble/post-quantum/package.json` version against `manifest.version`) return human-readable problem strings that cause `pqcheck run` to emit `NOT_REACHED` for every relation and exit `2`.

### 8.2 Safe Folder Discovery (`pqcheck/discover.py`)
When `pqcheck run <folder>` is given a directory instead of a JSON file:
- Walks up to `_MAX_DEPTH = 5` skipping non-build dot/cache dirs (`_SKIP_DIRS`), while deliberately searching `build/`, `out/`, `bin/`, `target/`.
- Identifies 4 candidate types **without executing any discovered binary**:
  1. Valid `pqcheck` manifest JSON files (`kind="manifest"`, ready if paths exist).
  2. Installed `node_modules/@noble/post-quantum` (`kind="noble"`, reads version from `package.json`, checks dependencies, parses algorithm list from `noble_bridge.mjs`).
  3. Compiled harness binaries (`kind="harness"`, detected by ELF `\x7fELF`, PE `MZ`, or Mach-O magic bytes, excluding CMake/Cargo build-script intermediates). Always marks `"version"` (and `"algorithms"` for `"c"`) in `candidate.missing` because **a compiled binary cannot state which commit of the library it was linked against**, forcing the CLI/UI to prompt or require `--set`.
  4. Unbuilt C/Rust library source trees (`missing=("needs_build",)`), printing instructions for compiling a harness.

### 8.3 CLI (`pqcheck/cli.py`) & Terminal UI (`pqcheck/tui.py`)
- Subcommands:
  - `pqcheck run <manifest-or-folder> [--set k=v ...] [--relation ID] [--seed HEX] [--json] [--reproducers DIR]`
  - `pqcheck reproduce <manifest> --relation ID [--algorithm ALG] [--seed HEX] [--set k=v ...]`
  - `pqcheck relations` (lists all registered relations and required capabilities)
  - `pqcheck adapters` (lists all adapters and required/optional manifest fields)
  - `pqcheck ui [folder]` (interactive ANSI terminal UI; renders `DEFECT_FOUND` in bold red, `NOT_REACHED` and `NO_WITNESS_ESTABLISHES_NOTHING` in amber, `NO_DEFECT_FOUND` in plain white—**never green**—and `NOT_ANSWERABLE` in dim text).

---

## 9. Layer 7: Validation, Mutants, Precision & Standing Probes

1. **`pqcheck/selftest.py`:**
   - **Precision:** Every registered relation must emit `NO_DEFECT_FOUND` (or `NOT_ANSWERABLE`) with zero `DEFECT_FOUND` against all reference-correct toy targets (`ToyKem`, `ToySig`, `ToyCodec`, `ToyLweKem`, `PackedEkKem`, `ToyFalconSig`, `ToyMldsaSig`) and all 8 adversarial precision fixtures in `pqcheck/testing/precision.py`.
   - **Mutant Inertness Guard:** Every planted mutant in `KEM_MUTANTS`, `SIG_MUTANTS`, `CODEC_MUTANTS`, `LWE_MUTANTS`, `PACKED_EK_MUTANTS`, `FALCON_MUTANTS`, and `MLDSA_MUTANTS` is probed outside the relations (`_differs_from_clean`) to prove the mutant is behaviourally distinct from the clean target.
   - **Recall:** Every registered relation must fire (`DEFECT_FOUND`) on at least one planted mutant, and every mutant (except documented `NEGATIVE_CONTROLS`) must be caught by its expected relations.
   - **Two-Sided Seed-Discrimination Gate:** Verifies that `sig-unread-bits` with `n_signatures=8` catches `ToyFalconSig[accepts_minus_zero]` on seeds (`pqcheck-recall-gate-8`, `pqcheck-recall-gate-11`) where degrading `n_signatures=1` misses, AND that `n_signatures=1` actually misses on those seeds (forbidding a rigged fixture).
2. **`pqcheck/backtest/report.py`:**
   - Evaluates the registered relations against 22 historical defects in `corpus.py`, deriving `COVERED`, `PARTIAL`, `MISSED`, and `OUT_OF_SCOPE` counts directly from the live registry.
3. **`pqcheck/probes.py` (`probes/verify_*.py`):**
   - Runs every standalone `verify_*.py` script, enforcing the exit-status protocol (`0` = verified, `77` = skipped with reason, `78` = partial; printing `SKIP` while exiting `0` fails as a protocol violation).
