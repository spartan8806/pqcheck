# START: a stranger's walkthrough

You need Python 3.10+ and nothing else: pqcheck has zero third-party
dependencies. All commands run from the repository root.

## 1. The tool tests itself first

```sh
python -m pqcheck.selftest
```

Expected tail: `selftest: ok (0 false positives, all mutants live and
caught, seed gate holds)`. This runs all 32 relations against clean
reference toys (expecting no defect) and against 41 planted mutants
(expecting every mutant to be caught and every relation to fire at
least once). For a seed sweep:

```sh
python -m pqcheck.selftest --seeds 10
```

Each of the 10 deterministic seeds must show 100% precision and
100% recall, with zero seed-dependent flakiness.

```sh
python -m pqcheck.verdict
```

Expected: `verdict self-check: ok`. This exercises the honesty gates:
clean claims without coverage, defects without reproducers, plain-string
verdicts, moving version references, and secret-shaped report text are
all refused at construction time.

## 2. The four-act demo

```sh
python -m pqcheck demo
```

Act 1 runs all 32 relations on clean and boundary targets (0 defects,
honest declines). Act 2 catches four flagship mutants with printed
witnesses. Act 3 shows a completely broken signer still producing a
loud `DEFECT_FOUND`. Act 4 shows `Report.score()` and the secret-material
floor refusing. It finishes in a few seconds and needs no target.

## 3. Point it at a real library

Shipped manifests live in [manifests/](../manifests/README.md):

- [manifests/noble.json](../manifests/noble.json) — @noble/post-quantum
  via the Node bridge (`node_cwd` must point at your install).
- [manifests/pqclean.json](../manifests/pqclean.json) — PQClean via the
  C harness (build with [tools/build_pqclean.sh](../tools/build_pqclean.sh)).
- [manifests/liboqs.json](../manifests/liboqs.json) — liboqs via the C
  harness (build with [tools/build_liboqs.sh](../tools/build_liboqs.sh)).

```sh
python -m pqcheck run manifests/noble.json
python -m pqcheck run manifests/noble.json --relation kem-fo-liveness
python -m pqcheck reproduce manifests/noble.json --relation kem-fo-liveness
```

Targets are only ever opened through a local manifest or an explicitly
named local folder. There is no network mode and no remote target.

## 4. Reading the exit code

| Exit | Meaning |
| --- | --- |
| 0 | Clean and conclusive somewhere: no defect, at least one real check ran. |
| 1 | A defect was found (or, for `selftest`/`demo`, the showcase itself failed). |
| 2 | The run established nothing (everything declined or was not reached). |
| 3 | Bad CLI usage or a bad manifest. Exit 3 is never a verdict on a target. |

`NOT_REACHED` and `NOT_ANSWERABLE` are never counted as clean. A run
that establishes nothing says so, in words, at the top of its report.

## 5. The enc_rust vulnerable/fixed regression (needs git + cargo)

A real upstream defect with exact pins, reproducible from this repo —
see [regressions/enc_rust/README.md](../regressions/enc_rust/README.md):

```sh
git clone https://github.com/supinie/enc_rust regressions/enc_rust/vendor/enc_rust
git -C regressions/enc_rust/vendor/enc_rust checkout 121385c2c9bab5ab509104b3e7b13259fc8a4080
REV=$(git -C regressions/enc_rust/vendor/enc_rust rev-parse HEAD)
ENC_RUST_REVISION=$REV cargo build --release --manifest-path regressions/enc_rust/Cargo.toml --target-dir regressions/enc_rust/target-vuln
python -m pqcheck run manifests/enc-rust-vulnerable.json --json --html enc-vuln.html --reproducers enc-repro
# expected: DEFECT_FOUND, exit 1; then replay: python enc-repro/reproduce_*.py (exit 1)
git -C regressions/enc_rust/vendor/enc_rust checkout 572a37f395e3c3bcf60d89bea89885b4dc13c176
REV=$(git -C regressions/enc_rust/vendor/enc_rust rev-parse HEAD)
ENC_RUST_REVISION=$REV cargo build --release --manifest-path regressions/enc_rust/Cargo.toml --target-dir regressions/enc_rust/target-fixed
python -m pqcheck run manifests/enc-rust-fixed.json --json --html enc-fixed.html
# expected: no defects, exit 0; each manifest has its own binary, so the
# vulnerable manifest and its reproducers still detect the defect afterward
```

Without cargo the manifests still load and exit 2 (nothing
established) — never 0. Unsupported checks (e.g. past-buffer guards
through this shim) stay `NOT_ANSWERABLE`/`NOT_REACHED` in the report.

## 6. Workbench: fixtures vs real reports

```sh
python -m pqcheck web --port 8420   # http://127.0.0.1:8420/ (loopback only)
```

The Live Target Runner only runs **toy/reference fixtures**, and says
so on every entry. The **Generated Reports** tab runs shipped
manifests and shows the target, its pinned revision, findings,
coverage gaps, and per-claim reproduction instructions. Real external
targets appear only there (or via the CLI) — never disguised as toys.

## 7. Native checks and the isolated wheel

Native coverage (C/PQClean harnesses, the restored upstream Falcon
Rust codec, ASan boundary, the enc_rust regression, wheel install)
lives in one designated Linux CI job that fails on missing tools or
skipped required checks:

```sh
bash tools/native_ci.sh   # same script CI runs; needs gcc, cargo, git
```

Manually, the isolated-wheel check is:

```sh
python -m pip wheel . -w /tmp/dist --no-deps
python -m venv .venv-wheel && .venv-wheel/bin/python -m pip install /tmp/dist/*.whl
.venv-wheel/bin/python -m pqcheck demo
```

## 8. Where to go next

- The assurance model: [00_SPEC_pqc_assurance.md](00_SPEC_pqc_assurance.md)
- Every relation: [01_SPEC_relations.md](01_SPEC_relations.md)
- What the tool cannot see: [06_LIMITATIONS.md](06_LIMITATIONS.md)
