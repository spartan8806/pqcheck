# enc_rust vulnerable/fixed regression

A reproducible, from-this-repository regression for a real upstream
defect pqcheck detects: enc_rust's ML-KEM decapsulation missed part
of the Fujisaki–Okamoto ciphertext comparison, so edited
ciphertexts could decapsulate to the honest secret
([GHSA-3qxj-wq9g-37w6](https://github.com/supinie/enc_rust/security/advisories/GHSA-3qxj-wq9g-37w6)).

Pinned revisions (never floating):

| Role | Commit |
| --- | --- |
| Vulnerable parent | `121385c2c9bab5ab509104b3e7b13259fc8a4080` |
| Fix | `572a37f395e3c3bcf60d89bea89885b4dc13c176` |

The harness (`enc_rust_harness.rs`) is a thin shim: it forwards real
serialized keys/ciphertexts into enc_rust's public API and plants
nothing. Which revision is under test is decided entirely by the
checkout in `vendor/enc_rust`.

## Build and run (needs git + cargo; run from the repo root)

```sh
# 1. Fetch the pinned vulnerable revision
git clone https://github.com/supinie/enc_rust regressions/enc_rust/vendor/enc_rust
git -C regressions/enc_rust/vendor/enc_rust checkout 121385c2c9bab5ab509104b3e7b13259fc8a4080
git -C regressions/enc_rust/vendor/enc_rust rev-parse HEAD   # must print that commit

# 2. Build the harness against it, into its OWN artifact directory
#    (target-vuln). The binary is stamped with the exact revision via
#    ENC_RUST_REVISION; check the stamp before trusting a run.
REV=$(git -C regressions/enc_rust/vendor/enc_rust rev-parse HEAD)
ENC_RUST_REVISION=$REV cargo build --release --manifest-path regressions/enc_rust/Cargo.toml --target-dir regressions/enc_rust/target-vuln
echo info | regressions/enc_rust/target-vuln/release/enc_rust_harness   # must print rev=121385c...

# 3. Run: the defect must be found (pqcheck exit 1), with reports
python -m pqcheck run manifests/enc-rust-vulnerable.json --json --html enc-rust-vulnerable.html --reproducers enc-rust-repro
echo "exit=$?"   # expect 1 (DEFECT_FOUND), never 0

# 4. Replay a generated reproducer (it re-detects the defect, exit 1)
python enc-rust-repro/reproduce_*.py

# 5. Switch to the fixed revision and build into target-fixed. This
#    never overwrites the vulnerable artifact, and each manifest
#    points at its own binary, so old reproducers stay bound to the
#    vulnerable build.
git -C regressions/enc_rust/vendor/enc_rust checkout 572a37f395e3c3bcf60d89bea89885b4dc13c176
REV=$(git -C regressions/enc_rust/vendor/enc_rust rev-parse HEAD)
ENC_RUST_REVISION=$REV cargo build --release --manifest-path regressions/enc_rust/Cargo.toml --target-dir regressions/enc_rust/target-fixed
echo info | regressions/enc_rust/target-fixed/release/enc_rust_harness   # must print rev=572a37f...
python -m pqcheck run manifests/enc-rust-fixed.json --json --html enc-rust-fixed.html
echo "exit=$?"   # expect 0

# 6. Re-check separation: the vulnerable manifest must STILL find the
#    defect, and the step-4 reproducer must STILL replay it (exit 1).
python -m pqcheck run manifests/enc-rust-vulnerable.json
python enc-rust-repro/reproduce_*.py
```

Expected shape (established by the independent audit and re-run in
CI's native job): vulnerable build → `DEFECT_FOUND` from the FO /
implicit-rejection relations; fixed build → zero defects, with the
relations that cannot be answered through this shim (e.g.
past-buffer guard checks, which the shim explicitly declines with
`ERR`) reported `NOT_ANSWERABLE` / `NOT_REACHED` — visible, never
silently clean.

## Without cargo

The manifests still load, and `python -m pqcheck run
manifests/enc-rust-vulnerable.json` exits 2 (nothing established)
because the harness binary is absent. That is the honest
unbuilt state, not a pass. The Linux CI job (`.github/workflows/ci.yml`,
`native` job) performs the full build-and-run above and fails if
either revision's expected exit code is not observed.

This regression was not executed on the Windows development machine
(no Rust toolchain there). Do not cite it as locally run; cite the
CI receipt.
