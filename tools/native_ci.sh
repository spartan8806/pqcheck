#!/usr/bin/env bash
# Designated native-verification job for pqcheck (Linux CI).
# In THIS job, missing required tools or skipped required checks
# FAIL the job (exit != 0). That is deliberate: this is the one place
# where native coverage is not allowed to silently degrade.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "NATIVE CI FAILURE: $*" >&2; exit 1; }

# --- required tools: absence is a failure here, not a skip ---------
for tool in gcc cargo rustc git python3 cmake; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool missing: $tool"
done
gcc --version | head -1; cargo --version; python3 --version

# gnu99 (not strict c99) so POSIX declarations such as strtok_r are
# visible; implicit function declarations are fatal, never warnings.
CFLAGS="-O1 -std=gnu99 -Wall -Wextra -Werror=implicit-function-declaration"

# --- provision liboqs (oqs_kem_harness.c needs <oqs/oqs.h>) ---------
if [ ! -f vendor/liboqs-install/include/oqs/oqs.h ]; then
  [ -d vendor/liboqs ] || git clone -q --depth 1 --branch 0.16.0 \
      https://github.com/open-quantum-safe/liboqs.git vendor/liboqs
  cmake -S vendor/liboqs -B vendor/liboqs/build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
      -DCMAKE_INSTALL_PREFIX="$PWD/vendor/liboqs-install" > /tmp/liboqs_cmake.log 2>&1 \
    || fail "liboqs cmake configure"
  cmake --build vendor/liboqs/build -j"$(nproc)" > /tmp/liboqs_build.log 2>&1 \
    || fail "liboqs build"
  cmake --install vendor/liboqs/build > /dev/null || fail "liboqs install"
fi
OQS_INC="$PWD/vendor/liboqs-install/include"
OQS_LIB="$PWD/vendor/liboqs-install/lib"

# --- C harnesses: syntax-check all (with liboqs includes), build ---
for src in pqcheck/adapters/*.c; do
  gcc $CFLAGS -I"$OQS_INC" -fsyntax-only "$src" || fail "syntax: $src"
done
gcc $CFLAGS -o pqcheck/adapters/codec_harness_bin \
    pqcheck/adapters/codec_harness.c || fail "build codec_harness.c"
gcc $CFLAGS -I"$OQS_INC" -o pqcheck/adapters/harness_liboqs \
    pqcheck/adapters/oqs_kem_harness.c -L"$OQS_LIB" -loqs -lcrypto -lpthread -ldl \
    || fail "build oqs_kem_harness.c"

# --- smoke-test the compiled binaries (a binary that crashes on ---
# --- the harmless "info" command must fail here, not downstream) ---
echo info | pqcheck/adapters/codec_harness_bin | grep -q "^OK kind=codec" \
  || fail "codec_harness_bin info smoke"
echo info | pqcheck/adapters/harness_liboqs kem ML-KEM-768 | grep -q "^OK kind=kem" \
  || fail "harness_liboqs info smoke"

# ASan exact-allocation boundary (runs only when a compiler exists;
# here one must exist, and the test must not skip)
python3 -m unittest tests.test_audit_fixes.ExactAllocationTests 2>&1 | tee /tmp/asan.txt
grep -q "OK" /tmp/asan.txt || fail "ASan boundary tests did not pass"
grep -q "skipped" /tmp/asan.txt && fail "ASan boundary test skipped in native job"

# --- PQClean ML-KEM harness: real build against pinned PQClean -----
PQREV=0586a82
[ -d vendor/PQClean ] || git clone -q https://github.com/PQClean/PQClean.git vendor/PQClean
git -C vendor/PQClean checkout -q "$PQREV"
git -C vendor/PQClean rev-parse HEAD
RNG=$(find vendor/PQClean -name 'notrandombytes.c' | head -1)
[ -n "$RNG" ] || fail "PQClean deterministic randombytes not found"
gcc $CFLAGS \
  -I vendor/PQClean/common \
  -I vendor/PQClean/crypto_kem/ml-kem-512/clean \
  -I vendor/PQClean/crypto_kem/ml-kem-768/clean \
  -I vendor/PQClean/crypto_kem/ml-kem-1024/clean \
  pqcheck/adapters/pqclean_mlkem_harness.c \
  vendor/PQClean/crypto_kem/ml-kem-*/clean/*.c \
  vendor/PQClean/common/fips202.c "$RNG" \
  -o pqcheck/adapters/harness_pqclean || fail "build pqclean harness"
echo info | pqcheck/adapters/harness_pqclean kem ML-KEM-768 | grep -q "^OK kind=kem" \
  || fail "harness_pqclean info smoke"

# Gate: EXACT exit 0, all three algorithms covered, zero defects,
# and kem-decaps-length-exact declined (pointer-only C API premise).
set +e
python3 -m pqcheck run manifests/pqclean.json --json > /tmp/pqclean.json 2>/tmp/pqclean.err
code=$?
set -e
[ "$code" -eq 0 ] || fail "PQClean run: expected exact exit 0, got $code"
python3 - <<'PYEOF' || fail "PQClean JSON evidence check"
import json
r = json.load(open("/tmp/pqclean.json"))
counts = r["counts"]
assert counts.get("DEFECT_FOUND", 0) == 0, counts
assert counts.get("NO_DEFECT_FOUND", 0) > 0, counts
algs = {c["subject"] for c in r["claims"]}
for a in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
    assert any(a in s for s in algs), f"algorithm not covered: {a}"
lenclaims = [c for c in r["claims"] if c["method"] == "kem-decaps-length-exact"]
assert len(lenclaims) == 3, f"expected 3 length-exact claims, got {len(lenclaims)}"
assert all(c["verdict"] == "NOT_ANSWERABLE" for c in lenclaims), lenclaims
print("PQClean evidence: exit 0, 3 algorithms, 0 defects, length-exact declined x3")
PYEOF

# --- Restored Falcon Rust harness: actual pinned upstream codec ----
cargo build --release --manifest-path pqcheck/adapters/rust/Cargo.toml \
  || cargo build --release --offline --manifest-path pqcheck/adapters/rust/Cargo.toml \
  || fail "build falcon codec harness"
cp pqcheck/adapters/rust/target/release/pqcheck_codec_harness \
   pqcheck/adapters/pqcheck_codec_harness
echo info | pqcheck/adapters/pqcheck_codec_harness | grep -q "^OK kind=codec ncoef=512" \
  || fail "falcon codec harness info smoke"
python3 -m unittest tests.test_audit_fixes.RustHarnessTests.test_upstream_binary_agrees_when_built \
  2>&1 | tee /tmp/rust.txt
grep -q "OK" /tmp/rust.txt || fail "upstream codec binary test did not pass"
grep -q "skipped" /tmp/rust.txt && fail "upstream codec binary test skipped in native job"

# --- enc_rust: separate artifacts per revision, provenance-bound ---
ENC=121385c2c9bab5ab509104b3e7b13259fc8a4080
FIX=572a37f395e3c3bcf60d89bea89885b4dc13c176
[ -d regressions/enc_rust/vendor/enc_rust ] || git clone -q \
    https://github.com/supinie/enc_rust.git regressions/enc_rust/vendor/enc_rust
build_enc() {  # $1=commit $2=target-dir
  git -C regressions/enc_rust/vendor/enc_rust checkout -qf "$1"
  local rev; rev=$(git -C regressions/enc_rust/vendor/enc_rust rev-parse HEAD)
  [ "$rev" = "$1" ] || fail "enc_rust checkout is $rev, expected $1"
  ENC_RUST_REVISION="$rev" cargo build --release \
      --manifest-path regressions/enc_rust/Cargo.toml --target-dir "regressions/enc_rust/$2" \
    || ENC_RUST_REVISION="$rev" cargo build --release --offline \
      --manifest-path regressions/enc_rust/Cargo.toml --target-dir "regressions/enc_rust/$2" \
    || fail "build enc harness ($1)"
  echo info | "regressions/enc_rust/$2/release/enc_rust_harness" \
      | grep -q "rev=$1" || fail "enc harness provenance mismatch for $1"
}
build_enc "$ENC" target-vuln
set +e
python3 -m pqcheck run manifests/enc-rust-vulnerable.json --json --html /tmp/enc-vuln.html --reproducers /tmp/enc-repro > /tmp/enc_vuln.txt 2>&1
vuln=$?
set -e
[ "$vuln" -eq 1 ] || fail "vulnerable enc_rust: expected pqcheck exit 1 (defect), got $vuln"
ls /tmp/enc-repro/reproduce_*.py >/dev/null || fail "no reproducer generated for vulnerable enc_rust"
build_enc "$FIX" target-fixed
set +e
python3 -m pqcheck run manifests/enc-rust-fixed.json --json --html /tmp/enc-fixed.html > /tmp/enc_fixed.txt 2>&1
fixed=$?
python3 -m pqcheck run manifests/enc-rust-vulnerable.json > /tmp/enc_vuln2.txt 2>&1
vuln2=$?
python3 /tmp/enc-repro/reproduce_*.py > /tmp/enc_replay.txt 2>&1
replay=$?
set -e
[ "$fixed" -eq 0 ] || fail "fixed enc_rust: expected pqcheck exit 0, got $fixed"
[ "$vuln2" -eq 1 ] || fail "vulnerable manifest after fixed build: expected exit 1, got $vuln2"
[ "$replay" -eq 1 ] || fail "reproducer replay after fixed build: expected exit 1, got $replay"

# Runtime revision binding: the FIXED binary supplied to the
# VULNERABLE manifest must be refused (NOT_REACHED, exit 2) by the
# shared validated runner -- through run, reproduce, and (below)
# the workbench, not just by this script's build-time grep.
sed 's#target-vuln#target-fixed#' manifests/enc-rust-vulnerable.json > manifests/enc-mismatch-tmp.json
set +e
python3 -m pqcheck run manifests/enc-mismatch-tmp.json > /tmp/enc_mismatch.txt 2>&1
mm=$?
python3 -m pqcheck reproduce manifests/enc-mismatch-tmp.json --relation kem-fo-liveness > /tmp/enc_mismatch_repro.txt 2>&1
mmr=$?
set -e
rm -f manifests/enc-mismatch-tmp.json
[ "$mm" -eq 2 ] || fail "mismatched binary under vulnerable manifest (run): expected exit 2, got $mm"
[ "$mmr" -eq 2 ] || fail "mismatched binary under vulnerable manifest (reproduce): expected exit 2, got $mmr"
grep -q "revision conflict" /tmp/enc_mismatch.txt || fail "run mismatch did not explain the revision conflict"
python3 - <<'PYEOF' || fail "workbench runner on vulnerable enc_rust"
from pqcheck import web
r = web.run_named_manifest("enc-rust-vulnerable.json")
assert r["counts"].get("DEFECT_FOUND", 0) >= 1, r["counts"]
print("workbench runner: vulnerable enc_rust DEFECT_FOUND via shared validated runner")
PYEOF

# --- standing probes: required native probes must not skip ---------
python3 -m pqcheck.probes 2>&1 | tee /tmp/probes.txt
grep -q "^FAIL" /tmp/probes.txt && fail "standing probe failure"
for required in verify_roundtrip_order.py verify_falcon_cross_vectors.py; do
  grep -q "SKIPPED  $required" /tmp/probes.txt && fail "required probe skipped: $required"
done

# --- isolated wheel: project-local venv, installed-package run -----
python3 -m pip wheel . -w /tmp/dist --no-deps -q 2>/dev/null \
  || python3 -m pip wheel . -w /tmp/dist --no-deps --no-build-isolation -q \
  || fail "wheel build"
rm -rf .wheel-venv .wheel-target
if python3 -m venv .wheel-venv 2>/dev/null; then
  WHEEL_PY="$PWD/.wheel-venv/bin/python"
  "$WHEEL_PY" -m pip install -q --no-index /tmp/dist/*.whl || fail "wheel install"
else
  # No ensurepip on this box (python3-venv absent, offline): fall back
  # to an isolated --target install in a project-local directory.
  echo "venv unavailable; using isolated --target wheel install"
  WHEEL_PY="python3"
  python3 -m pip install -q --no-index --target "$PWD/.wheel-target" /tmp/dist/*.whl \
    || fail "wheel install (--target)"
  export PYTHONPATH="$PWD/.wheel-target"
fi
(cd /tmp && "$WHEEL_PY" -m pqcheck.probes > /tmp/wheel_probes.txt 2>&1) \
  || fail "installed wheel probes failed"
grep -q "no probes found" /tmp/wheel_probes.txt && fail "installed wheel: no probes found"
"$WHEEL_PY" -m pqcheck demo >/dev/null || fail "installed wheel demo failed"

echo "native CI: all native builds and checks executed (no required skips)"
