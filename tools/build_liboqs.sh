#!/usr/bin/env bash
# Build a static, OpenSSL-free liboqs and the pqcheck OQS KEM harness.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OQS_DIR="${OQS_DIR:-$ROOT/third_party/liboqs}"
BUILD_DIR="$OQS_DIR/build-local"
OUT="$ROOT/pqcheck/adapters/harness_liboqs"

if [[ ! -d "$OQS_DIR/.git" ]]; then
  git clone https://github.com/open-quantum-safe/liboqs.git "$OQS_DIR"
fi
VERSION="$(git -C "$OQS_DIR" describe --tags --always)"
cmake -S "$OQS_DIR" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_BUILD_ONLY_LIB=ON
cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 4)"

cc -O2 -I"$OQS_DIR/include" -o "$OUT" \
  "$ROOT/pqcheck/adapters/oqs_kem_harness.c" \
  "$BUILD_DIR/lib/liboqs.a" -lpthread -lm

for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  printf 'info\n' | "$OUT" kem "$alg"
done
echo "liboqs version for manifests/liboqs.json: $VERSION"
echo "built $OUT"
