#!/usr/bin/env bash
# Build the PQClean ML-KEM harness at the pinned commit and smoke-test it.
# Refuses to build against any other PQClean commit: the manifest in
# manifests/pqclean.json names 0586a82, and a harness built from different
# sources must never silently answer for that version.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PQCLEAN_DIR="${PQCLEAN_DIR:-$ROOT/third_party/PQClean}"
EXPECTED="0586a824fc0d49df0b6b6e9179d8d15d06d0974f"
OUT="$ROOT/pqcheck/adapters/harness_pqclean"

if [[ ! -d "$PQCLEAN_DIR/.git" ]]; then
  git clone https://github.com/PQClean/PQClean.git "$PQCLEAN_DIR"
fi
cd "$PQCLEAN_DIR"
git fetch --quiet origin "$EXPECTED" || true
ACTUAL="$(git rev-parse HEAD)"
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  git checkout --quiet "$EXPECTED"
  ACTUAL="$(git rev-parse HEAD)"
fi
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "refusing to build: PQClean is at $ACTUAL, expected $EXPECTED" >&2
  exit 1
fi

SOURCES=(
  "$ROOT/pqcheck/adapters/pqclean_mlkem_harness.c"
  "$PQCLEAN_DIR"/crypto_kem/ml-kem-512/clean/*.c
  "$PQCLEAN_DIR"/crypto_kem/ml-kem-768/clean/*.c
  "$PQCLEAN_DIR"/crypto_kem/ml-kem-1024/clean/*.c
  "$PQCLEAN_DIR"/common/*.c
)
# PQClean clean/ trees keep per-scheme namespaces; add include dirs.
cc -O2 \
  -I"$PQCLEAN_DIR/crypto_kem/ml-kem-512/clean" \
  -I"$PQCLEAN_DIR/crypto_kem/ml-kem-768/clean" \
  -I"$PQCLEAN_DIR/crypto_kem/ml-kem-1024/clean" \
  -I"$PQCLEAN_DIR/common" \
  -o "$OUT" "${SOURCES[@]}"

for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  printf 'info\n' | "$OUT" kem "$alg"
done
echo "built $OUT at PQClean $EXPECTED"
