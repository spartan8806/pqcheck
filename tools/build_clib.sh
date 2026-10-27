#!/usr/bin/env bash
# Compile the generic C harness against your library and smoke-test it.
# Requires: LIB_SRC (sources/objects defining the pqc_* entry points),
# optionally ALG (default ML-KEM-768), KIND (default kem), OUT.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${LIB_SRC:?set LIB_SRC to your library sources/objects}"
OUT="${OUT:-$ROOT/pqcheck/adapters/harness_yourlib}"
KIND="${KIND:-kem}"
ALG="${ALG:-ML-KEM-768}"

cc -O2 -o "$OUT" "$ROOT/pqcheck/adapters/c_harness.c" $LIB_SRC

printf 'info\n' | "$OUT" "$KIND" "$ALG"
# Over-long line check: the harness must answer ERR, never REJ.
LONG="$(printf 'ab%.0s' $(seq 1 700000))"
REPLY="$(printf 'encaps %s\n' "$LONG" | "$OUT" "$KIND" "$ALG" | head -n 2 | tail -n 1)"
case "$REPLY" in
  ERR*) echo "over-long line -> ERR (correct)" ;;
  *) echo "over-long line did not produce ERR: $REPLY" >&2; exit 1 ;;
esac
echo "built $OUT"
