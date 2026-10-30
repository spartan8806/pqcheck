#!/usr/bin/env bash
# Rebuild any of the pqcheck C harnesses. Usage:
#   tools/rebuild_harness.sh <harness-name>
# where <harness-name> is c_harness, pqclean_mlkem_harness,
# oqs_kem_harness, codec_harness, hint_harness, timing_harness,
# falcon_compdecode_fixture, ctgrind_kem, or ctgrind_clib.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${1:?usage: rebuild_harness.sh <harness-name>}"
SRC="$ROOT/pqcheck/adapters/$NAME.c"
[[ -f "$SRC" ]] || { echo "no such harness source: $SRC" >&2; exit 1; }
OUT="${OUT:-$ROOT/pqcheck/adapters/$NAME}"
LIB_ARGS=()
[[ -n "${LIB_SRC:-}" ]] && LIB_ARGS=("$LIB_SRC")
cc -O2 -o "$OUT" "$SRC" "${LIB_ARGS[@]}"
echo "built $OUT"
