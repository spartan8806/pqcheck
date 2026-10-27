#!/usr/bin/env bash
# Build the Falcon comp_encode/comp_decode fixture harness.
# With FALCON_SRC set, links the real codec (-DPQCHECK_EXTERNAL);
# without it, builds the template codec so the protocol can be smoked.
set -euo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-codec_falcon512}"
if [[ -n "${FALCON_SRC:-}" ]]; then
  cc -O2 -DPQCHECK_EXTERNAL -o "$OUT" falcon_compdecode_fixture.c "$FALCON_SRC"
else
  cc -O2 -o "$OUT" falcon_compdecode_fixture.c
fi
printf 'info\n' | "./$OUT"
