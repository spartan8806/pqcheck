#!/usr/bin/env bash
# Controlled positive control: plant a one-line FO re-encryption bypass
# in YOUR OWN local checkout, prove pqcheck catches it, revert, prove
# the clean build passes. This is how you know the detector works.
#
# Required environment:
#   BREAK_FILE      file in the checkout to patch (relative to CHECKOUT)
#   BREAK_AFTER     literal line after which BREAK_INSERT is inserted
#   BREAK_INSERT    the one line to insert (the planted bypass)
#   CHECKOUT        local checkout to patch (must be a clean git tree)
#   BUILD_CMD       build command, run inside CHECKOUT
#   PQC_MANIFEST    pqcheck manifest for the built harness
#   PQC_ALGORITHM   algorithm argument for pqcheck run
# The patch is reverted via trap on ANY exit, then the target is rebuilt
# clean before the passing run. Nothing outside CHECKOUT is modified.
set -euo pipefail
: "${BREAK_FILE:?set BREAK_FILE}"
: "${BREAK_AFTER:?set BREAK_AFTER}"
: "${BREAK_INSERT:?set BREAK_INSERT}"
: "${CHECKOUT:?set CHECKOUT}"
: "${BUILD_CMD:?set BUILD_CMD}"
: "${PQC_MANIFEST:?set PQC_MANIFEST}"
: "${PQC_ALGORITHM:?set PQC_ALGORITHM}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CHECKOUT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "refusing: $CHECKOUT has uncommitted changes; the plant must be the only change" >&2
  exit 1
fi

revert() {
  git checkout -- "$BREAK_FILE" || true
}
trap revert EXIT

python3 - "$BREAK_FILE" "$BREAK_AFTER" "$BREAK_INSERT" <<'PY'
import sys
path, after, insert = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
for i, line in enumerate(lines):
    if after in line:
        lines.insert(i + 1, insert + "\n")
        break
else:
    raise SystemExit(f"BREAK_AFTER line not found in {path}")
open(path, "w", encoding="utf-8").writelines(lines)
PY

eval "$BUILD_CMD"
echo "--- running pqcheck against the PLANTED build (must find the FO defect) ---"
set +e
python3 -m pqcheck run "$PQC_MANIFEST" --algorithm "$PQC_ALGORITHM" \
  --relation kem-fo-liveness --reproducers "$ROOT/.break-reproducers"
DEFECT_CODE=$?
set -e
if [[ "$DEFECT_CODE" != "1" ]]; then
  echo "positive control FAILED: pqcheck exited $DEFECT_CODE on a planted FO bypass, expected 1" >&2
  exit 1
fi

revert
trap - EXIT
eval "$BUILD_CMD"
echo "--- running pqcheck against the CLEAN build (must pass) ---"
python3 -m pqcheck run "$PQC_MANIFEST" --algorithm "$PQC_ALGORITHM" \
  --relation kem-fo-liveness
echo "positive control ok: planted bypass caught, clean build passes"
