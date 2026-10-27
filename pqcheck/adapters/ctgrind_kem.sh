#!/usr/bin/env bash
# Build and run the ctgrind KEM instrument under Valgrind.
# Requires: LIB_SRC (library objects/sources defining pqc_kem_*),
# optionally CC, PQ_PK_BYTES/PQ_SK_BYTES/PQ_CT_BYTES/PQ_SS_BYTES.
set -euo pipefail
cd "$(dirname "$0")"
: "${LIB_SRC:?set LIB_SRC to the library sources/objects under test}"
cc -O3 -fno-omit-frame-pointer -g -o ctgrind_kem ctgrind_kem.c $LIB_SRC
valgrind --tool=memcheck --error-exitcode=99 ./ctgrind_kem 2> ctgrind_kem.log || true
python3 ctgrind_triage.py ctgrind_kem.log "${ALG:-ML-KEM-768}"
