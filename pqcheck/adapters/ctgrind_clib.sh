#!/usr/bin/env bash
# Build and run the ctgrind generic-C-library instrument under Valgrind.
# Requires: LIB_SRC (library objects/sources defining pqc_sig_*).
set -euo pipefail
cd "$(dirname "$0")"
: "${LIB_SRC:?set LIB_SRC to the library sources/objects under test}"
cc -O3 -fno-omit-frame-pointer -g -o ctgrind_clib ctgrind_clib.c $LIB_SRC
valgrind --tool=memcheck --error-exitcode=99 ./ctgrind_clib 2> ctgrind_clib.log || true
python3 ctgrind_triage.py ctgrind_clib.log "${ALG:-ML-DSA-65}"
