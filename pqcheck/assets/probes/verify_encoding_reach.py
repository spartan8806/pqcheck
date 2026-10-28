#!/usr/bin/env python3
"""Encoding relations reach conclusive verdicts on every clean codec toy."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toycodec import ToyCodec  # noqa: E402
from pqcheck.testing.toyfalcon import ToyFalconSig  # noqa: E402
from pqcheck.testing.toymldsa import ToyMldsaSig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

ENCODING = (
    "core-codec-round-trip", "sig-encoding-signed-zero", "sig-encoding-pad-bits-zero",
    "sig-encoding-length-exact", "sig-encoding-decode-reencode-identity",
    "mldsa-hint-strict-order", "mldsa-hint-tail-zero",
    "mldsa-verify-hint-strict-order", "mldsa-verify-hint-tail-zero",
)
for factory in (ToyCodec, ToyFalconSig, ToyMldsaSig):
    for rid in ENCODING:
        claim = registry_run(rid, factory())
        check(claim.verdict not in (Verdict.DEFECT_FOUND, Verdict.NOT_REACHED),
              f"{factory.name} {rid} gave {claim.verdict.value}: {claim.evidence} {claim.notes}")
print("no encoding relation fires or stalls on clean codec toys (clean or not-answerable only)")
passed("encoding reach")
