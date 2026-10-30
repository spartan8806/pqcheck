#!/usr/bin/env python3
"""Codec contract: round trip, exact length, and re-encode identity."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toycodec import ToyCodec, ToyStreamCodec  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

for rid in ("core-codec-round-trip", "sig-encoding-length-exact", "sig-encoding-decode-reencode-identity"):
    claim = registry_run(rid, ToyCodec())
    check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean codec {rid} gave {claim.verdict.value}")
print("clean codec satisfies round trip, exact length, and re-encode identity")
claim = registry_run("sig-encoding-length-exact", ToyStreamCodec(mutant="accepts_wrong_length"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"wrong-length codec gave {claim.verdict.value}")
print("codec that zero-pads truncated streams -> DEFECT_FOUND")
claim = registry_run("sig-encoding-decode-reencode-identity", ToyStreamCodec(mutant="decoder_rejects_own_encoding"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"own-encoding-rejecting codec gave {claim.verdict.value}")
print("codec that rejects its own encoding at realistic magnitudes -> DEFECT_FOUND")
passed("codec contract")
