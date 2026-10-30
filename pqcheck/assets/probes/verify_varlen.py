#!/usr/bin/env python3
"""Variable-length signatures: length-exact declines, sweeps still work."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.precision import VariableLengthSig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

target = VariableLengthSig()
claim = registry_run("sig-verify-length-exact", target)
check(claim.verdict in (Verdict.NOT_REACHED, Verdict.NOT_ANSWERABLE),
      f"variable-length length-exact gave {claim.verdict.value}")
print("sig-verify-length-exact declines on a variable-length scheme")
claim = registry_run("sig-unread-bits", VariableLengthSig())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"variable-length unread sweep gave {claim.verdict.value}")
print("bit sweep buckets variable-length signatures and stays silent on a correct one")
claim = registry_run("core-sig-round-trip", VariableLengthSig())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"variable-length round trip gave {claim.verdict.value}")
print("variable-length sign/verify round trip is clean")
passed("variable-length signatures")
