#!/usr/bin/env python3
"""Pad bits: set padding must be rejected on padded stream formats."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toycodec import ToyStreamCodec  # noqa: E402
from pqcheck.testing.toyfalcon import ToyFalconSig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("sig-encoding-pad-bits-zero", ToyFalconSig())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean stream codec gave {claim.verdict.value}")
print("clean stream codec rejects set padding bits")
claim = registry_run("sig-encoding-pad-bits-zero", ToyStreamCodec(mutant="accepts_nonzero_pad"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"pad-accepting mutant gave {claim.verdict.value}")
print("codec that ignores its padding region -> DEFECT_FOUND")
passed("pad bits")
