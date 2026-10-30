#!/usr/bin/env python3
"""The pad-bit probe sweeps a real region on streams and stays honest on fixed codecs."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toycodec import ToyCodec  # noqa: E402
from pqcheck.testing.toyfalcon import ToyFalconSig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("sig-encoding-pad-bits-zero", ToyFalconSig())
check(claim.verdict is Verdict.NO_DEFECT_FOUND and claim.coverage.units > 1,
      f"stream pad sweep reached only {claim.coverage.units if claim.coverage else 0} units")
print(f"stream format: pad region swept with {claim.coverage.units} observations")
claim = registry_run("sig-encoding-pad-bits-zero", ToyCodec())
check(claim.verdict is Verdict.NOT_ANSWERABLE, f"fixed-width codec gave {claim.verdict.value}")
print("fixed-width codec (no padding region) is NOT_ANSWERABLE, never clean on untested padding")
passed("pad-bit region")
