#!/usr/bin/env python3
"""sig-unread-bits: 8-signature sweep works on fixed and shaped signatures."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToySig  # noqa: E402
from pqcheck.testing.toyfalcon import ToyFalconSig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("sig-unread-bits", ToySig())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean fixed-length sig gave {claim.verdict.value}")
print("fixed-length signature: every bit is read")
claim = registry_run("sig-unread-bits", ToySig(mutant="verify_ignores_slack"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"unread-byte mutant gave {claim.verdict.value}")
print("a signature byte verify never reads -> DEFECT_FOUND")
claim = registry_run("sig-unread-bits", ToyFalconSig(mutant="accepts_minus_zero"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"minus-zero mutant gave {claim.verdict.value}")
print("a -0 encoding accepted as a second encoding of 0 -> DEFECT_FOUND")
passed("unread bits")
