#!/usr/bin/env python3
"""Encoding shape: signed zero and hint ordering/tail are canonical."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toycodec import ToyStreamCodec  # noqa: E402
from pqcheck.testing.toyfalcon import ToyFalconSig  # noqa: E402
from pqcheck.testing.toymldsa import ToyMldsaSig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("sig-encoding-signed-zero", ToyFalconSig())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean stream gave {claim.verdict.value}")
claim = registry_run("sig-encoding-signed-zero", ToyFalconSig(mutant="accepts_minus_zero"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"minus-zero mutant gave {claim.verdict.value}")
print("signed-zero stream: rejected clean, accepted by the mutant -> DEFECT_FOUND")
for rid, mutant in (("mldsa-hint-strict-order", "hint_accepts_repeat"), ("mldsa-hint-tail-zero", "hint_accepts_nonzero_tail")):
    claim = registry_run(rid, ToyStreamCodec(mutant=mutant))
    check(claim.verdict is Verdict.DEFECT_FOUND, f"{rid} on {mutant} gave {claim.verdict.value}")
    claim = registry_run(rid, ToyMldsaSig())
    check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"{rid} on clean ML-DSA toy gave {claim.verdict.value}")
print("hint strict-order and zero-tail are enforced on codec and verifier surfaces")
passed("encoding shape")
