#!/usr/bin/env python3
"""FO liveness shape: absent FO fires; a live FO transform stays silent."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("kem-fo-liveness", ToyKem(mutant="no_reencryption_check"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"absent FO gave {claim.verdict.value}")
print("ciphertext malleable back to the honest secret -> DEFECT_FOUND (FO absent shape)")

claim = registry_run("kem-fo-liveness", ToyKem())
check(claim.verdict is Verdict.NO_DEFECT_FOUND and claim.one_sided,
      f"live FO gave {claim.verdict.value} one_sided={claim.one_sided}")
print("live FO transform -> one-sided NO_DEFECT_FOUND (establishes nothing on its own)")
passed("FO shape")
