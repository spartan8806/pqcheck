#!/usr/bin/env python3
"""binds-full-ciphertext catches a single ignored ciphertext byte."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("kem-reject-binds-full-ciphertext", ToyKem(mutant="reject_ignores_ct"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"single ignored byte gave {claim.verdict.value}")
print(f"one ignored ciphertext byte -> DEFECT_FOUND: {claim.evidence}")
claim = registry_run("kem-reject-binds-full-ciphertext", ToyKem())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean KEM gave {claim.verdict.value}")
print("clean KEM binds every byte -> NO_DEFECT_FOUND")
passed("single ignored byte")
