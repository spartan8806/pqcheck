#!/usr/bin/env python3
"""binds-full-ciphertext catches an ignored ciphertext suffix."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("kem-reject-binds-full-ciphertext", ToyKem(mutant="reject_binds_prefix_only"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"ignored suffix gave {claim.verdict.value}")
print(f"ignored ciphertext suffix -> DEFECT_FOUND: {claim.evidence}")
passed("ignored suffix")
