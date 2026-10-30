#!/usr/bin/env python3
"""Unread-bit combinations are enumerated and counted, not assumed."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToySig  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("sig-unread-bits", ToySig(mutant="verify_ignores_slack"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"unread mutant gave {claim.verdict.value}")
check("unread bit position" in claim.evidence, "evidence does not count unread positions")
check("multi-bit combos also accepted" in claim.evidence,
      f"combination probing was not measured: {claim.evidence}")
print(f"combination probing measured, not assumed: {claim.evidence}")
passed("unread combinations")
