#!/usr/bin/env python3
"""Assertion aborts are partitioned from hard faults, and cannot hide one."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def pings(n):
    def _check(self, target, rng):
        for _ in range(n):
            target.ping()
        return Finding(True, "observed", n, "ping surface")
    return _check


claim = run_relation(make_relation(pings(1)), FakeTarget("assert"))
check(claim.verdict is Verdict.NOT_REACHED, f" lone assertion abort gave {claim.verdict.value}")
print("assertion abort in a debug build -> NOT_REACHED (precondition enforcement, not memory unsafety)")

claim = run_relation(make_relation(pings(3)), FakeTarget("assert_then_hard"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"assertion + hard faults gave {claim.verdict.value}")
print("a hard fault after an assertion abort still -> DEFECT_FOUND (assertion cannot hide a real crash)")
passed("assertion partition")
