#!/usr/bin/env python3
"""Coverage is measured by the runner's call counter, never self-reported."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def spoof(self, target, rng):
    return Finding(True, "claimed five hundred units without calling the target", 500, "ping surface")


claim = run_relation(make_relation(spoof), FakeTarget())
check(claim.verdict is Verdict.NOT_REACHED, f"zero-call spoof returned {claim.verdict.value}")
print("zero-call claim with units=500 was refused as NOT_REACHED")


def honest(self, target, rng):
    target.ping(); target.ping(); target.ping()
    return Finding(True, "three real calls", 3, "ping surface")


claim = run_relation(make_relation(honest), FakeTarget())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"honest relation returned {claim.verdict.value}")
check("calls: 3" in claim.coverage.observed, f"runner tally missing from coverage: {claim.coverage.observed}")
print(f"honest coverage observed by runner: {claim.coverage.observed}")
passed("coverage is measured, not self-reported")
