#!/usr/bin/env python3
"""Crashes under lying-length probes are ambiguous, never a memory defect."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def two_pings(self, target, rng):
    target.ping(); target.ping()
    return Finding(True, "observed", 2, "ping surface")


claim = run_relation(make_relation(two_pings, probes_lie_about_length=True), FakeTarget("crash2"))
check(claim.verdict is Verdict.NOT_REACHED,
      f"crash under a lying-length probe gave {claim.verdict.value}, expected NOT_REACHED")
print("crash while pqcheck lies about declared lengths -> NOT_REACHED (ambiguous with the adapter's promise)")
passed("declared-length crash ambiguity")
