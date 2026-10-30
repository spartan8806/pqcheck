#!/usr/bin/env python3
"""The rendered report carries the coverage receipt (units + runner tally)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Report  # noqa: E402


def honest(self, target, rng):
    target.ping(); target.ping()
    return Finding(True, "two real calls", 2, "ping surface")


claim = run_relation(make_relation(honest), FakeTarget())
text = Report((claim,)).to_text()
check("units: 2" in text, "report text lacks the units receipt")
check("observed by the runner: calls: 2" in text, "report text lacks the runner call tally")
print("report renders units and the runner-observed call tally")
passed("coverage receipt renders")
