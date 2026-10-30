#!/usr/bin/env python3
"""Corroborated hard crashes are defects; a single live-process crash is not."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def two_pings(self, target, rng):
    target.ping(); target.ping()
    return Finding(True, "observed", 2, "ping surface")


claim = run_relation(make_relation(two_pings), FakeTarget("crash2"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"two hard crashes gave {claim.verdict.value}")
print("two corroborated SIGSEGV crashes -> DEFECT_FOUND")


def one_ping(self, target, rng):
    target.ping()
    return Finding(True, "observed", 1, "ping surface")


claim = run_relation(make_relation(one_ping), FakeTarget("crash1_alive"))
check(claim.verdict is Verdict.NOT_REACHED, f"single crash with live process gave {claim.verdict.value}")
print("single crash while the process stays alive -> NOT_REACHED")
passed("crash corroboration")
