#!/usr/bin/env python3
"""A kill by pqcheck's own deadline is attributed to pqcheck, not the target."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def two_pings(self, target, rng):
    target.ping(); target.ping()
    return Finding(True, "observed", 2, "ping surface")


claim = run_relation(make_relation(two_pings), FakeTarget("deadline"))
check(claim.verdict is Verdict.NOT_REACHED, f"deadline-killed child gave {claim.verdict.value}")
print("crashes carrying pqcheck's own deadline marker -> NOT_REACHED")

claim = run_relation(make_relation(two_pings), FakeTarget("timeout2"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"two genuine timeouts gave {claim.verdict.value}")
check("not memory unsafety" in claim.ceiling, "hang defect ceiling does not disclaim memory unsafety")
print("two genuine per-call timeouts -> DEFECT_FOUND (reproducible hang, explicitly not memory unsafety)")
passed("deadline attribution")
