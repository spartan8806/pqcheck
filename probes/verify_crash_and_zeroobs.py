#!/usr/bin/env python3
"""Crash adjudication outranks a zero-observation finding."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def crash_no_obs(self, target, rng):
    target.ping(); target.ping()
    return Finding(None, "no comparable observation", 0, "ping surface")


claim = run_relation(make_relation(crash_no_obs), FakeTarget("crash2"))
check(claim.verdict is Verdict.DEFECT_FOUND,
      f"corroborated crash with zero observations gave {claim.verdict.value}, expected DEFECT_FOUND")
print("corroborated crash outranked the zero-observation gate -> DEFECT_FOUND")
passed("crash and zero-observation interaction")
