#!/usr/bin/env python3
"""Crash attribution: external signals and post-mortem repeats are not findings."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import FakeTarget, check, make_relation, passed, run_relation  # noqa: E402

from pqcheck.relations.base import Finding  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402


def two_pings(self, target, rng):
    target.ping(); target.ping()
    return Finding(True, "observed", 2, "ping surface")


for mode in ("external", "postmortem"):
    claim = run_relation(make_relation(two_pings), FakeTarget(mode))
    check(claim.verdict is Verdict.NOT_REACHED, f"{mode} crashes gave {claim.verdict.value}, expected NOT_REACHED")
    print(f"{mode} crash shape -> NOT_REACHED (not attributable / not self-corroborating)")
passed("crash attribution")
