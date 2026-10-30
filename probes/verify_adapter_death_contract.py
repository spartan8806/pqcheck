#!/usr/bin/env python3
"""The process-death contract markers classify exits before any blame."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed  # noqa: E402

from pqcheck.target import (  # noqa: E402
    DEADLINE_KILLED, NOT_ATTRIBUTABLE, POST_MORTEM, Status, classify_exit, post_mortem,
)


class DeadProc:
    _pqcheck_deadline_killed = False

    def poll(self):
        return -11


check(NOT_ATTRIBUTABLE in classify_exit(-15), "SIGTERM exit blamed the target")
check(NOT_ATTRIBUTABLE in classify_exit(-9), "SIGKILL exit blamed the target")
check(NOT_ATTRIBUTABLE not in classify_exit(-11), "SIGSEGV exit was excused as external")
print("external signals (SIGTERM/SIGKILL) are not attributable; SIGSEGV is a target fault shape")

out = post_mortem(DeadProc(), "")
check(out.status is Status.CRASHED and POST_MORTEM in out.detail, "post-mortem outcome lacks its marker")
print("calls after death carry the [post-mortem] marker so one death cannot self-corroborate")
check(DEADLINE_KILLED == "killed by pqcheck's own deadline", "deadline marker text changed")
passed("adapter death contract")
