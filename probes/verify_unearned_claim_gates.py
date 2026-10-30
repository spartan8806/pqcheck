#!/usr/bin/env python3
"""Unearned claims cannot be constructed; score() always raises."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.verdict import Claim, ClaimError, Coverage, Method, Report, Verdict  # noqa: E402

M = Method("probe", None)


def refused(label, **kwargs):
    try:
        Claim(subject=SUBJ, method=M, **kwargs)
    except ClaimError:
        print(f"refused: {label}")
        return
    check(False, f"unearned claim constructed: {label}")


refused("clean without coverage", property="p", verdict=Verdict.NO_DEFECT_FOUND, ceiling="c")
refused("clean with zero units", property="p", verdict=Verdict.NO_DEFECT_FOUND, ceiling="c", coverage=Coverage("surface", 0))
refused("clean with blank surface", property="p", verdict=Verdict.NO_DEFECT_FOUND, ceiling="c", coverage=Coverage("  ", 3))
refused("defect with TBD reproducer", property="p", verdict=Verdict.DEFECT_FOUND, ceiling="c", reproduce="TBD")
refused("defect with empty ceiling", property="p", verdict=Verdict.DEFECT_FOUND, ceiling="", reproduce="re-run the pinned relation again")
refused("not-reached without explanation", property="p", verdict=Verdict.NOT_REACHED, ceiling="c")
refused("not-answerable without explanation", property="p", verdict=Verdict.NOT_ANSWERABLE, ceiling="c")
refused("bare-string premises", property="p", verdict=Verdict.NOT_REACHED, ceiling="c", notes="n", premises="oops")
clean = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=M, ceiling="c", coverage=Coverage("surface", 1))
try:
    Report((clean,)).score()
    check(False, "Report.score() returned a number")
except NotImplementedError:
    print("refused: Report.score() raises NotImplementedError by design")
passed("unearned claim gates")
