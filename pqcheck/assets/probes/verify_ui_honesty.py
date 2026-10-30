#!/usr/bin/env python3
"""UI honesty: one-sided clean is separate, NOT REACHED renders first,
NO_DEFECT_FOUND is never green, and no percentage is ever shown."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.tui import render_claim, state_of  # noqa: E402
from pqcheck.verdict import Claim, Coverage, Method, Report, Verdict  # noqa: E402

M = Method("probe", None)
clean = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=M, ceiling="c", coverage=Coverage("s", 1))
witness = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=M, ceiling="c", coverage=Coverage("s", 1), one_sided=True)
unreached = Claim(subject=SUBJ, property="p", verdict=Verdict.NOT_REACHED, method=M, ceiling="c", notes="n")

counts = Report((clean, witness)).counts()
check(counts["NO_DEFECT_FOUND"] == 1 and counts["NO_WITNESS_ESTABLISHES_NOTHING"] == 1,
      f"one-sided clean was merged into NO_DEFECT_FOUND: {counts}")
check(state_of(witness)[0] == "NO_WITNESS_ESTABLISHES_NOTHING", "TUI does not separate the one-sided state")
print("one-sided NO_DEFECT_FOUND is counted and rendered separately")

rendered = render_claim(clean)
check("\x1b[37m" in rendered, "NO_DEFECT_FOUND is not plain white")
check("\x1b[32" not in rendered and "1;32" not in rendered, "NO_DEFECT_FOUND rendered green")
print("NO_DEFECT_FOUND renders plain white, never green")

text = Report((clean, unreached)).to_text()
check(text.index("NOT REACHED") < text.index("NO DEFECT FOUND"), "NO DEFECT rendered before NOT REACHED")
check("%" not in text and "score" not in text.lower(), "report text shows a percentage or score")
print("NOT REACHED renders before NO DEFECT FOUND; no score or percentage anywhere")
passed("UI honesty")
