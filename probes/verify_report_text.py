#!/usr/bin/env python3
"""Report text: subject on every claim, ceiling on defects, section order."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.verdict import Claim, Coverage, Method, Report, Verdict  # noqa: E402

M = Method("probe", None)
claims = (
    Claim(subject=SUBJ, property="defect property", verdict=Verdict.DEFECT_FOUND, method=M,
          ceiling="does not establish fault resistance", reproduce="re-run the pinned relation again now"),
    Claim(subject=SUBJ, property="unreached property", verdict=Verdict.NOT_REACHED, method=M,
          ceiling="c", notes="harness missing"),
    Claim(subject=SUBJ, property="clean property", verdict=Verdict.NO_DEFECT_FOUND, method=M,
          ceiling="c", coverage=Coverage("surface", 2, "calls: 2")),
    Claim(subject=SUBJ, property="witness property", verdict=Verdict.NO_DEFECT_FOUND, method=M,
          ceiling="c", coverage=Coverage("surface", 2, "calls: 2"), one_sided=True),
    Claim(subject=SUBJ, property="scope property", verdict=Verdict.NOT_ANSWERABLE, method=M,
          ceiling="c", notes="no such capability"),
)
text = Report(claims).to_text()
for label in ("DEFECTS FOUND", "NOT REACHED", "NO DEFECT FOUND", "NO WITNESS FOUND", "OUT OF SCOPE"):
    check(label in text, f"section missing from report: {label}")
check(text.count(str(SUBJ)) >= 5, "subject is not printed on every claim")
check("does not establish fault resistance" in text, "defect claim does not carry its ceiling")
order = [text.index(x) for x in ("DEFECTS FOUND", "NOT REACHED", "NO DEFECT FOUND", "NO WITNESS FOUND", "OUT OF SCOPE")]
check(order == sorted(order), f"sections out of order: {order}")
print("all 5 sections render in order, subject and ceiling on every claim")
passed("report text")
