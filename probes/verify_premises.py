#!/usr/bin/env python3
"""Premises a claim rests on are rendered in the report."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.verdict import Claim, Coverage, Method, Report, Verdict  # noqa: E402

claim = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND,
              method=Method("probe", None), ceiling="c", coverage=Coverage("surface", 1),
              premises=("fixed_sig_len=True", "sig_len_basis='declared by the target'"))
text = Report((claim,)).to_text()
check("rests on:" in text, "premises are not rendered")
check("fixed_sig_len=True" in text, "premise text is not rendered")
print("claim premises render under 'rests on:'")
passed("premises rendering")
