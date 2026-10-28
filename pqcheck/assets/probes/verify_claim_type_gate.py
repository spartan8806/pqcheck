#!/usr/bin/env python3
"""A plain string verdict must never construct a Claim (type gate)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.verdict import Claim, ClaimError, Coverage, Method, Verdict  # noqa: E402

try:
    Claim(subject=SUBJ, property="p", verdict="NO_DEFECT_FOUND",
          method=Method("probe", None), ceiling="c", coverage=Coverage("surface", 1))
    check(False, "string verdict 'NO_DEFECT_FOUND' was accepted")
except ClaimError as exc:
    print(f"string verdict refused with ClaimError (a ValueError): {exc}")
good = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND,
             method=Method("probe", None), ceiling="c", coverage=Coverage("surface", 1))
check(good.verdict is Verdict.NO_DEFECT_FOUND, "enum verdict was not preserved by identity")
passed("claim type gate")
