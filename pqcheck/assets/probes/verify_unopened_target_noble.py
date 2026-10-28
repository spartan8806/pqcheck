#!/usr/bin/env python3
"""An unopenable Noble target becomes NOT_REACHED claims, never a traceback."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import SUBJ, check, passed  # noqa: E402

import pqcheck.relations  # noqa: E402,F401
from pqcheck.relations import base  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
    try:
        from pqcheck.adapters.noble import NobleTarget
        target = NobleTarget(td, "ml-kem-768")
        target.close()
        check(False, "NobleTarget opened against an empty directory")
    except Exception as exc:
        claims = base.unopened_claims(SUBJ, exc)
        check(len(claims) == len(base.REGISTRY), "unopened claims do not cover every relation")
        check(all(c.verdict is Verdict.NOT_REACHED for c in claims), "unopened claims are not all NOT_REACHED")
        print(f"unopenable Noble target -> {len(claims)} NOT_REACHED claims ({type(exc).__name__}), no traceback")
passed("unopened target fault isolation")
