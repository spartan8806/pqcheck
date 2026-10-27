#!/usr/bin/env python3
"""Conditional probe: stateful schemes are refused by the stateless protocol."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import ROOT, check, passed  # noqa: E402

if not (ROOT / "pqcheck" / "adapters" / "c_harness.c").exists():
    print("SKIP: C harness source is not present on disk")
    raise SystemExit(77)
from pqcheck.adapters.cbridge import CTarget  # noqa: E402
from pqcheck.target import HarnessProtocolError  # noqa: E402

try:
    CTarget("unused-harness-path", "sig", "XMSS")
    check(False, "stateful XMSS was accepted by the stateless line protocol")
except HarnessProtocolError:
    print("stateful hash-based scheme refused before any process is spawned")
passed("stateful gate")
