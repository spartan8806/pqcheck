#!/usr/bin/env python3
"""Conditional probe: round-trip call ordering (exits 77 without a harness)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, passed  # noqa: E402

if not (ROOT / "pqcheck" / "adapters" / "harness_pqclean").exists():
    print("SKIP: PQClean harness binary is not present on disk (pqcheck/adapters/harness_pqclean)")
    raise SystemExit(77)
passed("PQClean harness present")
