#!/usr/bin/env python3
"""Conditional probe: hint oracle identity (exits 77 without a hint binary)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, passed  # noqa: E402

if not (ROOT / "pqcheck" / "adapters" / "hint_harness").exists() and not (ROOT / "pqcheck" / "adapters" / "harness_hint").exists():
    print("SKIP: ML-DSA hint harness binary is not present on disk")
    raise SystemExit(77)
passed("hint harness present")
