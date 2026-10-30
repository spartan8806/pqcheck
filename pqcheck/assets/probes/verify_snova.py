#!/usr/bin/env python3
"""Conditional probe: SNOVA harness (exits 77 when the binary is absent)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, check, passed  # noqa: E402

binary = ROOT / "pqcheck" / "adapters" / "harness_snova"
if not binary.exists():
    print("SKIP: SNOVA harness binary is not present on disk (pqcheck/adapters/harness_snova)")
    raise SystemExit(77)
check(binary.is_file(), "SNOVA harness path exists but is not a file")
passed("SNOVA harness present")
