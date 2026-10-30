#!/usr/bin/env python3
"""The whole tree compiles: pqcheck/ and probes/ are valid Python."""
import compileall
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, check, passed  # noqa: E402

for tree in (ROOT / "pqcheck", ROOT / "probes"):
    ok = compileall.compile_dir(str(tree), quiet=2, force=False)
    check(ok, f"compileall failed under {tree}")
    print(f"compileall clean: {tree.relative_to(ROOT)}/")
passed("tree compiles")
