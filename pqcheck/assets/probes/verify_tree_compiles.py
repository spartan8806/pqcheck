#!/usr/bin/env python3
"""The whole tree compiles: pqcheck/ and probes/ are valid Python."""
import compileall
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import ROOT, check, passed  # noqa: E402

for tree in (ROOT / "pqcheck", ROOT / "probes"):
    ok = compileall.compile_dir(str(tree), quiet=2, force=False)
    check(ok, f"compileall failed under {tree}")
    print(f"compileall clean: {tree.relative_to(ROOT)}/")
passed("tree compiles")
