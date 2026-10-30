#!/usr/bin/env python3
"""Folder discovery finds candidates and never executes what it finds."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed  # noqa: E402

from pqcheck.discover import discover  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "manifest.json").write_text(json.dumps(
        {"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./h"}), encoding="utf-8")
    binary = root / "harness_pqclean"
    binary.write_bytes(b"MZ" + b"\x00" * 64)
    candidates = discover(root)
    kinds = {c.kind for c in candidates}
    check("manifest" in kinds, f"manifest not discovered: {kinds}")
    harness = [c for c in candidates if c.kind == "harness"]
    check(harness and "version" in harness[0].missing,
          "compiled binary candidate does not declare its version missing")
    print("manifest discovered; compiled binary is a candidate with version missing (never guessed, never executed)")
passed("discovery")
