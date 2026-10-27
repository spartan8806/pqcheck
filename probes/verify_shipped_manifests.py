#!/usr/bin/env python3
"""Shipped manifests load, and exit 2 (never 0) while their harnesses are unbuilt."""
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import ROOT, check, passed  # noqa: E402

from pqcheck.cli import main  # noqa: E402
from pqcheck.manifest import Manifest  # noqa: E402

manifests = sorted((ROOT / "manifests").glob("*.json"))
check(len(manifests) == 5, f"expected 5 shipped manifests, found {len(manifests)}")
for path in manifests:
    manifest = Manifest.load(path)
    print(f"{path.name}: loads ({manifest.target} via {manifest.adapter})")
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["run", str(path), "--relation", "core-kem-round-trip"])
    check(code == 2, f"{path.name} exited {code} with unbuilt harness, expected 2 (never 0)")
print("every shipped manifest exits 2 while its harness is unbuilt -- none can report clean")
passed("shipped manifests")
