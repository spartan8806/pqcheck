#!/usr/bin/env python3
"""Shipped manifests load, and exit 2 (never 0) while their harnesses are unbuilt."""
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import MANIFESTS_DIR, check, passed  # noqa: E402

from pqcheck.cli import main  # noqa: E402
from pqcheck.manifest import Manifest  # noqa: E402

manifests = sorted(MANIFESTS_DIR.glob("*.json"))
check(len(manifests) == 8, f"expected 8 shipped manifests, found {len(manifests)}")
for path in manifests:
    manifest = Manifest.load(path)
    print(f"{path.name}: loads ({manifest.target} via {manifest.adapter})")
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["run", str(path), "--relation", "core-kem-round-trip"])
    if path.name == "python-reference.json":
        # The python adapter needs no build: it must run conclusively.
        check(code == 0, f"python-reference.json exited {code}, expected a conclusive 0 out of the box")
    elif manifest.harness is not None and manifest.harness.exists():
        # Built harness (native CI): the round trip must conclude
        # cleanly; "nothing established" (2) here would be a failure.
        check(code == 0, f"{path.name} exited {code} with a BUILT harness, expected a conclusive 0")
    else:
        check(code == 2, f"{path.name} exited {code} with unbuilt harness, expected 2 (never 0)")
print("build-requiring manifests exit 2 while unbuilt, 0 once built; python-reference runs conclusively (0)")
passed("shipped manifests")
