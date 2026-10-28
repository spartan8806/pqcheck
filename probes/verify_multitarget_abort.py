#!/usr/bin/env python3
"""One unopenable target never aborts the run for the others."""
import io
import json
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import ROOT, check, passed  # noqa: E402

from pqcheck.cli import main  # noqa: E402

if not (ROOT / 'tests' / 'fake_harness.py').is_file():
    print('SKIP: tests/fake_harness.py is a source-checkout file, not shipped in the wheel')
    raise SystemExit(77)


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        return main(argv), buf.getvalue()


with tempfile.TemporaryDirectory() as td:
    bad = Path(td) / "bad.json"
    bad.write_text(json.dumps({"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./nope"}), encoding="utf-8")
    code, _ = run(["run", str(bad), "--relation", "core-codec-round-trip"])
    check(code == 2, f"unopenable target run exited {code}")
    good = Path(td) / "good.json"
    good.write_text(json.dumps({"target": "fake", "version": "1.0.0", "adapter": "c",
                                 "harness": str(ROOT / "tests" / "fake_harness.py"),
                                 "algorithms": ["fake-kem"], "kind": "kem"}), encoding="utf-8")
    code, out = run(["run", str(good), "--relation", "core-kem-round-trip"])
    check(code == 0, f"healthy target after a dead one exited {code}: {out[:200]}")
print("dead target reported NOT_REACHED; the next target still ran to a clean conclusive result")
passed("multi-target fault isolation")
