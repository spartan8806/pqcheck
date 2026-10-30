#!/usr/bin/env python3
"""CLI exit codes: 0 clean conclusive, 1 defect, 2 nothing, 3 bad input."""
import io
import json
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, check, passed  # noqa: E402

from pqcheck.cli import main  # noqa: E402

if not (ROOT / 'tests' / 'fake_harness.py').is_file():
    print('SKIP: tests/fake_harness.py is a source-checkout file, not shipped in the wheel')
    raise SystemExit(77)


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


def manifest(td, data):
    path = Path(td) / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


with tempfile.TemporaryDirectory() as td:
    good = manifest(td, {"target": "fake", "version": "1.0.0", "adapter": "c",
                          "harness": str(ROOT / "tests" / "fake_harness.py"),
                          "algorithms": ["fake-kem"], "kind": "kem"})
    code, out = run(["run", good, "--relation", "core-kem-round-trip"])
    check(code == 0, f"clean conclusive run exited {code}, expected 0")
    print("clean conclusive run -> 0")
    code, out = run(["run", good, "--relation", "kem-fo-liveness"])
    check(code == 2, f"one-sided-only run exited {code}, expected 2 (never 0)")
    print("one-sided witness search only -> 2 (established nothing)")
    missing = manifest(td, {"target": "fake", "version": "1.0.0", "adapter": "codec", "harness": "./nope"})
    code, out = run(["run", missing])
    check(code == 2 and "ESTABLISHED NOTHING" in out, f"missing harness exited {code}")
    print("unopenable target -> 2")
    bad = manifest(td, {"target": "fake", "version": "main", "adapter": "codec", "harness": "./h"})
    code, _out = run(["run", bad])
    check(code == 3, f"bad manifest exited {code}, expected 3")
    print("moving-reference manifest -> 3")
passed("CLI exit-code contract")
