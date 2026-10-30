#!/usr/bin/env python3
"""ERR from a harness is a protocol error, never a target rejection."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, check, passed  # noqa: E402

from pqcheck.adapters.cbridge import CTarget  # noqa: E402
from pqcheck.target import HarnessProtocolError  # noqa: E402

SCRIPT = '''
import sys
for line in sys.stdin:
    cmd = line.split()[0] if line.split() else ""
    if cmd == "info":
        print("OK kind=kem alg=fake pk=32 sk=96 ct=32 ss=32 guard=1", flush=True)
    else:
        print("ERR harness cannot marshal that request", flush=True)
'''

with tempfile.TemporaryDirectory() as td:
    harness = Path(td) / "err_harness.py"
    harness.write_text(SCRIPT, encoding="utf-8")
    target = CTarget([sys.executable, str(harness)], "kem", "fake")
    try:
        try:
            target.keygen()
            check(False, "ERR reply was swallowed")
        except HarnessProtocolError:
            print("ERR reply raised HarnessProtocolError (not Status.REJECTED, not a crash)")
    finally:
        target.close()
check((ROOT / "pqcheck" / "adapters" / "cbridge.py").exists(), "workspace layout changed")
passed("harness channel: ERR is a protocol error")
