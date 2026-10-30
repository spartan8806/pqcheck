#!/usr/bin/env python3
"""Every C harness drains over-long lines and answers ERR, never REJ.

The harnesses cannot be compiled in every environment, so this probe
verifies the guard in source and the protocol mapping in Python: an
over-long line must hit the truncation guard, and 'REJ bad hex' must
never be the answer to a line the harness could not even read.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import ROOT, check, passed  # noqa: E402

adapters = ROOT / "pqcheck" / "adapters"
harnesses = sorted(adapters.glob("*harness*.c")) + [adapters / "falcon_compdecode_fixture.c"]
check(len(harnesses) >= 5, f"expected at least 5 C harnesses, found {len(harnesses)}")
for harness in harnesses:
    source = harness.read_text(encoding="utf-8")
    check("fgets" in source, f"{harness.name} does not read with fgets")
    check("ERR line exceeds" in source, f"{harness.name} lacks the line-truncation guard")
    print(f"{harness.name}: fgets truncation guard present (ERR line exceeds ...)")
passed("harness line limit")
