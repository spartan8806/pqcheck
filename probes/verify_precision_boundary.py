#!/usr/bin/env python3
"""All 8 adversarial precision boundary cases pass."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import check, passed  # noqa: E402

from pqcheck.testing.precision import run_precision  # noqa: E402

failures = run_precision()
check(not failures, f"precision boundary failures: {failures}")
print("8 correct-but-differently-shaped targets produce no false positives outside may_fire")
passed("precision boundary suite")
