#!/usr/bin/env python3
"""ct-bit-contribution counts comparable observations, not attempts."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.precision import ExplicitRejectKem  # noqa: E402
from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("kem-reject-ct-bit-contribution", ToyKem())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean KEM gave {claim.verdict.value}")
check(claim.coverage.units >= 21, f"only {claim.coverage.units} comparable units counted")
print(f"clean KEM: {claim.coverage.units} comparable bit-flip observations counted")

claim = registry_run("kem-reject-ct-bit-contribution", ToyKem(mutant="reject_binds_prefix_only"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"ignored byte gave {claim.verdict.value}")
print("a byte that does not contribute -> DEFECT_FOUND")

claim = registry_run("kem-reject-ct-bit-contribution", ExplicitRejectKem())
check(claim.verdict in (Verdict.NOT_REACHED, Verdict.NOT_ANSWERABLE),
      f"explicit-rejection KEM gave {claim.verdict.value}, expected decline")
print("explicit-rejection KEM declines (no implicit secret to count)")
passed("ct-bit comparable counting")
