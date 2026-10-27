#!/usr/bin/env python3
"""Constructed-probe controls: a wrong assumed layout is NOT_ANSWERABLE."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.testing.toylwe import PackedEkKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("kem-ek-modulus-canonical", ToyKem())
check(claim.verdict is Verdict.NOT_ANSWERABLE,
      f"hash-shaped ek gave {claim.verdict.value}, expected NOT_ANSWERABLE")
print("ek-modulus probes decline when the target has no 12-bit packed ek (wrong assumed layout)")
claim = registry_run("kem-ek-modulus-canonical", PackedEkKem())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"packed ek clean gave {claim.verdict.value}")
claim = registry_run("kem-ek-modulus-canonical", PackedEkKem(mutant="no_ek_modulus_check"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"modulus-lax mutant gave {claim.verdict.value}")
print("packed ek: canonical coefficients pass, +q coefficients are a DEFECT_FOUND")
passed("probe control")
