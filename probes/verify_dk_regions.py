#!/usr/bin/env python3
"""dk region handling: tampering H(ek) inside dk must never yield the ss."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.testing.toylwe import PackedEkKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

for target in (ToyKem(), PackedEkKem()):
    claim = registry_run("kem-dk-hash-consistency", target)
    check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"{target.name} gave {claim.verdict.value}")
    print(f"{target.name}: tampered H(ek) region never returns the honest secret")
claim = registry_run("kem-dk-hash-consistency", PackedEkKem(mutant="no_dk_hash_check"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"dk-hash-ignoring mutant gave {claim.verdict.value}")
print("dk that ignores its H(ek) region -> DEFECT_FOUND")
passed("dk regions")
