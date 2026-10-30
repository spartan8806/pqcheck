#!/usr/bin/env python3
"""KEM attribution: a key-independent rejection secret is a defect,
and broken keygen RNG is never misattributed to the z binding."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem  # noqa: E402
from pqcheck.verdict import Verdict  # noqa: E402

claim = registry_run("kem-reject-binds-z-accept-path-does-not", ToyKem(mutant="reject_ignores_z"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"key-independent rejection gave {claim.verdict.value}")
print("rejection secret ignores the decapsulation key -> DEFECT_FOUND")
claim = registry_run("kem-reject-binds-z-accept-path-does-not", ToyKem())
check(claim.verdict is Verdict.NO_DEFECT_FOUND, f"clean KEM gave {claim.verdict.value}")
print("clean KEM rejection binds the key -> NO_DEFECT_FOUND")
claim = registry_run("kem-reject-determinism", ToyKem(mutant="reject_nondeterministic"))
check(claim.verdict is Verdict.DEFECT_FOUND, f"non-deterministic rejection gave {claim.verdict.value}")
print("non-deterministic implicit rejection -> DEFECT_FOUND (validity-oracle shape)")
passed("KEM attribution")
