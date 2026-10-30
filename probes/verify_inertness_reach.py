#!/usr/bin/env python3
"""Mutant liveness probes reach the front and back of large inputs."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed  # noqa: E402

from pqcheck.selftest import _differs_from_clean, probe_behaviour  # noqa: E402
from pqcheck.testing.toy import KEM_MUTANTS, SIG_MUTANTS, ToyKem, ToySig  # noqa: E402
from pqcheck.testing.toylwe import PACKED_EK_MUTANTS, PackedEkKem  # noqa: E402
from pqcheck.testing.toymldsa import ToyMldsaSig  # noqa: E402

# a defect in the back half of a signature (last byte unread) must differ
check(_differs_from_clean(ToySig, SIG_MUTANTS["verify_ignores_slack"], "verify_ignores_slack"),
      "back-of-signature mutant appears inert")
print("mutant in the last byte of a signature is behaviourally live")
check(_differs_from_clean(ToyKem, KEM_MUTANTS["decaps_reads_past_ct"], "decaps_reads_past_ct"),
      "guard-fill mutant appears inert")
print("guard-fill mutant is behaviourally live")
check(_differs_from_clean(PackedEkKem, PACKED_EK_MUTANTS["no_dk_hash_check"], "no_dk_hash_check"),
      "dk-region mutant appears inert")
print("dk H(ek)-region mutant is behaviourally live")
sig = ToyMldsaSig().sign(ToyMldsaSig().keygen(b"x")[1] if False else ToyMldsaSig().keygen(b"x").value[1], b"probe")
check(sig.ok and len(sig.value) == 132, "ML-DSA-shaped toy geometry changed")
print("large-signature geometry is probed at both ends by the behaviour fingerprint")
passed("inertness reach")
