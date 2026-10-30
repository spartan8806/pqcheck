#!/usr/bin/env python3
"""Muse AI expansion: offline mode, clean gate, ephemeral wipe."""
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import check, passed  # noqa: E402

from pqcheck import ai  # noqa: E402
from pqcheck.testing.toy import ToySig  # noqa: E402
from pqcheck.testing.toylwe import ToyLweKem  # noqa: E402
from pqcheck.verdict import Subject, Verdict  # noqa: E402

SUBJ = Subject(target="probe", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")

# 1. Offline mode works with no API key (0 errors).
check(ai.resolve_mode(env={}) == "inactive", "offline mode is not inactive")
check(str(len(ai.REGISTRY)) in ai.inactive_footer(), "footer missing relation count")

SPEC = {"id": "probe-boundary", "failure_class": "f", "description": "boundary probe",
        "kind": "sig-boundary-message-and-tail-probe", "probe_strategy": "s",
        "parameters": {"require_randomized_signing": True}, "ceiling": "c",
        "false_positive_modes": []}


class CrashSig(ToySig):
    def sign(self, *args, **kwargs):
        raise RuntimeError("target exploded")


# 2. Wipe holds even when the target crashes inside the check.
verifier = ai.EphemeralVerifier()
crash_spec = dict(SPEC, id="probe-crash", parameters={})
outcome = verifier.verify(crash_spec, CrashSig(), ToySig, SUBJ, random.Random(3))
check(outcome.claim is not None and outcome.claim.verdict is Verdict.NOT_REACHED,
      "crashing target did not produce NOT_REACHED")
check(outcome.wiped and not os.path.exists(outcome.tmp_dir),
      "ephemeral dir survived a crashing target")

# 3. Over-aggressive candidate is blocked by the clean gate.
outcome = verifier.verify(SPEC, ToySig(mutant="verify_ignores_slack"),
                          ToySig, SUBJ, random.Random(3))
check(outcome.rejected_by_clean_control and outcome.claim is None,
      "over-aggressive candidate was not blocked by the clean gate")

# 4. Valid candidate catches the mutant; receipt populates; wipe holds.
from pqcheck.relations.base import REGISTRY  # noqa: E402
from pqcheck.verdict import Report  # noqa: E402

target = ToyLweKem(mutant="no_reencryption_check")
subject = Subject(target="ToyLweKem", commit=SUBJ.commit)
claims = [rel.run(target, subject, random.Random(f"probe:{rid}"))
          for rid, rel in sorted(REGISTRY.items())]
expanded = ai.expand_report(Report(tuple(claims)), target,
                            ai.SimulatedMuseClient(), subject,
                            random.Random(5), mode="simulated")
receipt = expanded.ai_receipt
check(receipt["candidates_rejected_by_clean_control"] >= 1, "no clean-gate rejection")
check(receipt["ephemeral_temp_dirs_created"] == receipt["ephemeral_temp_dirs_wiped"],
      "ephemeral dirs not all wiped")
ai_claims = expanded.claims[len(claims):]
check(any(c.verdict is Verdict.DEFECT_FOUND for c in ai_claims),
      "valid Muse candidate did not catch the mutant")
check(all(ai._check_no_secret_material(c) for c in ai_claims),
      "secret-material floor failed on a Muse claim")
print(f"Muse expansion simulated: proposed={receipt['candidates_proposed']} "
      f"rejected={receipt['candidates_rejected_by_clean_control']} "
      f"verified={receipt['candidates_verified']} wiped="
      f"{receipt['ephemeral_temp_dirs_wiped']}/{receipt['ephemeral_temp_dirs_created']}")
passed("muse ephemeral expansion (offline, clean-gated, wiped)")
