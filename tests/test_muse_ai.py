"""Muse AI Expansion Engine (pqcheck/ai.py): offline mode, clean
gate, ephemeral wipe, secret floor, receipt."""
import os
import random
import unittest

from pqcheck import ai
from pqcheck.relations.base import REGISTRY
from pqcheck.testing.toy import ToySig
from pqcheck.testing.toylwe import ToyLweKem
from pqcheck.verdict import Report, Subject, Verdict

SUBJ = Subject(target="muse-test", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")


def core_report(target, name="target"):
    subject = Subject(target=name, commit=SUBJ.commit)
    claims = [rel.run(target, subject, random.Random(f"t:{rid}"))
              for rid, rel in sorted(REGISTRY.items())]
    return Report(tuple(claims)), subject


class OfflineModeTests(unittest.TestCase):
    def test_no_key_no_flags_is_inactive(self):
        self.assertEqual(ai.resolve_mode(env={}), "inactive")
        self.assertEqual(ai.resolve_mode(env={"MUSE_API_KEY": "k"}), "live")
        self.assertEqual(ai.resolve_mode(simulate=True, env={}), "simulated")
        self.assertEqual(ai.resolve_mode(muse=True, env={}), "live")
        self.assertEqual(ai.resolve_mode(no_muse=True,
                                         env={"MUSE_API_KEY": "k"}), "inactive")

    def test_footer_names_registry_count(self):
        footer = ai.inactive_footer()
        self.assertIn(f"{len(REGISTRY)} deterministic relations", footer)
        self.assertIn("0 tokens", footer)

    def test_live_client_requires_config(self):
        with self.assertRaises(ai.MuseError):
            ai.MuseClient(base="", key="")

    def test_candidate_validation_rejects_unknown_kind(self):
        good = {"id": "x", "failure_class": "f", "description": "d",
                "kind": "kem-multi-bit-ct-perturbation",
                "probe_strategy": "s", "parameters": {}, "ceiling": "c",
                "false_positive_modes": []}
        self.assertIsNotNone(ai.validate_candidate(good))
        bad = dict(good, kind="emit-a-forgery")
        self.assertIsNone(ai.validate_candidate(bad))
        self.assertIsNone(ai.validate_candidate({"id": "x"}))
        self.assertIsNone(ai.validate_candidate("not a dict"))


class DigestTests(unittest.TestCase):
    def test_digest_fields(self):
        target = ToyLweKem(mutant="no_reencryption_check")
        report, _subject = core_report(target, "ToyLweKem")
        digest = ai.build_gap_digest(report, target)
        for key in ("target_name", "capabilities", "sizes",
                    "core_relations_ran", "core_calls_executed",
                    "estimated_tokens_saved", "already_caught",
                    "unreached_or_unanswerable"):
            self.assertIn(key, digest)
        self.assertEqual(digest["estimated_tokens_saved"],
                         digest["core_calls_executed"] * 45)
        self.assertIn("kem-fo-liveness", digest["already_caught"])
        self.assertIn("kem", digest["capabilities"])


class _CrashSig(ToySig):
    def sign(self, *args, **kwargs):
        raise RuntimeError("target exploded")


class EphemeralVerifierTests(unittest.TestCase):
    SPEC = {"id": "test-boundary", "failure_class": "f",
            "description": "boundary probe", "kind": "sig-boundary-message-and-tail-probe",
            "probe_strategy": "s", "parameters": {}, "ceiling": "c",
            "false_positive_modes": []}

    def test_wipe_even_when_target_crashes(self):
        verifier = ai.EphemeralVerifier()
        outcome = verifier.verify(self.SPEC, _CrashSig(), ToySig, SUBJ,
                                  random.Random(3))
        self.assertIsNotNone(outcome.claim)
        self.assertIs(outcome.claim.verdict, Verdict.NOT_REACHED)
        self.assertTrue(outcome.wiped)
        self.assertFalse(os.path.exists(outcome.tmp_dir))
        self.assertEqual(verifier.created, verifier.wiped)

    def test_overaggressive_candidate_blocked_by_clean_gate(self):
        spec = dict(self.SPEC, id="test-require-randomized",
                    parameters={"require_randomized_signing": True})
        verifier = ai.EphemeralVerifier()
        outcome = verifier.verify(
            spec, ToySig(mutant="verify_ignores_slack"), ToySig, SUBJ,
            random.Random(3))
        self.assertTrue(outcome.rejected_by_clean_control)
        self.assertIsNone(outcome.claim)
        self.assertFalse(os.path.exists(outcome.tmp_dir))

    def test_valid_candidate_catches_mutant_and_wipes(self):
        spec = {"id": "test-multi-bit", "failure_class": "fo-transform-absent",
                "description": "multi-bit ct probe",
                "kind": "kem-multi-bit-ct-perturbation",
                "probe_strategy": "s", "parameters": {"trials": 6},
                "ceiling": "c", "false_positive_modes": []}
        verifier = ai.EphemeralVerifier()
        outcome = verifier.verify(
            spec, ToyLweKem(mutant="no_reencryption_check"), ToyLweKem,
            SUBJ, random.Random(3))
        self.assertIsNotNone(outcome.claim)
        self.assertIs(outcome.claim.verdict, Verdict.DEFECT_FOUND)
        self.assertTrue(ai._check_no_secret_material(outcome.claim))
        self.assertIn("muse-wonder-1.0", outcome.claim.method.oracle)
        self.assertFalse(os.path.exists(outcome.tmp_dir))


class ExpansionReceiptTests(unittest.TestCase):
    def test_expand_report_populates_receipt(self):
        target = ToyLweKem(mutant="no_reencryption_check")
        report, subject = core_report(target, "ToyLweKem[mutant]")
        expanded = ai.expand_report(report, target, ai.SimulatedMuseClient(),
                                    subject, random.Random(5), mode="simulated")
        receipt = expanded.ai_receipt
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["mode"], "simulated")
        self.assertGreaterEqual(receipt["candidates_rejected_by_clean_control"], 1)
        self.assertGreaterEqual(receipt["candidates_verified"], 1)
        self.assertEqual(receipt["ephemeral_temp_dirs_created"],
                         receipt["ephemeral_temp_dirs_wiped"])
        self.assertTrue(receipt["ephemeral_dir_wiped"])
        ai_claims = expanded.claims[len(report.claims):]
        self.assertTrue(any(c.verdict is Verdict.DEFECT_FOUND for c in ai_claims))
        rendered = expanded.to_text()
        self.assertIn("Muse AI expansion: simulated", rendered)
        self.assertIn("100% wiped, 0 wild PoCs on disk", rendered)

    def test_act5(self):
        _lines, failures, receipt, claims = ai.run_act5()
        self.assertEqual(failures, [])
        self.assertTrue(receipt["ephemeral_dir_wiped"])
        self.assertTrue(any(c.verdict is Verdict.DEFECT_FOUND for c in claims))


if __name__ == "__main__":
    unittest.main()
