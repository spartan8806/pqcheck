"""Noble mutation kit (Set 3 Phase 13): structural checks always run;
execution checks require PQCHECK_NOBLE_SRC (CI provides it and a
missing prerequisite fails the job there, per the Set 3 spec)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "regressions" / "noble-mutations"
KIT = json.loads((KIT_DIR / "noble-mutations.json").read_text(encoding="utf-8"))
SRC = os.environ.get("PQCHECK_NOBLE_SRC", "")


class KitStructureTests(unittest.TestCase):
    def test_pinned_revision_recorded(self):
        self.assertEqual(KIT["upstream_revision"], "99da15c1a5417f5c3fc36e7d84e7525fdcdbeaa9")
        self.assertEqual(KIT["upstream_version"], "0.6.1")
        for name, digest in KIT["pinned_built_sha256"].items():
            self.assertEqual(len(digest), 64, name)

    def test_case_inventory(self):
        ids = [c["id"] for c in KIT["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        buckets = {}
        for case in KIT["cases"]:
            buckets[case["bucket"]] = buckets.get(case["bucket"], 0) + 1
            if case["bucket"] != "clean-control":
                self.assertTrue(case["expected_relations"] or case.get("expected_any"), case["id"])
                self.assertTrue(case["replacements"], case["id"])
                for _f, old, new, count in case["replacements"]:
                    self.assertNotEqual(old, new, case["id"])
                    self.assertGreaterEqual(count, 1, case["id"])
        self.assertEqual(buckets["clean-control"], 1)
        self.assertEqual(buckets["should-detect"], 10)
        self.assertEqual(buckets["newly-covered"], 4)  # 3 audit misses + 8192 control

    def test_controls_cover_contract_declines(self):
        kinds = {c["validation_ek"] for c in KIT["controls"]}
        self.assertEqual(kinds, {"prevalidated-input", "unspecified"})


def _load_kit():
    import importlib.util
    spec = importlib.util.spec_from_file_location("run_kit", KIT_DIR / "run_kit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReplayValidationTests(unittest.TestCase):
    """A replay proves something only with exit 1 plus a valid JSON
    report naming the expected relation DEFECT_FOUND."""

    RID = "kem-fo-liveness"

    def _script(self, td: Path, body: str) -> Path:
        script = td / f"reproduce_{self.RID}_ml-kem-768.py"
        script.write_text(body, encoding="utf-8")
        return script

    def test_crashing_script_rejected_despite_exit_1(self):
        kit = _load_kit()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            self._script(tdp, "raise RuntimeError('boom before testing')\n")
            _n, bad, validated, _inc = kit.replay_reproducers(tdp, {self.RID}, {self.RID})
            self.assertEqual(bad, 1)
            self.assertEqual(validated, set())
            preserved = tdp / f"reproduce_{self.RID}_ml-kem-768.py.stderr.txt"
            self.assertIn("boom before testing", preserved.read_text(encoding="utf-8"))

    def test_exit_3_rejected_without_retry(self):
        kit = _load_kit()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            marker = tdp / "runs.txt"
            self._script(tdp, f"open({str(marker)!r}, 'a').write('x\\n')\n"
                              "import sys; sys.exit(3)\n")
            _n, bad, validated, _inc = kit.replay_reproducers(tdp, {self.RID}, {self.RID})
            self.assertEqual(bad, 1)
            self.assertEqual(validated, set())
            self.assertEqual(marker.read_text(encoding="utf-8").count("x"), 1,
                             "exit 3 must not be retried")

    def test_json_without_expected_defect_rejected(self):
        kit = _load_kit()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            body = ("import json, sys\n"
                    "print(json.dumps({'claims': [{'method': 'kem-fo-liveness',"
                    " 'verdict': 'NO_DEFECT_FOUND'}]}))\n"
                    "sys.exit(1)\n")
            self._script(tdp, body)
            _n, bad, validated, _inc = kit.replay_reproducers(tdp, {self.RID}, {self.RID})
            self.assertEqual(bad, 1)
            self.assertEqual(validated, set())

    def test_incidental_replay_failure_reported_not_gating(self):
        kit = _load_kit()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # an incidental (non-expected) relation whose witness
            # search does not re-find its witness on replay: exit 0
            script = tdp / "reproduce_sig-unread-bits_ml-dsa-44.py"
            script.write_text("import sys; sys.exit(0)\n", encoding="utf-8")
            _n, bad, validated, inc = kit.replay_reproducers(
                tdp, {"sig-unread-bits"}, {self.RID})
            self.assertEqual(bad, 0)
            self.assertEqual(inc, 1)
            self.assertEqual(validated, set())

    def test_valid_replay_accepted_and_output_preserved(self):
        kit = _load_kit()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            body = ("import json, sys\n"
                    "print(json.dumps({'claims': [{'method': 'kem-fo-liveness',"
                    " 'verdict': 'DEFECT_FOUND'}]}))\n"
                    "sys.exit(1)\n")
            self._script(tdp, body)
            n, bad, validated, _inc = kit.replay_reproducers(tdp, {self.RID}, {self.RID})
            self.assertEqual((n, bad), (1, 0))
            self.assertEqual(validated, {self.RID})
            preserved = tdp / f"reproduce_{self.RID}_ml-kem-768.py.stdout.txt"
            self.assertIn("DEFECT_FOUND", preserved.read_text(encoding="utf-8"))


class CaseAcceptanceTests(unittest.TestCase):
    def test_defect_report_requires_exit_1(self):
        kit = _load_kit()
        expected = {"kem-fo-liveness"}
        for code in (0, 2, 3):
            self.assertFalse(
                kit.case_accepted("should-detect", expected, set(expected), code,
                                  replay_bad=0, validated=set(expected)),
                f"defect report with exit {code} must be rejected")
        self.assertTrue(
            kit.case_accepted("should-detect", expected, set(expected), 1,
                              replay_bad=0, validated=set(expected)))
        self.assertFalse(
            kit.case_accepted("should-detect", expected, set(expected), 1,
                              replay_bad=0, validated=set()),
            "exit 1 without a validated replay must be rejected")

    def test_clean_control_rejects_any_finding(self):
        kit = _load_kit()
        self.assertFalse(kit.case_accepted("clean-control", set(), {"x"}, 0))
        self.assertFalse(kit.case_accepted("clean-control", set(), set(), 1))
        self.assertTrue(kit.case_accepted("clean-control", set(), set(), 0))

    def test_contract_control_rejects_unrelated_defect(self):
        kit = _load_kit()
        need = {"kem-ek-rejects-noncanonical", "kem-dk-rejects-hash-mismatch"}
        self.assertFalse(kit.control_accepted(need, set(need), {"some-other"}, 0))
        self.assertFalse(kit.control_accepted(need, set(need), set(), 1))
        self.assertTrue(kit.control_accepted(need, set(need), set(), 0))


@unittest.skipUnless(SRC, "PQCHECK_NOBLE_SRC not set (CI noble-kit job sets it)")
class KitExecutionTests(unittest.TestCase):
    def test_missing_prereq_is_loud(self):
        proc = subprocess.run(
            [sys.executable, str(KIT_DIR / "run_kit.py"), "--src", str(ROOT / "does-not-exist")],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("PREREQUISITE", proc.stderr)

    def test_new_cases_seed1(self):
        proc = subprocess.run(
            [sys.executable, str(KIT_DIR / "run_kit.py"), "--src", SRC,
             "--cases", "baseline", "explore-kem-ek-modulus-check-removed",
             "explore-kem-dk-hash-check-removed", "explore-sig-long-message-truncation",
             "control-sig-truncation-8192", "--seed", "1"],
            capture_output=True, text=True, timeout=1200)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
