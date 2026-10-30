import random
import re
import unittest

import pqcheck.relations  # noqa: F401
from pqcheck import web
from pqcheck.html_report import report_to_html
from pqcheck.relations.base import REGISTRY
from pqcheck.testing.toy import ToyKem
from pqcheck.verdict import Claim, Method, Report, Subject, Verdict

SUBJ = Subject(target="html-test", commit="a1b2c3d4e5f60718293a")


def _run(rid, target):
    return REGISTRY[rid].run(target, SUBJ, random.Random(f"html:{rid}"))


class HtmlReportTests(unittest.TestCase):
    def test_buckets_order_and_no_score(self):
        claims = (
            _run("kem-fo-liveness", ToyKem(mutant="no_reencryption_check")),
            _run("kem-fo-liveness", ToyKem()),
            _run("core-kem-round-trip", ToyKem()),
            Claim(subject=SUBJ, property="escape probe",
                  verdict=Verdict.NOT_REACHED,
                  method=Method(name="html-escape-probe", oracle=None),
                  ceiling="escape ceiling",
                  evidence='a < b & "quoted" <script>alert(1)</script>'),
        )
        text = report_to_html(Report(claims))
        self.assertLess(text.index("DEFECT FOUND"), text.index("NO DEFECT FOUND"))
        self.assertIn("NO DEFECT FOUND (one-sided", text)
        self.assertIn("Why is there no percentage score?", text)
        self.assertIn("measures tool effort", text)
        self.assertIsNone(re.search(r"\d+(?:\.\d+)?\s*%", text))
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn("<script>alert", text)
        self.assertIn("runner_calls:", text)

    def test_report_to_html_method(self):
        report = Report((_run("core-kem-round-trip", ToyKem()),))
        self.assertTrue(report.to_html().startswith("<!DOCTYPE html>"))


class WebDataTests(unittest.TestCase):
    def test_catalog_and_relations(self):
        catalog = web.targets_catalog()
        self.assertEqual(len(catalog["mutants"]), 43)
        self.assertIn("PackedEkKem", catalog["clean"])
        self.assertEqual(len(catalog["boundary"]), 8)
        rows = web.relations_data()
        self.assertEqual(len(rows), 34)
        self.assertTrue(all("failure_class" in r for r in rows))
        self.assertEqual(len(web.relations_data(fclass="X-FO-LIVE")), 1)

    def test_run_clean_and_mutant(self):
        clean = web.run_target("clean:PackedEkKem")
        self.assertEqual(clean["counts"]["DEFECT_FOUND"], 0)
        mutant = web.run_target("mutant:PACKED_EK:no_ek_modulus_check")
        self.assertGreaterEqual(mutant["counts"]["DEFECT_FOUND"], 1)

    def test_manifest_reports_distinguish_real_from_fixture(self):
        rows = {m["name"]: m for m in web.manifests_data()}
        self.assertEqual(rows["enc-rust-vulnerable.json"]["revision"],
                         "121385c2c9bab5ab509104b3e7b13259fc8a4080")
        self.assertEqual(rows["enc-rust-fixed.json"]["revision"],
                         "572a37f395e3c3bcf60d89bea89885b4dc13c176")
        self.assertIn("real target", rows["enc-rust-fixed.json"]["kind"])
        self.assertIn("reference fixture", rows["python-reference.json"]["kind"])
        catalog = web.targets_catalog()
        self.assertIn("toy fixture", catalog["kinds"]["clean"])
        unbuilt = web.run_named_manifest("enc-rust-vulnerable.json")
        self.assertGreater(unbuilt["counts"].get("NOT_REACHED", 0), 0,
                           unbuilt)  # nothing established, visibly
        self.assertEqual(unbuilt["counts"].get("NO_DEFECT_FOUND", 0), 0)
        codec = web.run_named_manifest("falcon-codec.json")
        self.assertGreater(codec["counts"].get("NOT_REACHED", 0), 0,
                           codec)  # codec manifest opens one target
        reference = web.run_named_manifest("python-reference.json")
        self.assertEqual(reference["revision"], "0.1.0b1")
        self.assertIn("gaps", reference)

    def test_page_script_has_no_broken_js_string(self):
        # A literal newline inside a JS string kills the whole page
        # script (every button dead). The muse output join must reach
        # the browser as an escaped \n, not a raw line break.
        import re
        script = re.search(r"<script>(.*?)</script>", web.PAGE, re.S).group(1)
        self.assertIn('join("\\n")', script)
        self.assertNotIn('join("\n")', script)

    def test_project_workflow_is_the_real_default(self):
        import tempfile
        from pathlib import Path

        page = web.PAGE
        self.assertLess(page.index('data-tab="project"'),
                        page.index('data-tab="demo"'))
        self.assertIn("Demo / Self-test", page)
        root = Path(__file__).resolve().parents[1]
        ready = web.inspect_project(str(root / "manifests" / "python-reference.json"))
        self.assertTrue(ready["ready"], ready)
        self.assertEqual(ready["target"], "pqcheck-reference-toys")
        self.assertEqual(ready["revision"], "0.1.0b1")
        run = web.run_project(str(root / "manifests" / "python-reference.json"))
        self.assertIn("exports", run)
        self.assertIn('"counts"', run["exports"]["json"])
        self.assertIn("pqcheck", run["exports"]["reproduction"])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "main.c").write_text("int main(void){return 0;}")
            unsupported = web.inspect_project(td)
            self.assertFalse(unsupported["ready"], unsupported)
            self.assertTrue(unsupported["next_steps"], unsupported)
            nowhere = web.inspect_project(str(Path(td) / "does-not-exist"))
            self.assertFalse(nowhere["found"])

    def test_about_page_explains_how_and_why(self):
        self.assertIn('data-tab="about"', web.PAGE)
        for phrase in ("How pqcheck works, and why", "no score",
                       "Inconclusive", "What pqcheck cannot establish",
                       "examples/vulnerable-kem"):
            self.assertIn(phrase, web.PAGE)

    def test_reader_verdict_inconclusive_for_one_sided(self):
        result = web.run_target("clean:ToyKem")
        flat = [c for bucket in result["buckets"].values() for c in bucket]
        one_sided = [c for c in flat if c["one_sided"]
                     and c["verdict"] == "NO_DEFECT_FOUND"]
        self.assertTrue(one_sided)
        self.assertTrue(all(c["reader_verdict"].startswith("Inconclusive")
                            for c in one_sided))

    def test_backtest_data(self):
        data = web.backtest_data()
        self.assertEqual(len(data["entries"]), 22)
        self.assertEqual(data["work_queue"],
                         ["clib-xmss-key-reuse", "CVE-2022-37454"])


if __name__ == "__main__":
    unittest.main()
