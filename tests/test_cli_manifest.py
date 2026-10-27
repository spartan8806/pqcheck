import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from pqcheck.cli import main
from pqcheck.discover import discover
from pqcheck.manifest import Manifest, ManifestError
from pqcheck.tui import render_claim
from pqcheck.verdict import Claim, Coverage, Method, Subject, Verdict

ROOT = Path(__file__).resolve().parents[1]


def write_manifest(td, data):
    p = Path(td) / "manifest.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


class ManifestTests(unittest.TestCase):
    def test_moving_version_refused(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_manifest(td, {"target": "x", "version": "main", "adapter": "codec", "harness": "./h"})
            with self.assertRaises(ManifestError):
                Manifest.load(p)

    def test_set_override_revalidates(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_manifest(td, {"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./h"})
            m = Manifest.load(p)
            with self.assertRaises(ManifestError):
                m.with_overrides(["version=latest"])

    def test_missing_paths(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_manifest(td, {"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./nope"})
            self.assertTrue(Manifest.load(p).missing_paths())


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_relations_and_adapters(self):
        self.assertEqual(self.run_cli(["relations"])[0], 0)
        self.assertEqual(self.run_cli(["adapters"])[0], 0)

    def test_bad_manifest_exit_3(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_manifest(td, {"target": "x", "version": "main", "adapter": "codec", "harness": "./h"})
            self.assertEqual(self.run_cli(["run", str(p)])[0], 3)

    def test_missing_harness_exit_2_established_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_manifest(td, {"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./nope"})
            code, out = self.run_cli(["run", str(p)])
            self.assertEqual(code, 2)
            self.assertIn("ESTABLISHED NOTHING", out)

    def test_fake_harness_kem_run_exit_0(self):
        with tempfile.TemporaryDirectory() as td:
            p = write_manifest(td, {
                "target": "fake", "version": "1.0.0", "adapter": "c",
                "harness": str(ROOT / "tests" / "fake_harness.py"),
                "algorithms": ["fake-kem"], "kind": "kem",
            })
            code, out = self.run_cli(["run", str(p), "--relation", "core-kem-round-trip"])
            self.assertEqual(code, 0, out)
            self.assertIn("NO DEFECT FOUND", out)


class DiscoverTests(unittest.TestCase):
    def test_discovers_manifest_without_executing(self):
        with tempfile.TemporaryDirectory() as td:
            write_manifest(td, {"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./nope"})
            kinds = [c.kind for c in discover(td)]
            self.assertIn("manifest", kinds)


class TuiTests(unittest.TestCase):
    def test_no_defect_is_never_green(self):
        claim = Claim(
            subject=Subject(target="t", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"),
            property="p", verdict=Verdict.NO_DEFECT_FOUND, method=Method("m", None),
            ceiling="c", coverage=Coverage("x", 1),
        )
        rendered = render_claim(claim)
        self.assertIn("\x1b[37m", rendered)
        self.assertNotIn("\x1b[32", rendered)
        self.assertNotIn("\x1b[1;32", rendered)


if __name__ == "__main__":
    unittest.main()
