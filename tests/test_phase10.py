import json
import unittest
from pathlib import Path

from pqcheck.cli import _split_algorithm
from pqcheck.manifest import Manifest

ROOT = Path(__file__).resolve().parents[1]


class Phase10Tests(unittest.TestCase):
    def test_shipped_manifests_load(self):
        manifests = sorted((ROOT / "manifests").glob("*.json"))
        self.assertEqual(len(manifests), 8)
        for path in manifests:
            manifest = Manifest.load(path)
            self.assertTrue(manifest.target)

    def test_manifest_versions_are_exact(self):
        noble = json.loads((ROOT / "manifests" / "noble.json").read_text())
        self.assertEqual(noble["version"], "0.6.1")
        pqclean = json.loads((ROOT / "manifests" / "pqclean.json").read_text())
        self.assertEqual(pqclean["version"], "0586a82")

    def test_kind_prefix_parsing(self):
        self.assertEqual(_split_algorithm("kem:ML-KEM-768"), ("kem", "ML-KEM-768"))
        self.assertEqual(_split_algorithm("ml-dsa-65"), (None, "ml-dsa-65"))
        self.assertEqual(_split_algorithm(None), (None, None))

    def test_packaging(self):
        text = (ROOT / "pyproject.toml").read_text()
        self.assertIn('version = "0.1.0b1"', text)
        self.assertIn("dependencies = []", text)
        self.assertIn('"pqcheck.testing"', text)

    def test_ci_and_security_exist(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("windows-latest", ci)
        self.assertIn("python pqcheck/selftest.py", ci)
        security = (ROOT / "SECURITY.md").read_text()
        self.assertIn("False reassurance", security)

    def test_tools_scripts_exist(self):
        for name in ("build_pqclean.sh", "build_liboqs.sh", "build_clib.sh", "rebuild_harness.sh", "break_mlkem.sh"):
            script = (ROOT / "tools" / name).read_text()
            self.assertTrue(script.startswith("#!/usr/bin/env bash"), name)
            self.assertIn("set -euo pipefail", script)


if __name__ == "__main__":
    unittest.main()
