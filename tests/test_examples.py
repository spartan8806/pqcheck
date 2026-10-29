"""The shipped vulnerable-kem sample must actually pop."""
import unittest
from pathlib import Path

import pqcheck.relations  # noqa: F401
from pqcheck import web
from pqcheck.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "vulnerable-kem"


class VulnerableSampleTests(unittest.TestCase):
    def test_sample_folder_opens_ready_and_finds_defect(self):
        info = web.inspect_project(str(SAMPLE))
        self.assertTrue(info["ready"], info)
        self.assertIn("intentionally defective", info["target"])
        result = web.run_project(str(SAMPLE))
        self.assertGreaterEqual(result["counts"]["DEFECT_FOUND"], 1, result["counts"])
        self.assertIn("kem-fo-liveness", result["exports"]["reproduction"])

    def test_sample_cli_exit_1(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["run", str(SAMPLE / "manifest.json"),
                         "--relation", "kem-fo-liveness"])
        self.assertEqual(code, 1, buf.getvalue()[-400:])
        self.assertIn("DEFECT_FOUND", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
