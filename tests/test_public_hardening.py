"""Public-hardening regressions: untrusted manifests, web POST auth,
ctgrind error honesty, pad-bits applicability, symlink discovery,
Muse key handling / verdict immutability, read-only MCP surface."""
import random
import unittest
from pathlib import Path

from pqcheck.manifest import Manifest, ManifestError
from pqcheck.verdict import Subject

SUBJ = Subject(target="hardening", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")


class ManifestSchemaTests(unittest.TestCase):
    def test_unknown_field_rejected(self):
        with self.assertRaises(ManifestError):
            Manifest({"target": "x", "version": "1.0.0", "adapter": "c",
                      "harness": "h", "algorithms": ["kem:ML-KEM-768"],
                      "surprise": "eval(me)"})

    def test_shell_as_exec_command_rejected(self):
        with self.assertRaises(ManifestError):
            Manifest({"target": "x", "version": "1.0.0", "adapter": "exec",
                      "command": ["bash", "-c", "id"],
                      "algorithms": ["kem:ML-KEM-768"]})

    def test_algorithm_shell_metachars_rejected(self):
        with self.assertRaises(ManifestError):
            Manifest({"target": "x", "version": "1.0.0", "adapter": "c",
                      "harness": "h", "algorithms": ["kem:X;id"]})


class PadBitsTests(unittest.TestCase):
    def test_fixed_width_codec_is_not_answerable_not_clean(self):
        from pqcheck.relations.base import REGISTRY
        from pqcheck.testing.toycodec import ToyCodec
        claim = REGISTRY["sig-encoding-pad-bits-zero"].run(
            ToyCodec(), SUBJ, random.Random(1))
        self.assertEqual(claim.verdict.value, "NOT_ANSWERABLE")


class CtgrindTests(unittest.TestCase):
    def test_missing_log_is_error_not_pass(self):
        from pqcheck.adapters.ctgrind_triage import main
        self.assertEqual(main(["/nonexistent/valgrind.log", "ML-KEM-768"]), 2)


class DiscoverTests(unittest.TestCase):
    def test_directory_symlink_not_followed(self):
        import tempfile
        from pqcheck.discover import discover
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            outside = Path(td) / "outside"
            root.mkdir(); outside.mkdir()
            (outside / "x.json").write_text("{}", encoding="utf-8")
            try:
                (root / "link").symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            found = [str(c.path) for c in discover(root)]
            self.assertFalse(any("outside" in f for f in found))


class MuseLayerTests(unittest.TestCase):
    def test_explain_never_changes_verdicts(self):
        from pqcheck import ai
        from pqcheck.relations.base import REGISTRY
        from pqcheck.testing.toy import ToyKem
        claims = [REGISTRY["core-kem-round-trip"].run(
            ToyKem(), SUBJ, random.Random(2))]
        from pqcheck.verdict import Report
        report = Report(tuple(claims))
        before = [(c.method.name, c.verdict) for c in report.claims]
        text = ai.explain_report(report)
        after = [(c.method.name, c.verdict) for c in report.claims]
        self.assertEqual(before, after)
        self.assertIn("deterministic", text)

    def test_key_from_secrets_folder(self):
        import tempfile
        from pqcheck import ai
        with tempfile.TemporaryDirectory() as td:
            secrets = Path(td) / "secrets"
            secrets.mkdir()
            (secrets / "muse_api_key").write_text("test-key-value\n", encoding="utf-8")
            self.assertEqual(ai.resolve_api_key({}, root=td), "test-key-value")
            self.assertEqual(ai.resolve_api_key({"MUSE_API_KEY": "env-key"}, root=td), "env-key")


class McpTests(unittest.TestCase):
    def test_tools_are_read_only_surface(self):
        from pqcheck import mcp_server
        resp = mcp_server._handle({"method": "tools/list", "id": 1})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"pqcheck.relations", "pqcheck.run_fixture",
                                 "pqcheck.backtest", "pqcheck.explain"})
        bad = mcp_server._handle({"method": "tools/call", "id": 2,
                                  "params": {"name": "pqcheck.run_manifest",
                                             "arguments": {}}})
        self.assertIn("error", bad)

    def test_run_fixture_tool_call_returns_report(self):
        from pqcheck import mcp_server
        resp = mcp_server._handle({"method": "tools/call", "id": 3,
                                  "params": {"name": "pqcheck.run_fixture",
                                             "arguments": {"spec": "clean:ToyKem"}}})
        self.assertIn("result", resp, resp)
        result = resp["result"]["structuredContent"]
        self.assertEqual(result["spec"], "clean:ToyKem")
        self.assertIn("counts", result)
        self.assertTrue(any(n > 0 for n in result["counts"].values()),
                        result["counts"])


class WebAuthTests(unittest.TestCase):
    def test_post_authorization(self):
        from pqcheck import web
        token = web.session_token()
        handler = web._Handler.__new__(web._Handler)
        handler.headers = {"Host": "127.0.0.1:8420", "X-PQCheck-Token": token}
        self.assertTrue(handler._authorized())
        handler.headers = {"Host": "127.0.0.1:8420"}
        self.assertFalse(handler._authorized())
        handler.headers = {"Host": "127.0.0.1:8420", "X-PQCheck-Token": token,
                           "Origin": "http://evil.example"}
        self.assertFalse(handler._authorized())

    def test_host_is_exact_match_not_prefix(self):
        from types import SimpleNamespace

        from pqcheck import web
        token = web.session_token()
        server = SimpleNamespace(server_address=("127.0.0.1", 8420))
        for good in ("127.0.0.1:8420", "localhost:8420"):
            handler = web._Handler.__new__(web._Handler)
            handler.headers = {"Host": good, "X-PQCheck-Token": token}
            handler.server = server
            self.assertTrue(handler._authorized(), good)
        for evil in ("127.0.0.1:8420.evil.com", "127.0.0.1.evil.com:8420",
                     "localhost.evil:8420", "localhost:8420evil",
                     "127.0.0.1:9999", "127.0.0.1", ""):
            handler = web._Handler.__new__(web._Handler)
            handler.headers = {"Host": evil, "X-PQCheck-Token": token}
            handler.server = server
            self.assertFalse(handler._authorized(), evil)

    def test_muse_demo_get_requires_token(self):
        from types import SimpleNamespace

        from pqcheck import web
        token = web.session_token()
        server = SimpleNamespace(server_address=("127.0.0.1", 8420))

        def run(headers):
            handler = web._Handler.__new__(web._Handler)
            handler.headers = headers
            handler.path = "/api/muse-demo"
            handler.server = server
            captured = {}

            def _json(obj, code=200):
                captured["obj"] = obj
                captured["code"] = code

            handler._json = _json
            handler.do_GET()
            return captured

        self.assertEqual(
            run({"Host": "127.0.0.1:8420"})["code"], 403)
        self.assertEqual(
            run({"Host": "127.0.0.1:8420.evil.com",
                 "X-PQCheck-Token": token})["code"], 403)
        self.assertEqual(
            run({"Host": "127.0.0.1:8420",
                 "X-PQCheck-Token": token})["code"], 200)


if __name__ == "__main__":
    unittest.main()
