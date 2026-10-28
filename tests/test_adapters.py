import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pqcheck.adapters.cbridge import CTarget, parse_hex_reply
from pqcheck.adapters.codec_bridge import CodecTarget
from pqcheck.adapters.hint_bridge import HintTarget
from pqcheck.target import Capability

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")


@unittest.skipUnless(CC, "no C compiler available")
class CAdapterTests(unittest.TestCase):
    def _build(self, source, out):
        subprocess.run([CC, "-O1", "-o", str(out), str(source)], check=True, capture_output=True, text=True, timeout=120)

    def test_kem_harness_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / ("harness.exe" if sys.platform == "win32" else "harness")
            self._build(ROOT / "pqcheck" / "adapters" / "c_harness.c", exe)
            target = CTarget(str(exe), "kem", "template-kem")
            try:
                self.assertIn(Capability.KEM, target.caps)
                kg = target.keygen()
                self.assertTrue(kg.ok)
                ek, dk = kg.value
                enc = target.encaps(ek)
                self.assertTrue(enc.ok)
                ss, ct = enc.value
                self.assertEqual(target.decaps(dk, ct).value, ss)
            finally:
                target.close()

    def test_codec_and_hint_harnesses(self):
        with tempfile.TemporaryDirectory() as td:
            cexe = Path(td) / ("codec.exe" if sys.platform == "win32" else "codec")
            hexe = Path(td) / ("hint.exe" if sys.platform == "win32" else "hint")
            self._build(ROOT / "pqcheck" / "adapters" / "codec_harness.c", cexe)
            self._build(ROOT / "pqcheck" / "adapters" / "hint_harness.c", hexe)
            codec = CodecTarget(str(cexe))
            hint = HintTarget(str(hexe))
            try:
                enc = codec.encode((0, 1, -1, 2, -2, 3, -3, 0))
                self.assertTrue(enc.ok)
                self.assertTrue(codec.decode(enc.value).ok)
                self.assertFalse(codec.decode(enc.value[:-1]).ok)
                h = hint.encode_hints([[1, 3], [5]])
                self.assertTrue(h.ok)
                self.assertTrue(hint.decode_hints(h.value).ok)
            finally:
                codec.close(); hint.close()


class BridgeTests(unittest.TestCase):
    def _cmd(self):
        return [sys.executable, str(Path(__file__).with_name("fake_harness.py"))]

    def test_cbridge_kem_and_sig(self):
        kem = CTarget(self._cmd(), "kem", "fake-kem")
        sig = CTarget(self._cmd(), "sig", "fake-sig")
        try:
            self.assertIn(Capability.KEM, kem.caps)
            ek, dk = kem.keygen().value
            ss, ct = kem.encaps(ek).value
            self.assertEqual(kem.decaps(dk, ct).value, ss)
            pk, sk = sig.keygen().value
            s = sig.sign(sk, b"hello")
            self.assertTrue(s.ok)
            self.assertTrue(sig.verify(pk, b"hello", s.value).ok)
            self.assertFalse(sig.verify(pk, b"bye", s.value).ok)
            self.assertTrue(sig.fixed_sig_len)
        finally:
            kem.close(); sig.close()

    def test_codec_and_hint_bridges(self):
        codec = CodecTarget(self._cmd() + ["codec"])
        hint = HintTarget(self._cmd() + ["hint"])
        try:
            enc = codec.encode((0, 1, -1, 2, -2, 3, -3, 0))
            self.assertTrue(enc.ok)
            self.assertTrue(codec.decode(enc.value).ok)
            h = hint.encode_hints([[1, 3], [5]])
            self.assertTrue(h.ok)
            self.assertTrue(hint.decode_hints(h.value).ok)
        finally:
            codec.close(); hint.close()


class ExecAdapterTests(unittest.TestCase):
    """The subprocess line protocol is execution-tested without gcc
    by driving templates/python_harness.py through the exec adapter."""

    HARNESS = ROOT / "pqcheck" / "adapters" / "templates" / "python_harness.py"

    def _manifest(self, kind, algorithm):
        from pqcheck.manifest import Manifest
        return Manifest({
            "target": "python-harness-template", "version": "1.0.0",
            "adapter": "exec", "kind": kind,
            "command": [sys.executable, str(self.HARNESS)],
            "algorithms": [f"{kind}:{algorithm}"],
        }, ROOT / "manifest.json")

    def _run_relation(self, rid, kind, algorithm):
        import random

        import pqcheck.relations  # noqa: F401
        from pqcheck.cli import open_target
        from pqcheck.relations.base import REGISTRY
        from pqcheck.verdict import Subject
        manifest = self._manifest(kind, algorithm)
        target = open_target(manifest, f"{kind}:{algorithm}")
        try:
            subject = Subject(target="python-harness-template",
                              commit="1.0.0", algorithm=algorithm)
            return REGISTRY[rid].run(target, subject, random.Random("exec-test"))
        finally:
            target.close()

    def test_exec_kem_clean_over_wire(self):
        from pqcheck.verdict import Verdict
        claim = self._run_relation("kem-fo-liveness", "kem", "WireKem")
        self.assertIs(claim.verdict, Verdict.NO_DEFECT_FOUND, claim.evidence)

    def test_exec_kem_mutant_over_wire(self):
        from pqcheck.verdict import Verdict
        claim = self._run_relation(
            "kem-fo-liveness", "kem", "WireKem[no_reencryption_check]")
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)

    def test_exec_sig_over_wire(self):
        from pqcheck.verdict import Verdict
        claim = self._run_relation("core-sig-round-trip", "sig", "WireSig")
        self.assertIs(claim.verdict, Verdict.NO_DEFECT_FOUND, claim.evidence)


class PythonAdapterTests(unittest.TestCase):
    def test_python_reference_manifest_opens_toys(self):
        from pqcheck.cli import open_target
        from pqcheck.manifest import Manifest
        manifest = Manifest.load(ROOT / "manifests" / "python-reference.json")
        names = {type(open_target(manifest, a)).__name__ for a in manifest.algorithms}
        self.assertEqual(names, {"PackedEkKem", "ToySig", "ToyFalconSig", "ToyMldsaSig"})


class ParseTests(unittest.TestCase):
    def test_parse_hex_reply(self):
        self.assertEqual(parse_hex_reply("00ff"), b"\x00\xff")
        self.assertIsNone(parse_hex_reply("zz"))
        self.assertIsNone(parse_hex_reply("abc"))


if __name__ == "__main__":
    unittest.main()
