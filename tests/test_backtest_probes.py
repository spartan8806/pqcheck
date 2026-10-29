import py_compile
import tempfile
import unittest
from pathlib import Path

from pqcheck.backtest.corpus import CORPUS, Defect
from pqcheck.backtest.report import GRADES, evaluate
from pqcheck.cli import _write_reproducers
from pqcheck.manifest import Manifest
from pqcheck.probes import EXIT_PARTIAL, EXIT_SKIPPED, _classify, run_probes
from pqcheck.verdict import Claim, Method, Report, Subject, Verdict


class BacktestTests(unittest.TestCase):
    def test_corpus_accounting(self):
        result = evaluate()
        self.assertEqual(result["counts"], {
            "DEMONSTRATED": 7, "ARGUED": 5, "PARTIAL": 4,
            "MISSED": 2, "OUT_OF_SCOPE": 4,
        })
        self.assertNotIn("COVERED", result["counts"])
        self.assertEqual(
            [e.id for e, g in result["rows"] if g == "MISSED"],
            ["clib-xmss-key-reuse", "CVE-2022-37454"],
        )
        self.assertEqual(
            [e.id for e, g in result["rows"] if g == "OUT_OF_SCOPE"],
            ["clib-fndsa-double-ub", "mouha-update-chunking",
             "KyberSlash-1-2", "GHSA-25rm-9wvm-m38v"],
        )
        self.assertEqual(GRADES, ["DEMONSTRATED", "ARGUED", "PARTIAL", "MISSED", "OUT_OF_SCOPE"])
        for _cls, info in result["by_class"].items():
            if info["in_scope"] > 0 and info["DEMONSTRATED"] == 0:
                self.assertTrue(info["gap"])

    def test_defect_post_init_enforces_ours_disclosure(self):
        with self.assertRaises(ValueError):
            Defect("x", "t", "cls", "DEMONSTRATED", ours=True)
        with self.assertRaises(ValueError):
            Defect("x", "t", "cls", "DEMONSTRATED", disclosure="disclosed")
        with self.assertRaises(ValueError):
            Defect("x", "t", "cls", "NOT_A_GRADE")


class EkModulusTests(unittest.TestCase):
    def _run(self, target):
        import random

        import pqcheck.relations  # noqa: F401
        from pqcheck.relations.base import REGISTRY
        from pqcheck.verdict import Subject
        subject = Subject(target=target.name, commit="a1b2c3d4e5f60718293a")
        return REGISTRY["kem-ek-modulus-canonical"].run(
            target, subject, random.Random("ek-test"))

    def test_pack12_is_fips203_little_endian(self):
        from pqcheck.relations.kem_encoding import _pack12, _split_ek, _unpack12
        # FIPS 203 ByteEncode_12: c0 = b0 | ((b1 & 0x0F) << 8),
        # c1 = (b1 >> 4) | (b2 << 4)
        self.assertEqual(_unpack12(bytes([0x01, 0x20, 0x03]), 2), [1, 50])
        self.assertEqual(_pack12([1, 50]), bytes([0x01, 0x20, 0x03]))
        body, tail = _split_ek(b"B" * 48 + b"R" * 32, 48)
        self.assertEqual(body, b"B" * 48)
        self.assertEqual(tail, b"R" * 32)  # rho untouched

    def test_toy_bitpacker_is_independent_and_agrees(self):
        # The toy must not borrow the relation's codec: two independent
        # implementations agreeing is what makes probe_control a check.
        import inspect

        from pqcheck.relations.kem_encoding import _pack12, _unpack12
        from pqcheck.testing import toylwe
        src = inspect.getsource(toylwe)
        self.assertFalse(any("kem_encoding" in line and "import" in line
                             for line in src.splitlines()), src[:400])
        coeffs = [(i * 37) % 4096 for i in range(128)]
        self.assertEqual(toylwe._bitpack12(coeffs), _pack12(coeffs))
        self.assertEqual(toylwe._bitunpack12(toylwe._bitpack12(coeffs)), coeffs)
        self.assertEqual(_unpack12(toylwe._bitpack12(coeffs), 128), coeffs)

    def test_clean_packed_ek_no_defect_lax_is_defect(self):
        from pqcheck.testing.toylwe import PackedEkKem
        from pqcheck.verdict import Verdict
        self.assertIs(self._run(PackedEkKem()).verdict, Verdict.NO_DEFECT_FOUND)
        claim = self._run(PackedEkKem(mutant="no_ek_modulus_check"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)


class MutantMatrixTests(unittest.TestCase):
    def test_canonical_43_mutant_keys(self):
        from pqcheck.testing import (
            CODEC_MUTANTS, FALCON_MUTANTS, KEM_MUTANTS, LWE_MUTANTS,
            MLDSA_MUTANTS, PACKED_EK_MUTANTS, SIG_MUTANTS,
        )
        self.assertEqual(sorted(KEM_MUTANTS), sorted([
            "reject_ignores_ct", "reject_binds_prefix_only", "reject_ignores_z",
            "no_reencryption_check", "reject_nondeterministic",
            "decaps_returns_wrong_secret", "reject_uninit_on_degenerate",
            "decaps_ignores_ct_length", "decaps_reads_past_ct",
            "decaps_reads_past_ct_dirty"]))
        self.assertEqual(sorted(SIG_MUTANTS), sorted([
            "verify_ignores_ctx", "sign_produces_unverifiable",
            "refuses_every_message", "sig_overruns_declared_size",
            "no_ctx_length_prefix", "verify_accepts_degenerate",
            "verify_ignores_prehash_domain", "verify_ignores_pk_arg",
            "msg_unbound", "msg_prefix_only", "msg_truncates_at_4096",
            "msg_truncates_at_8192", "verify_accepts_trailing",
            "verify_drops_byte_at_rate_multiple", "verify_ignores_slack",
            "verify_reads_past_msg", "msg_len_wraps_at_32bit"]))
        self.assertEqual(sorted(CODEC_MUTANTS), sorted([
            "accepts_minus_zero", "accepts_nonzero_pad", "accepts_wrong_length",
            "hint_accepts_repeat", "hint_order_row0_only",
            "hint_accepts_nonzero_tail", "encoder_random_pad",
            "decoder_rejects_own_encoding"]))
        self.assertEqual(sorted(LWE_MUTANTS), sorted([
            "no_reencryption_check", "reject_ignores_z", "reject_ignores_ct"]))
        self.assertEqual(sorted(PACKED_EK_MUTANTS), sorted([
            "no_ek_modulus_check", "no_dk_hash_check"]))
        self.assertEqual(sorted(FALCON_MUTANTS), ["accepts_minus_zero"])
        self.assertEqual(sorted(MLDSA_MUTANTS), sorted([
            "accept_non_strict_hints", "ignore_nonzero_hint_tail"]))


class DemoTests(unittest.TestCase):
    def test_demo_showcase_passes(self):
        import io
        from contextlib import redirect_stdout

        from pqcheck.cli import main
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["demo"])
        text = out.getvalue()
        self.assertEqual(code, 0, text[-2000:])
        for act in ("Act 1", "Act 2", "Act 3", "Act 4", "demo: ok"):
            self.assertIn(act, text)


class ProbeTests(unittest.TestCase):
    def test_skip_line_with_exit_zero_is_protocol_failure(self):
        self.assertEqual(_classify(0, "SKIP: no binary\n"), "protocol")
        self.assertEqual(_classify(EXIT_SKIPPED, "SKIP: no binary\n"), "SKIPPED")
        self.assertEqual(_classify(EXIT_PARTIAL, "partial\n"), "PARTIAL")
        with tempfile.TemporaryDirectory() as td:
            Path(td, "verify_fake_skip.py").write_text(
                "print('SKIP: optional binary absent')\n", encoding="utf-8")
            results, code = run_probes(td)
        self.assertEqual(code, 1, results)
        self.assertEqual(results[0][1], "FAIL", results)
        self.assertIn("skip-protocol: printed a SKIP line and exited 0", results[0][2])

    def test_exit_77_probe_is_skipped_not_failed(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "verify_fake_absent.py").write_text(
                "import sys\nprint('SKIP: optional binary absent')\nsys.exit(77)\n",
                encoding="utf-8")
            results, code = run_probes(td)
        self.assertEqual(code, 0, results)
        self.assertEqual(results[0][1], "SKIPPED", results)
    def test_standing_probes_pass(self):
        results, code = run_probes()
        self.assertEqual(code, 0, results)
        self.assertTrue(all(s in ("PASS", "SKIPPED") for _n, s, _d in results), results)
        self.assertTrue(any(s == "PASS" for _n, s, _d in results), results)


class ReproducerTests(unittest.TestCase):
    def test_reproducer_script_is_generated_and_compiles(self):
        claim = Claim(
            subject=Subject(target="x", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4", algorithm="fake-kem"),
            property="p", verdict=Verdict.DEFECT_FOUND, method=Method("core-kem-round-trip", None),
            ceiling="c", reproduce="re-run the pinned relation again now",
        )
        manifest = Manifest({"target": "x", "version": "1.0.0", "adapter": "codec", "harness": "./h"}, Path("manifest.json"))

        class Args:
            set = []
            seed = None

        with tempfile.TemporaryDirectory() as td:
            _write_reproducers(Path(td), manifest, Args(), Report((claim,)))
            scripts = list(Path(td).glob("*.py"))
            self.assertEqual(len(scripts), 1)
            py_compile.compile(str(scripts[0]), doraise=True)


if __name__ == "__main__":
    unittest.main()
