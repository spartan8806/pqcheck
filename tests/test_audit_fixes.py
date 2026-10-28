"""Regression tests for the independent audit findings (2026-10-27).

Each test names the finding it locks. Where a check needs a real
compiler/toolchain that this machine may not have, it skips
explicitly instead of passing silently.
"""
import io
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import pqcheck.relations  # noqa: F401
from pqcheck.adapters.cbridge import CTarget
from pqcheck.cli import _safe_filename_part, _write_reproducers, main
from pqcheck.manifest import Manifest
from pqcheck.relations.base import REGISTRY
from pqcheck.verdict import Claim, Method, Report, Subject, Verdict

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
SUBJ = Subject(target="audit", commit="a1b2c3d4e5f60718293a")


def _fake_cmd():
    return [sys.executable, str(Path(__file__).with_name("fake_harness.py"))]


class PrehashDeclineTests(unittest.TestCase):
    """Finding 1: C/exec adapter cannot express prehash -> decline."""

    def test_ctarget_declares_no_prehash(self):
        target = CTarget(_fake_cmd(), "sig", "fake-sig")
        try:
            self.assertIs(target.supports_prehash, False)
            self.assertFalse(target.sign(b"s" * 32, b"m", prehash=True).ok)
            claim = REGISTRY["sig-mode-domain-separation"].run(
                target, SUBJ, random.Random("audit1"))
            self.assertIs(claim.verdict, Verdict.NOT_ANSWERABLE,
                          claim.evidence + claim.notes)
        finally:
            target.close()


class ExactAllocationTests(unittest.TestCase):
    """Finding 2: payload allocations are exact (payload + guard)."""

    FILES = ("c_harness.c", "pqclean_mlkem_harness.c", "oqs_kem_harness.c",
             "codec_harness.c", "falcon_compdecode_fixture.c",
             "hint_harness.c", "timing_harness.c")

    def test_no_plus_one_slack(self):
        for name in self.FILES:
            text = (ROOT / "pqcheck" / "adapters" / name).read_text()
            self.assertNotIn("g_guard_n + 1", text, name)
            self.assertNotIn("malloc((hn / 2) + 1)", text, name)
            self.assertNotIn("malloc(hn / 2 + 1)", text, name)
            self.assertNotIn("malloc(in_len + 1)", text, name)
            self.assertNotIn("malloc(n / 2 + 1)", text, name)

    @unittest.skipUnless(CC, "no C compiler available for the ASan boundary check")
    def test_asan_exact_allocation_poisons_one_past(self):
        # A one-byte read past an exact payload+guard allocation must
        # trip AddressSanitizer; with the old +1 slack it did not.
        src = r"""
#include <stdlib.h>
#include <string.h>
int main(void) {
    size_t payload = 32, guard = 64;
    unsigned char *buf = malloc(payload + guard);
    memset(buf, 0x41, payload + guard);
    volatile unsigned char x = buf[payload + guard];
    (void)x;
    free(buf);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as td:
            c = Path(td) / "asan_probe.c"
            c.write_text(src)
            exe = Path(td) / "asan_probe"
            build = subprocess.run(
                [CC, "-fsanitize=address", "-g", "-o", str(exe), str(c)],
                capture_output=True, text=True, timeout=120)
            if build.returncode != 0:
                self.skipTest(f"ASan build unavailable: {build.stderr[:200]}")
            run = subprocess.run([str(exe)], capture_output=True, text=True,
                                 timeout=60)
            self.assertNotEqual(run.returncode, 0,
                                "one-past read was NOT poisoned under ASan")
            self.assertIn("AddressSanitizer", run.stderr)


class ExplicitLengthCapabilityTests(unittest.TestCase):
    """Item 2 correction: pointer-only C KEM APIs take no explicit
    ciphertext length, so CTarget must not declare it and the
    length-exact relation must decline, not accuse."""

    def test_ctarget_kem_lacks_explicit_length_and_declines(self):
        from pqcheck.target import Capability

        target = CTarget(_fake_cmd(), "kem", "fake-kem")
        try:
            self.assertNotIn(Capability.EXPLICIT_SIG_LENGTH, target.caps)
            claim = REGISTRY["kem-decaps-length-exact"].run(
                target, SUBJ, random.Random("lenexact"))
            self.assertIs(claim.verdict, Verdict.NOT_ANSWERABLE,
                          claim.evidence + claim.notes)
        finally:
            target.close()


class JsonHtmlOutputTests(unittest.TestCase):
    """Item 6 correction: --json stdout stays valid JSON with --html."""

    def test_json_stdout_parseable_with_html(self):
        import subprocess as _sp

        with tempfile.TemporaryDirectory() as td:
            html = Path(td) / "r.html"
            proc = _sp.run(
                [sys.executable, "-m", "pqcheck", "run",
                 "manifests/python-reference.json", "--json",
                 "--html", str(html)],
                capture_output=True, text=True, cwd=ROOT, timeout=300)
            parsed = json.loads(proc.stdout)  # raises if polluted
            self.assertIn("counts", parsed)
            self.assertIn("HTML report written", proc.stderr)
            self.assertTrue(html.is_file())


VULN_REV = "121385c2c9bab5ab509104b3e7b13259fc8a4080"
FIXED_REV = "572a37f395e3c3bcf60d89bea89885b4dc13c176"


class RevisionBindingTests(unittest.TestCase):
    """Runtime revision check: a revision-bound manifest must only
    run against a binary reporting the same rev=, through run,
    reproduce, and the shared (workbench) runner alike."""

    def _manifest(self, td, version):
        path = Path(td) / "manifest.json"
        path.write_text(json.dumps({
            "target": "enc_rust", "version": version, "adapter": "c",
            "harness": str(Path(__file__).with_name("fake_rev_harness.py")),
            "algorithms": ["kem:ML-KEM-768"]}))
        return str(path)

    def _run_cli(self, argv, rev):
        import os
        from unittest import mock

        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"PQCHECK_FAKE_REV": rev}):
            with redirect_stdout(buf):
                code = main(argv)
        return code, buf.getvalue()

    def test_correct_vulnerable_artifact_finds_defect_exit_1(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._manifest(td, VULN_REV)
            code, out = self._run_cli(
                ["run", m, "--relation", "kem-fo-liveness"], VULN_REV)
            self.assertEqual(code, 1, out[-500:])
            self.assertIn("DEFECT_FOUND", out)

    def test_correct_fixed_artifact_clean_exit_0(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._manifest(td, FIXED_REV)
            # Full run, as with the real manifests: the one-sided FO
            # check alone establishes nothing on a clean target, so
            # exit 0 comes from the conclusive relations around it.
            code, out = self._run_cli(["run", m], FIXED_REV)
            self.assertEqual(code, 0, out[-500:])
            self.assertIn("DEFECTS FOUND: 0", out)

    def test_fixed_binary_under_vulnerable_manifest_refused_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._manifest(td, VULN_REV)
            code, out = self._run_cli(
                ["run", m, "--relation", "kem-fo-liveness"], FIXED_REV)
            self.assertEqual(code, 2, out[-500:])
            self.assertIn("revision conflict", out)
            self.assertIn("NOT_REACHED", out)
            self.assertNotIn("NO_DEFECT_FOUND", out)

    def test_unknown_revision_refused_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._manifest(td, VULN_REV)
            code, out = self._run_cli(
                ["run", m, "--relation", "kem-fo-liveness"], "none")
            self.assertEqual(code, 2, out[-500:])
            self.assertIn("did not report a revision", out)

    def test_refusal_through_reproduce_and_workbench_runner(self):
        import os
        from unittest import mock

        from pqcheck.cli import run_manifest_validated
        from pqcheck.manifest import Manifest

        with tempfile.TemporaryDirectory() as td:
            m = self._manifest(td, VULN_REV)
            code, out = self._run_cli(
                ["reproduce", m, "--relation", "kem-fo-liveness"], FIXED_REV)
            self.assertEqual(code, 2, out[-500:])
            self.assertIn("revision conflict", out)
            # The workbench calls this same validated runner.
            manifest = Manifest.load(Path(m))
            with mock.patch.dict(os.environ, {"PQCHECK_FAKE_REV": FIXED_REV}):
                report = run_manifest_validated(
                    manifest, ["kem:ML-KEM-768"], ["kem-fo-liveness"])
            self.assertTrue(report.claims)
            self.assertTrue(all(c.verdict is Verdict.NOT_REACHED
                                for c in report.claims), report.claims)
            self.assertIn("revision conflict", report.claims[0].evidence)


class NobleOracleTests(unittest.TestCase):
    """Finding 3: a single-implementation run is not an oracle."""

    def test_noble_oracle_is_none(self):
        import inspect

        from pqcheck.adapters import noble
        src = inspect.getsource(noble.NobleTarget.__init__)
        self.assertIn("self.oracle = None", src)
        self.assertNotIn("independent JS implementation", src)


class ReproduceProvenanceTests(unittest.TestCase):
    """Finding 4: reproduce applies the same version check as run."""

    def _setup_noble(self, td, manifest_version):
        td = Path(td)
        pkg = td / "node_modules" / "@noble" / "post-quantum"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(json.dumps({"version": "0.6.1"}))
        manifest = td / "manifest.json"
        manifest.write_text(json.dumps({
            "target": "@noble/post-quantum", "version": manifest_version,
            "adapter": "noble", "node_cwd": str(td),
            "algorithms": ["ml-kem-768"]}))
        return manifest

    def test_reproduce_refuses_version_mismatch_like_run(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = self._setup_noble(td, "0.6.0")
            for argv in (["run", str(manifest)],
                         ["reproduce", str(manifest),
                          "--relation", "core-kem-round-trip"]):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = main(argv)
                self.assertEqual(code, 2, f"{argv[0]} gave {code}: {buf.getvalue()[-300:]}")


class ReproducerFilenameTests(unittest.TestCase):
    """Finding 5: algorithm colons must not create NTFS streams."""

    def test_safe_filename_part(self):
        self.assertEqual(_safe_filename_part("kem:ML-KEM-768"), "kem_ML-KEM-768")
        self.assertEqual(_safe_filename_part("sig:ML-DSA-65"), "sig_ML-DSA-65")
        self.assertNotIn(":", _safe_filename_part("kem:ML-KEM-768"))

    def test_reproducer_file_is_discoverable(self):
        claim = Claim(
            subject=Subject(target="x", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
                            algorithm="kem:ML-KEM-768"),
            property="p", verdict=Verdict.DEFECT_FOUND,
            method=Method("core-kem-round-trip", None), ceiling="c",
            reproduce="re-run the pinned relation again now")
        manifest = Manifest({"target": "x", "version": "1.0.0",
                             "adapter": "codec", "harness": "./h"},
                            Path("manifest.json"))

        class Args:
            set = []
            seed = None

        with tempfile.TemporaryDirectory() as td:
            _write_reproducers(Path(td), manifest, Args(), Report((claim,)))
            scripts = list(Path(td).glob("*.py"))
            self.assertEqual(len(scripts), 1, list(Path(td).iterdir()))
            self.assertGreater(scripts[0].stat().st_size, 0)
            self.assertNotIn(":", scripts[0].name)


class RustHarnessTests(unittest.TestCase):
    """Finding 6 (reopened): the harness tests ACTUAL pinned upstream
    falcon-rust code, not a locally written replacement codec."""

    RUST = ROOT / "pqcheck" / "adapters" / "rust"
    UPSTREAM_SHA256 = "a6eb5fd5e891c69627b76cd6ef249a54392730000624b5afa6aec78032eae02a"
    # git blob id of falcon-rust/src/encoding.rs at upstream commit
    # 8845fe573b2108a1a84eced6c438a4aeb6b3773c (canonical, line-ending
    # independent because the vendored file is LF-normalized and
    # .gitattributes pins eol=lf for it)
    UPSTREAM_BLOB = "d8dee7cc5606d6fef1ff9c61e734d25b15136969"

    def test_vendored_upstream_file_is_byte_identical(self):
        import hashlib

        data = (self.RUST / "upstream_encoding.rs").read_bytes()
        self.assertNotIn(b"\r\n", data, "vendored file must stay LF")
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.UPSTREAM_SHA256,
                         "vendored upstream encoding.rs drifted from the "
                         "pinned falcon-rust v0.3.0 file")
        blob = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
        self.assertEqual(blob, self.UPSTREAM_BLOB,
                         "vendored file no longer matches the upstream "
                         "Git blob at the pinned commit")

    def test_harness_shell_has_no_local_codec(self):
        src = (self.RUST / "codec_harness.rs").read_text()
        self.assertIn("upstream_encoding::{compress, decompress}", src)
        self.assertNotIn("fn compress", src.replace(
            "upstream_encoding::{compress, decompress}", ""))
        self.assertNotIn("fn decompress", src.replace(
            "upstream_encoding::{compress, decompress}", ""))
        self.assertIn("compress(&coeffs, SLEN)", src)
        cargo = (self.RUST / "Cargo.toml").read_text()
        self.assertIn("8845fe573b2108a1a84eced6c438a4aeb6b3773c", cargo)
        self.assertIn(self.UPSTREAM_SHA256, cargo)

    def test_upstream_binary_agrees_when_built(self):
        binary = ROOT / "pqcheck" / "adapters" / "pqcheck_codec_harness"
        if not binary.exists():
            self.skipTest("upstream harness binary not built "
                          "(needs cargo; see adapters/rust/README.md)")
        try:
            proc = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, text=True)
        except OSError as exc:  # e.g. an ELF built under WSL, seen from Windows
            self.skipTest(f"harness binary not executable on this platform: {exc}")
        try:
            def call(line):
                proc.stdin.write(line + "\n")
                proc.stdin.flush()
                return proc.stdout.readline().strip()

            self.assertTrue(call("info").startswith("OK kind=codec"))
            vectors = json.loads(
                (ROOT / "pqcheck" / "testing" / "falcon_vectors.json").read_text())
            for entry in vectors["noble_signatures"]:
                reply = call("decode " + entry["compressed_hex"])
                self.assertTrue(reply.startswith("OK "), reply[:80])
                import struct as _struct
                got = _struct.unpack("<512h", bytes.fromhex(reply[3:])[:1024])
                self.assertEqual(list(got), entry["coeffs"])
        finally:
            proc.stdin.close()
            proc.wait(timeout=10)


class FalconCrossVectorTests(unittest.TestCase):
    """Cross-implementation encoding vectors: Noble signature
    encodings, hand-computed spec vectors, negative vectors."""

    def test_vectors_against_independent_python_codec(self):
        from pqcheck.testing.falcon_codec import compress, decompress

        vectors = json.loads(
            (ROOT / "pqcheck" / "testing" / "falcon_vectors.json").read_text())
        self.assertGreaterEqual(len(vectors["noble_signatures"]), 3)
        for entry in vectors["noble_signatures"]:
            comp = bytes.fromhex(entry["compressed_hex"])
            coeffs = decompress(comp, 512)
            self.assertEqual(coeffs, tuple(entry["coeffs"]))
            self.assertEqual(compress(coeffs, len(comp)), comp,
                             "independent codec re-encode != Noble bytes")
        for vec in vectors["hand_vectors"]:
            got = compress(vec["coeffs"], vec["byte_length"])
            self.assertIsNotNone(got)
            self.assertEqual(got.hex(), vec["hex"])
        for vec in vectors["negative_vectors"]:
            self.assertIsNone(
                decompress(bytes.fromhex(vec["hex"]), vec["n"]), vec["why"])


class BundledAssetsTests(unittest.TestCase):
    """Finding 7: bundled probes/manifests match the checkout files."""

    def test_assets_match_and_exist(self):
        for source_dir, bundled_dir in (
                (ROOT / "probes", ROOT / "pqcheck" / "assets" / "probes"),
                (ROOT / "manifests", ROOT / "pqcheck" / "assets" / "manifests")):
            self.assertTrue(bundled_dir.is_dir(), bundled_dir)
            for source in source_dir.iterdir():
                if source.is_file():
                    bundled = bundled_dir / source.name
                    self.assertTrue(bundled.is_file(), bundled)
                    self.assertEqual(bundled.read_bytes(), source.read_bytes(),
                                     f"bundled copy drifted: {bundled}")


class PqcleanHarnessTests(unittest.TestCase):
    """Finding 8: comment cannot close early; pointer types exact."""

    def test_comment_and_wrappers(self):
        text = (ROOT / "pqcheck" / "adapters" / "pqclean_mlkem_harness.c").read_text()
        self.assertNotIn("ml-kem-*/", text)
        for alg in ("512", "768", "1024"):
            self.assertIn(f"wrap_PQCLEAN_MLKEM{alg}_CLEAN_enc", text)
            self.assertIn(f"wrap_PQCLEAN_MLKEM{alg}_CLEAN_dec", text)


if __name__ == "__main__":
    unittest.main()
