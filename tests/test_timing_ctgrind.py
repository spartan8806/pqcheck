import io
import unittest
from contextlib import redirect_stdout

from pqcheck.adapters import leakzoo_stat
from pqcheck.adapters.ctgrind_triage import WARNING, report_frames, triage
from pqcheck.adapters.timing_probe import analyse, crop, scan_t, welch_t

LOG = """==1== Conditional jump or move depends on uninitialised value(s)
==1==    at 0x1234: secret_leak_fn (kem.c:10)
==1==    by 0x5678: PQCLEAN_crypto_kem_dec (kem.c:20)

==1== Use of uninitialised value of size 8
==1==    at 0x9ABC: public_parse (kem.c:30)
"""


class TimingTests(unittest.TestCase):
    def test_welch_identical_is_zero(self):
        self.assertEqual(welch_t([5.0] * 20, [5.0] * 20), 0.0)

    def test_scan_detects_separation(self):
        a = [100.0 + (i % 3) for i in range(200)]
        b = [200.0 + (i % 3) for i in range(200)]
        t, _at = scan_t(a, b)
        self.assertGreater(t, 4.5)

    def test_crop(self):
        self.assertEqual(len(crop(list(range(100)), 0.0, 0.5)), 50)

    def test_analyse_verdict_language(self):
        same = ([100.0 + (i % 5) for i in range(200)], [100.0 + (i % 5) for i in range(200)])
        result = analyse({"honest vs random": same, "honest vs all-zero": same, "random vs random": same})
        self.assertIn("BOUND ON THIS INSTRUMENT", result["verdict"])
        self.assertIn("not a certificate", result["verdict"])


class LeakzooTests(unittest.TestCase):
    def test_fires_and_silent(self):
        inp = io.StringIO("CLASS demo 1,2,3,4,5 100,101,102,103,104\n")
        out = io.StringIO()
        old = leakzoo_stat.sys.stdin
        try:
            leakzoo_stat.sys.stdin = inp
            with redirect_stdout(out):
                self.assertEqual(leakzoo_stat.main(), 0)
        finally:
            leakzoo_stat.sys.stdin = old
        self.assertIn("FIRES", out.getvalue())


class CtgrindTests(unittest.TestCase):
    def test_report_frames(self):
        reports = report_frames(LOG)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0][0], "secret_leak_fn")

    def test_triage_unexplained_warns(self):
        results = triage(LOG, "ML-KEM-768")
        self.assertTrue(all(label == "UNEXPLAINED" for label, _ in results))
        self.assertIn("not findings", WARNING)


if __name__ == "__main__":
    unittest.main()
