import unittest

from pqcheck.verdict import Claim, ClaimError, Coverage, Method, Report, Subject, Verdict

S = Subject(target="t", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")
M = Method(name="m", oracle=None)


class VerdictTests(unittest.TestCase):
    def test_moving_ref_refused(self):
        with self.assertRaises(ClaimError):
            Subject(target="t", commit="main")

    def test_plain_string_verdict_refused(self):
        with self.assertRaises(ClaimError):
            Claim(subject=S, property="p", verdict="NO_DEFECT_FOUND", method=M, ceiling="c", coverage=Coverage("x", 1))

    def test_clean_requires_coverage(self):
        with self.assertRaises(ClaimError):
            Claim(subject=S, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=M, ceiling="c")

    def test_exit_codes_and_score(self):
        clean = Claim(subject=S, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=M, ceiling="c", coverage=Coverage("x", 1))
        self.assertEqual(Report((clean,)).exit_code(), 0)
        self.assertEqual(Report(()).exit_code(), 2)
        with self.assertRaises(NotImplementedError):
            Report((clean,)).score()


if __name__ == "__main__":
    unittest.main()
