import unittest

from pqcheck.testing.fixtures import NOBLE_061
from pqcheck.testing.precision import CASES, RandomizedRejectKem, run_precision


class PrecisionTests(unittest.TestCase):
    def test_eight_cases(self):
        self.assertEqual(len(CASES), 8)
        labels = [c.label for c in CASES]
        self.assertIn("explicit-reject-kem", labels)
        self.assertIn("variable-length-sig", labels)

    def test_randomized_reject_is_not_a_case(self):
        self.assertNotIn("randomized-reject-kem", [c.label for c in CASES])
        self.assertEqual(RandomizedRejectKem.name, "randomized-reject-kem")

    def test_precision_suite(self):
        self.assertEqual(run_precision(), [])


class NobleFixtureConfigTests(unittest.TestCase):
    def test_pinned_config(self):
        self.assertEqual(NOBLE_061["version"], "0.6.1")
        self.assertEqual(len(NOBLE_061["algorithms"]), 10)
        self.assertEqual(
            NOBLE_061["expected_defects"],
            {("sig-verify-length-exact", "falcon512padded"), ("sig-verify-length-exact", "falcon1024padded")},
        )
        self.assertEqual(NOBLE_061["expected_reach"]["ml-kem-768"]["kem-fo-liveness"], 3264)


if __name__ == "__main__":
    unittest.main()
