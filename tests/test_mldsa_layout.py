import unittest

from pqcheck.relations.mldsa_encoding import _parse_hints


class FakeFipsTarget:
    hint_layout = "fips204"
    mldsa_hint = {"ctilde": 48, "z": 3200, "omega": 55, "k": 6, "sig_len": 3309}


class FakeToyTarget:
    hint_layout = "toy"
    mldsa_hint = {"ctilde": 32, "z": 64, "omega": 8, "k": 4}


def fips_sig():
    sig = bytearray(3309)
    hint_start = 3309 - (55 + 6)
    # rows: cumulative offsets 2,3,3,5,5,6 -> indices area starts at hint_start
    indices = [10, 20, 30, 40, 50, 60]
    for i, v in enumerate(indices):
        sig[hint_start + i] = v
    for i, off in enumerate([2, 3, 3, 5, 5, 6]):
        sig[hint_start + 55 + i] = off
    return bytes(sig)


class HintLayoutTests(unittest.TestCase):
    def test_fips204_parse(self):
        parsed = _parse_hints(FakeFipsTarget(), fips_sig())
        self.assertIsNotNone(parsed)
        rows, tail = parsed
        self.assertEqual(rows[0][1], [10, 20])
        self.assertEqual(rows[3][1], [40, 50])
        self.assertEqual(len(tail), 55 - 6)

    def test_toy_parse(self):
        sig = bytearray(132)
        main = 96
        for r in range(4):
            sig[main + r * 8] = 1
            sig[main + r * 8 + 1] = 3
            sig[main + 32 + r] = 2 * (r + 1)
        parsed = _parse_hints(FakeToyTarget(), bytes(sig))
        self.assertIsNotNone(parsed)
        rows, tail = parsed
        self.assertEqual(rows[0][1], [1, 3])
        self.assertEqual(len(tail), 6)


if __name__ == "__main__":
    unittest.main()
