"""LWE-flavoured and packed-ML-KEM-shaped toy KEMs."""
from __future__ import annotations

import hashlib

from pqcheck.target import Capability, Outcome, Status
from pqcheck.testing.toy import ToyKem, _h, _ok, _rej

Q = 3329
NCOEF = 64
KPOLY = 2
# Mutants that skip the ek modulus check (canonicalise silently instead
# of rejecting coefficients >= q). "modulus_lax" is the historical name.
_NO_EK_MODULUS_CHECK = ("modulus_lax", "no_ek_modulus_check")


def _bitpack12(coeffs) -> bytes:
    """FIPS 203 ByteEncode_12 via a big-integer accumulator.

    Deliberately independent of pqcheck.relations.kem_encoding._pack12
    (byte-pair arithmetic there, integer shifts here) so the relation's
    probe_control cross-checks two genuinely different implementations.
    """
    acc = 0
    for i, c in enumerate(coeffs):
        acc |= (c & 0xFFF) << (12 * i)
    return acc.to_bytes(len(coeffs) * 12 // 8, "little")


def _bitunpack12(b: bytes):
    """FIPS 203 ByteDecode_12 via a big-integer accumulator."""
    acc = int.from_bytes(b, "little")
    return [(acc >> (12 * i)) & 0xFFF for i in range(len(b) * 8 // 12)]


# Short aliases kept for existing callers; same independent implementation.
pack12 = _bitpack12


def unpack12(data: bytes, count=NCOEF * KPOLY) -> list[int]:
    return _bitunpack12(data)[:count]


class ToyLweKem(ToyKem):
    name = "ToyLweKem"

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self.ct_len = 48
        self.sizes = dict(self.sizes, ct=48)
        self.measured_sizes = ["ek", "dk", "ct", "ss"]


class PackedEkKem:
    """ML-KEM-shaped toy: ek is 12-bit packed coefficients mod 3329.

    dk = seed32 || ek || H(ek)32 || z32
    """

    name = "PackedEkKem"
    oracle = None
    size_semantics = "exact"
    q = Q
    ncoef = NCOEF
    kpoly = KPOLY
    ek_packing = {"coeff_bits": 12, "q": Q, "n": NCOEF, "k": KPOLY}

    def __init__(self, mutant=None):
        self.mutant = mutant
        self.caps = frozenset({
            Capability.KEM, Capability.PINNED_RANDOMNESS,
            Capability.EXPLICIT_SIG_LENGTH, Capability.GUARD_FILL,
        })
        ek_len = len(pack12([0] * (NCOEF * KPOLY)))
        self.sizes = {"ek": ek_len, "dk": 32 + ek_len + 64, "ct": 32, "ss": 32}
        self.measured_sizes = ["ek", "dk", "ct", "ss"]
        self.fixed_sig_len = None
        self._ctr = 0
        self._guard = None
        self._last = None

    def alive(self):
        return True

    def guard(self, fill):
        self._guard = fill
        return _ok(b"")

    def _coeffs(self, seed):
        raw = hashlib.shake_256(b"packed-ek" + bytes(seed)).digest(NCOEF * KPOLY * 2)
        return [int.from_bytes(raw[i * 2:i * 2 + 2], "big") % Q for i in range(NCOEF * KPOLY)]

    def keygen(self, seed=None):
        if seed is None:
            seed = b"packed-ek-default-seed"
        seed = bytes(seed)
        ek = pack12(self._coeffs(seed))
        dk = seed.ljust(32, b"\x00")[:32] + ek + hashlib.sha3_256(ek).digest() + _h(b"z", seed)
        return _ok((ek, dk))

    def encaps(self, ek, m=None):
        ek = bytes(ek)
        if len(ek) != self.sizes["ek"]:
            return _rej("bad ek length")
        coeffs = unpack12(ek)
        if any(c >= Q for c in coeffs) and self.mutant not in _NO_EK_MODULUS_CHECK:
            return _rej("non-canonical ek coefficient >= q")
        if self.mutant in _NO_EK_MODULUS_CHECK:
            # canonicalises silently: the bumped ek becomes the same key
            ek = pack12([c % Q for c in coeffs])
        if m is not None:
            ct = bytes(m).ljust(32, b"\x00")[:32]
        else:
            self._ctr += 1
            ct = _h(b"ct", ek, self._ctr.to_bytes(8, "big"))
        ss = _h(b"ss", ek, ct)
        self._last = (ct, ss)
        return _ok((ss, ct))

    def decaps(self, dk, ct):
        dk, ct = bytes(dk), bytes(ct)
        if len(dk) != self.sizes["dk"] or len(ct) != 32:
            return _rej("bad dk/ct length")
        ek_len = self.sizes["ek"]
        ek = dk[32:32 + ek_len]
        hh = dk[32 + ek_len:64 + ek_len]
        z = dk[64 + ek_len:96 + ek_len]
        if hh != hashlib.sha3_256(ek).digest() and self.mutant != "no_dk_hash_check":
            return _ok(_h(b"rej", z, ct))
        return _ok(_h(b"ss", ek, ct))


def _f(cls, m):
    return lambda: cls(mutant=m)


LWE_MUTANTS = {
    "no_reencryption_check": _f(ToyLweKem, "no_reencryption_check"),
    "reject_ignores_z": _f(ToyLweKem, "reject_ignores_z"),
    "reject_ignores_ct": _f(ToyLweKem, "reject_ignores_ct"),
}
PACKED_EK_MUTANTS = {
    "no_ek_modulus_check": _f(PackedEkKem, "no_ek_modulus_check"),
    "no_dk_hash_check": _f(PackedEkKem, "no_dk_hash_check"),
}
