"""Falcon-shaped toy signature: sign-magnitude unary codec inside sign/verify."""
from __future__ import annotations

from pqcheck.target import Capability, Outcome, Status
from pqcheck.testing.toy import _h
from pqcheck.testing.toycodec import decode_coeffs, encode_coeffs, pack_int16

SALT = 0


class ToyFalconSig:
    name = "ToyFalconSig"
    oracle = None
    size_semantics = "exact"
    codec_kind = "sign_magnitude_unary"
    ncoef = 8

    def __init__(self, mutant=None, salt=SALT):
        self.mutant = mutant
        self.salt = salt
        self.caps = frozenset({
            Capability.SIG, Capability.PINNED_RANDOMNESS, Capability.DETACHED_SIG,
            Capability.CTX_STRING, Capability.RAW_DECODE,
        })
        self.sizes = {"pk": 32, "sk": 32}
        self.measured_sizes = ["pk", "sk"]
        self.fixed_sig_len = False
        self.sig_len_basis = "variable-length Falcon-shaped stream; not fixed"
        self._guard = None

    def alive(self):
        return True

    def guard(self, fill):
        self._guard = fill
        return Outcome(Status.OK, value=b"")

    def keygen(self, seed=None):
        if seed is None:
            seed = b"toy-falcon-default-seed"
        seed = bytes(seed)
        sk = _h(b"sk", seed)
        return Outcome(Status.OK, value=(_h(b"pk", sk), sk))

    def _coeffs(self, pk, msg, ctx=b"", prehash=False):
        raw = _h(b"falcon-coeffs", bytes([self.salt & 0xFF]), pk, bytes(msg), bytes(ctx), b"P" if prehash else b"H", out=8)
        coeffs = []
        for b in raw:
            coeffs.append((b % 7) - 3)
        return coeffs

    def sign(self, sk, msg, ctx=b"", prehash=False, **kw):
        pk = _h(b"pk", bytes(sk))
        return Outcome(Status.OK, value=encode_coeffs(self._coeffs(pk, msg, ctx, prehash)))

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, **kw):
        try:
            coeffs = decode_coeffs(
                bytes(sig),
                accept_minus_zero=self.mutant == "accepts_minus_zero",
                accept_pad=self.mutant == "pad_accepts",
            )
        except ValueError as exc:
            return Outcome(Status.REJECTED, detail=str(exc))
        expected = tuple(self._coeffs(bytes(pk), msg, ctx, prehash))
        return Outcome(Status.OK, value=None) if coeffs == expected else Outcome(Status.REJECTED, detail="mismatch")

    # RAW_DECODE surface
    def encode(self, coeffs):
        return Outcome(Status.OK, value=encode_coeffs([int(c) for c in coeffs]))

    def decode(self, data):
        try:
            coeffs = decode_coeffs(
                bytes(data),
                accept_minus_zero=self.mutant == "accepts_minus_zero",
                accept_pad=self.mutant == "pad_accepts",
            )
        except ValueError as exc:
            return Outcome(Status.REJECTED, detail=str(exc))
        return Outcome(Status.OK, value=pack_int16(coeffs))


def _f(m):
    return lambda: ToyFalconSig(mutant=m)


FALCON_MUTANTS = {
    "accepts_minus_zero": _f("accepts_minus_zero"),
}
