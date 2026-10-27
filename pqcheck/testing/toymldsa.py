"""ML-DSA-shaped toy signature with a detached hint block."""
from __future__ import annotations

from pqcheck.target import Capability, Outcome, Status
from pqcheck.testing.toy import _h
from pqcheck.testing.toycodec import ToyCodec, decode_hints, encode_hints

OMEGA = 8
KROWS = 4
MAIN = 96
SIG_LEN = MAIN + KROWS * OMEGA + KROWS


class ToyMldsaSig:
    name = "ToyMldsaSig"
    oracle = None
    size_semantics = "exact"
    hint_layout = "toy"

    def __init__(self, mutant=None):
        self.mutant = mutant
        self.caps = frozenset({
            Capability.SIG, Capability.PINNED_RANDOMNESS, Capability.DETACHED_SIG,
            Capability.CTX_STRING, Capability.EXPLICIT_SIG_LENGTH,
            Capability.MLDSA_HINT_ENCODING, Capability.RAW_DECODE,
        })
        self.sizes = {"pk": 32, "sk": 32, "sig": SIG_LEN}
        self.measured_sizes = ["pk", "sk", "sig"]
        self.fixed_sig_len = True
        self.sig_len_basis = "toy fixed ML-DSA-shaped signature"
        self.mldsa_hint = {"ctilde": 32, "z": 64, "omega": OMEGA, "k": KROWS, "main": MAIN, "sig_len": SIG_LEN}
        self._codec = ToyCodec(mutant={
            "accept_non_strict_hints": "hint_order_lax",
            "ignore_nonzero_hint_tail": "hint_tail_lax",
        }.get(mutant))
        self._guard = None

    def alive(self):
        return True

    def guard(self, fill):
        self._guard = fill
        return Outcome(Status.OK, value=b"")

    def keygen(self, seed=None):
        if seed is None:
            seed = b"toy-mldsa-default-seed"
        seed = bytes(seed)
        sk = _h(b"sk", seed)
        return Outcome(Status.OK, value=(_h(b"pk", sk), sk))

    def _main(self, pk, msg, ctx, prehash):
        return _h(b"mldsa-main", pk, bytes(msg), bytes(ctx), b"P" if prehash else b"H", out=MAIN)

    def _rows(self):
        return [[1, 3] for _ in range(KROWS)]

    def sign(self, sk, msg, ctx=b"", prehash=False, **kw):
        pk = _h(b"pk", bytes(sk))
        sig = self._main(pk, msg, ctx, prehash) + encode_hints(self._rows())
        return Outcome(Status.OK, value=sig)

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, **kw):
        sig = bytes(sig)
        if len(sig) != SIG_LEN:
            return Outcome(Status.REJECTED, detail="bad sig length")
        main, hint = sig[:MAIN], sig[MAIN:]
        try:
            rows = decode_hints(
                hint,
                accept_order=self.mutant == "accept_non_strict_hints",
                accept_tail=self.mutant == "ignore_nonzero_hint_tail",
            )
        except ValueError as exc:
            return Outcome(Status.REJECTED, detail=str(exc))
        if self.mutant not in ("accept_non_strict_hints", "ignore_nonzero_hint_tail") and rows != self._rows():
            return Outcome(Status.REJECTED, detail="hint rows do not match the expected hints")
        if main != self._main(bytes(pk), msg, ctx, prehash):
            return Outcome(Status.REJECTED, detail="mismatch")
        return Outcome(Status.OK, value=None)

    # RAW_DECODE surface (coefficients and hints)
    def encode(self, coeffs):
        return self._codec.encode(coeffs)

    def decode(self, data):
        return self._codec.decode(data)

    def encode_hints(self, rows):
        return Outcome(Status.OK, value=encode_hints(rows))

    def decode_hints(self, data):
        return self._codec.decode_hints(data)


def _f(m):
    return lambda: ToyMldsaSig(mutant=m)


MLDSA_MUTANTS = {
    "accept_non_strict_hints": _f("accept_non_strict_hints"),
    "ignore_nonzero_hint_tail": _f("ignore_nonzero_hint_tail"),
}
