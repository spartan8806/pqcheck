"""Adversarial precision boundary suite (Set 2, Phase 7).

Correct implementations that are NOT ML-KEM / ML-DSA shaped. A relation
that fires DEFECT_FOUND on one of these (outside may_fire) is a false
positive. RandomizedRejectKem is a documented broken counterexample and
is intentionally not in CASES.
"""
from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass, field

from pqcheck.target import Capability, Outcome, Status
from pqcheck.testing.toy import ToySig, _h
from pqcheck.testing.toylwe import ToyLweKem
from pqcheck.verdict import Subject, Verdict

COMMIT = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
FO_FORBIDDEN = (
    "exclude the one benign explanation",
    "Which bits leak DIFFERS between bytes",
    "check is ABSENT",
    "cannot span that many bytes",
)


def _rej(detail):
    return Outcome(Status.REJECTED, detail=detail)


class ExplicitRejectKem(ToyLweKem):
    """FO check intact, but failure is an explicit rejection, not an ss."""

    name = "explicit-reject-kem"

    def decaps(self, dk, ct):
        if self._last is None or bytes(ct) != self._last[0]:
            return _rej("ciphertext failed re-encryption check")
        return super().decaps(dk, ct)


class WideByteSlackCtKem(ToyLweKem):
    """6 reserved trailing bytes the decoder ignores (real malleability)."""

    name = "wide-byte-slack-ct-kem"
    SLACK = 6

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self._body = self.ct_len
        self.ct_len = self.ct_len + self.SLACK
        self.sizes = dict(self.sizes, ct=self.ct_len)

    def _body_len(self):
        return self._body

    def _wrap_ct(self, body):
        return bytes(body) + b"\x00" * self.SLACK

    def _canonical(self, ct):
        return bytes(ct[:-self.SLACK]) if len(ct) >= self.SLACK else bytes(ct)


class RandomizedRejectKem(ToyLweKem):
    """Broken counterexample (not in CASES): randomised rejection secret.

    Two decapsulations of one invalid ciphertext differ, which is a
    trivial validity oracle; kem-reject-determinism firing here is a
    true positive.
    """

    name = "randomized-reject-kem"

    def decaps(self, dk, ct):
        if self._last is not None and bytes(ct) == self._last[0]:
            return super().decaps(dk, ct)
        dk = bytes(dk)
        if len(dk) != 96:
            return _rej("bad dk length")
        return Outcome(Status.OK, value=_h(b"J", dk[64:], bytes(ct), os.urandom(16)))


class InterleavedPadCtKem(ToyLweKem):
    """Every odd byte is reserved alignment padding (0.5 bound fraction)."""

    name = "interleaved-pad-ct-kem"

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self._body = self.ct_len
        self.ct_len = self.ct_len * 2
        self.sizes = dict(self.sizes, ct=self.ct_len)

    def _body_len(self):
        return self._body

    def _wrap_ct(self, body):
        out = bytearray()
        for b in bytes(body):
            out.append(b)
            out.append(0)
        return bytes(out)

    def _canonical(self, ct):
        return bytes(ct)[0::2]


class AlignedCoeffCtKem(ToyLweKem):
    """Odd bytes keep only their low nibble; top 4 bits are unused."""

    name = "aligned-coeff-ct-kem"

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self._body = self.ct_len
        self.ct_len = self.ct_len * 2
        self.sizes = dict(self.sizes, ct=self.ct_len)

    def _body_len(self):
        return self._body

    def _wrap_ct(self, body):
        out = bytearray()
        for b in bytes(body):
            out.append(b)
            out.append(b & 0x0F)
        return bytes(out)

    def _canonical(self, ct):
        return bytes((b & 0x0F) if i % 2 else b for i, b in enumerate(bytes(ct)))


class NoPinnedRandomnessKem(ToyLweKem):
    """encaps discards caller-supplied randomness (C KEM API shape)."""

    name = "no-pinned-randomness-kem"

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self.caps = frozenset(c for c in self.caps if c is not Capability.PINNED_RANDOMNESS)

    def encaps(self, ek, m=None):
        return super().encaps(ek, None)


class VariableLengthSig(ToySig):
    """Variable-length signatures with a self-describing zero tail."""

    name = "variable-length-sig"

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self.caps = frozenset(c for c in self.caps if c is not Capability.EXPLICIT_SIG_LENGTH)
        self.fixed_sig_len = False
        self.sig_len_basis = "variable length with self-describing tail"
        self.size_semantics = {"sig": "max"}
        self.measured_sizes = ("pk", "sk", "sig")
        self.sizes = dict(self.sizes, sig=68)

    def sign(self, sk, msg, ctx=b"", prehash=False, declared_len=None):
        out = super().sign(sk, msg, ctx=ctx, prehash=prehash, declared_len=declared_len)
        if not out.ok:
            return out
        n = _h(b"padlen", bytes(msg), bytes(ctx))[0] % 4
        return Outcome(Status.OK, value=out.value + bytes([n]) + bytes(n))

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, declared_len=None):
        sig = bytes(sig)
        if len(sig) == 64:
            core = sig
        elif len(sig) > 64:
            n = sig[64]
            if len(sig) != 65 + n or sig[65:] != bytes(n):
                return _rej("bad variable-length tail")
            core = sig[:64]
        else:
            return _rej("bad sig length")
        return super().verify(pk, msg, core, ctx=ctx, prehash=prehash, declared_len=declared_len)


class NoPreHashSig(ToySig):
    name = "no-prehash-sig"

    def sign(self, sk, msg, ctx=b"", prehash=False, declared_len=None):
        if prehash:
            return _rej("this scheme has no pre-hash mode")
        return super().sign(sk, msg, ctx=ctx, prehash=False, declared_len=declared_len)

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, declared_len=None):
        if prehash:
            return _rej("this scheme has no pre-hash mode")
        return super().verify(pk, msg, sig, ctx=ctx, prehash=False, declared_len=declared_len)


class HedgedSig(ToySig):
    """Hedged signing: fresh randomness per signature, no pinned mode.

    Toy simplification: the hedged nonce is consumed internally and the
    verification equation cancels it, so the emitted signature bytes are
    the same shape as the deterministic toy; what the fixture exercises
    is that relations must not require PINNED_RANDOMNESS or deterministic
    re-signing.
    """

    name = "hedged-sig"

    def __init__(self, mutant=None):
        super().__init__(mutant=mutant)
        self.caps = frozenset(c for c in self.caps if c is not Capability.PINNED_RANDOMNESS)

    def sign(self, sk, msg, ctx=b"", prehash=False, declared_len=None):
        _nonce = os.urandom(32)  # hedged nonce; cancels in verify (toy)
        return super().sign(sk, msg, ctx=ctx, prehash=prehash, declared_len=declared_len)


@dataclass(frozen=True)
class PrecisionCase:
    make: object
    label: str
    why_correct: str
    kind: str = "kem"
    may_fire: dict[str, str] = field(default_factory=dict)
    must_not_say: dict[str, tuple[str, ...]] = field(default_factory=dict)
    must_decline: dict[str, str] = field(default_factory=dict)


_KEM_DECLINE = {
    "kem-reject-determinism": "explicit rejection returns no implicit secret to compare",
    "kem-reject-binds-full-ciphertext": "explicit rejection returns no implicit secret to compare",
    "kem-reject-binds-z-accept-path-does-not": "explicit rejection returns no implicit secret to compare",
    "kem-reject-ct-bit-contribution": "explicit rejection returns no implicit secret to compare",
}
_MALLEABLE = "distinct ciphertext strings decapsulate identically; ciphertext malleability is real"

CASES: tuple[PrecisionCase, ...] = (
    PrecisionCase(ExplicitRejectKem, "explicit-reject-kem", "FO check intact; failure is explicit rejection", must_decline=dict(_KEM_DECLINE)),
    PrecisionCase(WideByteSlackCtKem, "wide-byte-slack-ct-kem", "reserved slack bytes are ignored by design", may_fire={"kem-fo-liveness": _MALLEABLE, "kem-reject-binds-full-ciphertext": _MALLEABLE, "kem-reject-ct-bit-contribution": _MALLEABLE}, must_not_say={"kem-fo-liveness": FO_FORBIDDEN}),
    PrecisionCase(InterleavedPadCtKem, "interleaved-pad-ct-kem", "odd bytes are alignment padding by design", may_fire={"kem-fo-liveness": _MALLEABLE, "kem-reject-binds-full-ciphertext": _MALLEABLE, "kem-reject-ct-bit-contribution": _MALLEABLE}, must_not_say={"kem-fo-liveness": ("Which bits leak DIFFERS between bytes", "check is ABSENT")}),
    PrecisionCase(AlignedCoeffCtKem, "aligned-coeff-ct-kem", "top nibble of odd bytes is unused by design", may_fire={"kem-fo-liveness": _MALLEABLE}, must_not_say={"kem-fo-liveness": ("Which bits leak DIFFERS between bytes", "check is ABSENT", "exclude the one benign explanation")}),
    PrecisionCase(NoPinnedRandomnessKem, "no-pinned-randomness-kem", "C-shaped KEM API without caller randomness"),
    PrecisionCase(VariableLengthSig, "variable-length-sig", "variable-length signature format", kind="sig", must_decline={"sig-verify-length-exact": "variable-length scheme has no fixed signature length"}),
    PrecisionCase(NoPreHashSig, "no-prehash-sig", "scheme has no pre-hash mode", kind="sig", must_decline={"sig-mode-domain-separation": "prehash mode does not exist on this scheme"}),
    PrecisionCase(HedgedSig, "hedged-sig", "hedged (randomised) signing is the FIPS 204 default shape", kind="sig"),
)


def _roundtrip_ok(case: PrecisionCase, target) -> bool:
    if case.kind == "kem":
        kg = target.keygen(b"precision-roundtrip")
        if not kg.ok:
            return False
        ek, dk = kg.value
        enc = target.encaps(ek)
        if not enc.ok:
            return False
        ss, ct = enc.value
        dec = target.decaps(dk, ct)
        return dec.ok and dec.value == ss
    kg = target.keygen(b"precision-roundtrip")
    if not kg.ok:
        return False
    pk, sk = kg.value
    sig = target.sign(sk, b"precision roundtrip")
    return sig.ok and target.verify(pk, b"precision roundtrip", sig.value).ok


def run_precision() -> list[str]:
    from pqcheck.relations.base import REGISTRY
    failures: list[str] = []
    for case in CASES:
        target = case.make()
        if not _roundtrip_ok(case, target):
            failures.append(f"{case.label}: honest round-trip failed; fixture itself is broken")
            continue
        subject = Subject(target=case.label, commit=COMMIT)
        for rid, relation in sorted(REGISTRY.items()):
            claim = relation.run(target, subject, random.Random(f"precision:{case.label}:{rid}"))
            text = f"{claim.evidence} {claim.notes}"
            if claim.verdict is Verdict.DEFECT_FOUND and rid not in case.may_fire:
                failures.append(f"{case.label}: {rid} fired DEFECT_FOUND on a correct target: {claim.evidence}")
            if rid in case.may_fire and claim.verdict is not Verdict.DEFECT_FOUND:
                failures.append(f"{case.label}: {rid} is in may_fire but stopped firing (got {claim.verdict.value}); stale permission")
            for phrase in case.must_not_say.get(rid, ()):
                if phrase in text:
                    failures.append(f"{case.label}: {rid} evidence contains forbidden phrase {phrase!r}")
            if rid in case.must_decline and claim.verdict not in (Verdict.NOT_REACHED, Verdict.NOT_ANSWERABLE):
                failures.append(f"{case.label}: {rid} must decline but returned {claim.verdict.value}")
    return failures


def main() -> int:
    failures = run_precision()
    if failures:
        print(f"precision boundary suite FAILED ({len(failures)}):")
        for failure in failures:
            print(" -", failure)
        return 1
    print(f"precision boundary suite: ok ({len(CASES)} cases, 0 false positives outside may_fire)")
    return 0


if __name__ == "__main__":
    sys.exit(main())


# --- earlier Set 1 precision fixtures (kept for selftest) -------------------
from pqcheck.testing.toy import ToyKem as _ToyKem  # noqa: E402
from pqcheck.testing.toycodec import ToyCodec as _ToyCodec  # noqa: E402
from pqcheck.testing.toymldsa import ToyMldsaSig as _ToyMldsaSig  # noqa: E402


class VariableLenSig(ToySig):
    name = "VariableLenSig"

    def __init__(self):
        super().__init__()
        self.caps = frozenset({Capability.SIG, Capability.PINNED_RANDOMNESS, Capability.DETACHED_SIG})
        self.fixed_sig_len = False
        self.sig_len_basis = "variable in the general shape; toy still emits 64 bytes"


class NoCtxSig(ToySig):
    name = "NoCtxSig"

    def __init__(self):
        super().__init__()
        self.caps = frozenset({Capability.SIG, Capability.PINNED_RANDOMNESS, Capability.DETACHED_SIG, Capability.EXPLICIT_SIG_LENGTH})


class KemNoExplicit(_ToyKem):
    name = "KemNoExplicit"

    def __init__(self):
        super().__init__()
        self.caps = frozenset({Capability.KEM, Capability.PINNED_RANDOMNESS, Capability.GUARD_FILL})


class SigNoGuard(ToySig):
    name = "SigNoGuard"

    def __init__(self):
        super().__init__()
        self.caps = frozenset(c for c in self.caps if c is not Capability.GUARD_FILL)


class CodecVariable(_ToyCodec):
    name = "CodecVariable"

    def __init__(self):
        super().__init__()
        self.fixed_sig_len = False
        self.sig_len_basis = "variable codec shape"


class SmallSig(ToySig):
    name = "SmallSig"


class KemLargeCt(_ToyKem):
    name = "KemLargeCt"

    def __init__(self):
        super().__init__()
        self.ct_len = 64
        self.sizes = dict(self.sizes, ct=64)


class MldsaNoHintCap(_ToyMldsaSig):
    name = "MldsaNoHintCap"

    def __init__(self):
        super().__init__()
        self.caps = frozenset(c for c in self.caps if c is not Capability.MLDSA_HINT_ENCODING)


PRECISION_TARGETS = [
    ("variable-len-sig", VariableLenSig),
    ("no-ctx-sig", NoCtxSig),
    ("kem-no-explicit-length", KemNoExplicit),
    ("sig-no-guard-fill", SigNoGuard),
    ("codec-variable", CodecVariable),
    ("small-sig", SmallSig),
    ("kem-large-ct", KemLargeCt),
    ("mldsa-no-hint-cap", MldsaNoHintCap),
]
