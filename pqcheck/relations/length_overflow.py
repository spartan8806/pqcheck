"""Declared-length integer-wrap probe (CVE-2022-37454 class)."""
from __future__ import annotations

from pqcheck.relations._common import SigRelation, ok, pair
from pqcheck.relations.base import Finding, NotApplicable, register
from pqcheck.target import Capability


@register
class DeclaredLengthOverflow(SigRelation):
    id = "core-declared-length-overflow"
    property = "sign/verify reject declared lengths that wrap 16/32/64-bit byte or bit length arithmetic"
    ceiling = "does not establish overflow handling on untested entry points"
    requires = frozenset({Capability.SIG, Capability.DECLARED_LENGTH})
    probes_lie_about_length = True

    def control(self, target):
        kg = pair(target.keygen(b"pqcheck-overflow-control"))
        if kg is None:
            return False, "keygen failed"
        pk, sk = kg
        msg = b"declared length control message"
        try:
            s = target.sign(sk, msg, declared_len=len(msg))
            if not ok(s):
                return False, "sign with an exact declared length failed (parameter may be inert)"
            if not ok(target.verify(pk, msg, s.value, declared_len=len(msg))):
                return False, "verify with an exact declared length failed (parameter may be inert)"
        except TypeError:
            raise NotApplicable("target has no declared_len parameter")
        return True, "declared_len parameter is live"

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "declared length overflow")
        pk, sk = kg
        msg = rng.randbytes(32)
        m = len(msg)
        s = target.sign(sk, msg)
        if not ok(s):
            return Finding(None, "signing failed", 0, "declared length overflow")
        sig = s.value
        units = 0
        accepted = []
        for k in (16, 32, 64):
            for declared in (m + (1 << k), m + (1 << (k - 3)), (1 << k) - 1):
                try:
                    out = target.sign(sk, msg, declared_len=declared)
                except TypeError as exc:
                    raise NotApplicable("sign has no declared_len parameter") from exc
                units += 1
                if ok(out):
                    accepted.append(("sign", declared))
                try:
                    v = target.verify(pk, msg, sig, declared_len=declared)
                except TypeError as exc:
                    raise NotApplicable("verify has no declared_len parameter") from exc
                units += 1
                if ok(v):
                    accepted.append(("verify", declared))
        if accepted:
            return Finding(False, f"declared lengths that wrap length arithmetic were accepted: {accepted[:4]}", units, "declared-length wrap probes at 16/32/64-bit boundaries", reproduce="re-run pqcheck core-declared-length-overflow with the pinned seed")
        return Finding(True, "all wrapping declared lengths rejected on sign and verify", units, "declared-length wrap probes at 16/32/64-bit boundaries")
