"""Generic signature soundness relations."""
from __future__ import annotations

import inspect

from pqcheck.relations._common import SigRelation, flip, ok, pair, rej, sig_baseline
from pqcheck.relations.base import Finding, NotApplicable, register
from pqcheck.target import Capability


def _baseline(target, rng, msg=None):
    kg = pair(target.keygen(rng.randbytes(16)))
    if kg is None:
        return None
    pk, sk = kg
    if msg is None:
        msg = rng.randbytes(32)
    s = target.sign(sk, msg)
    if not ok(s) or not ok(target.verify(pk, msg, s.value)):
        return None
    return pk, sk, msg, s.value


@register
class WrongKeyRejection(SigRelation):
    id = "sig-wrong-key-rejection"
    property = "a signature does not verify under an independent public key"
    ceiling = "does not establish unforgeability against chosen-message attacks"

    def check(self, target, rng):
        units = 0
        for _ in range(8):
            base = _baseline(target, rng)
            if base is None:
                return Finding(None, "baseline failed", units, "wrong-key rejection")
            pk, sk, msg, sig = base
            kg2 = pair(target.keygen(rng.randbytes(16) + b"\x02"))
            if kg2 is None or kg2[0] == pk:
                continue
            units += 1
            if ok(target.verify(kg2[0], msg, sig)):
                return Finding(False, "signature verified under a wrong key", units, "wrong-key rejection over 8 messages", reproduce="re-run pqcheck sig-wrong-key-rejection with the pinned seed")
        if units == 0:
            return Finding(None, "no independent key obtained", 0, "wrong-key rejection")
        return Finding(True, "wrong keys rejected over 8 messages", units, "wrong-key rejection over 8 messages")


@register
class MessageBinding(SigRelation):
    id = "sig-message-binding"
    property = "a signature binds the exact message bytes and length"
    ceiling = "does not establish binding of context or mode unless separately checked"

    def check(self, target, rng):
        units = 0
        for n in (1, 8, 9, 16, 33, 64, 137, 300):
            base = _baseline(target, rng, rng.randbytes(n))
            if base is None:
                return Finding(None, "baseline failed", units, "message binding")
            pk, sk, msg, sig = base
            edits = [rng.randbytes(n), flip(msg, len(msg) - 1, 1), flip(msg, 0, 1), msg[:-1], b"", msg + b"\x00"]
            for e in edits:
                if e == msg:
                    continue
                units += 1
                if ok(target.verify(pk, e, sig)):
                    return Finding(False, f"signature accepted a different message (length {len(e)} vs {len(msg)})", units, "message binding edits", reproduce="re-run pqcheck sig-message-binding with the pinned seed")
        return Finding(True, "message edits rejected across 8 lengths", units, "message binding edits")


@register
class DegenerateValues(SigRelation):
    id = "sig-degenerate-values"
    property = "all-zero and all-ones signatures (and zero key/signature pair) are rejected"
    ceiling = "does not cover all degenerate algebraic values for every scheme"

    def check(self, target, rng):
        base = _baseline(target, rng)
        if base is None:
            return Finding(None, "baseline failed", 0, "degenerate values")
        pk, sk, msg, sig = base
        sizes = getattr(target, "sizes", {}) or {}
        n = sizes.get("sig") or len(sig)
        probes = [(pk, b"\x00" * n), (pk, b"\xff" * n), (b"\x00" * len(pk), b"\x00" * n)]
        units = 0
        for key, s in probes:
            units += 1
            if ok(target.verify(key, msg, s)):
                return Finding(False, "a degenerate signature/key value verified (Psychic-Signatures class)", units, "degenerate value probes", reproduce="re-run pqcheck sig-degenerate-values with the pinned seed")
        return Finding(True, "degenerate values rejected", units, "degenerate value probes")


@register
class CtxBinding(SigRelation):
    id = "sig-ctx-binding"
    property = "the FIPS 204 context string is length-framed and bound into the signature"
    ceiling = "does not establish domain separation for prehash modes"
    requires = frozenset({Capability.SIG, Capability.CTX_STRING})

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "ctx binding")
        pk, sk = kg
        msg = b"ctx binding message"
        try:
            s = target.sign(sk, msg, ctx=b"a")
            if not ok(s) or not ok(target.verify(pk, msg, s.value, ctx=b"a")):
                return Finding(None, "ctx baseline failed", 0, "ctx binding")
        except TypeError as exc:
            raise NotApplicable("target cannot express a context string") from exc
        units = 0
        for ctx in (b"", b"b", b"ab", b"a\x00"):
            units += 1
            if ok(target.verify(pk, msg, s.value, ctx=ctx)):
                return Finding(False, f"signature accepted under a different context {ctx!r}", units, "context variation probes", reproduce="re-run pqcheck sig-ctx-binding with the pinned seed")
        for (c1, m1), (c2, m2) in [((b"a", b"bc"), (b"ab", b"c")), ((b"", b"ab"), (b"a", b"b"))]:
            s1 = target.sign(sk, m1, ctx=c1)
            units += 1
            if ok(s1) and ok(target.verify(pk, m2, s1.value, ctx=c2)):
                return Finding(False, "ctx||msg length ambiguity: split pair cross-verifies", units, "ctx/msg length-ambiguity pairs", reproduce="re-run pqcheck sig-ctx-binding with the pinned seed")
        return Finding(True, "context variations and ambiguity splits rejected", units, "context variation and length-ambiguity probes")


@register
class ModeDomainSeparation(SigRelation):
    id = "sig-mode-domain-separation"
    property = "prehash and direct modes are domain-separated in both directions"
    ceiling = "does not establish correctness of the prehash function itself"

    def check(self, target, rng):
        if getattr(target, "supports_prehash", True) is False:
            raise NotApplicable("target declares that it cannot express a prehash mode")
        try:
            params = inspect.signature(target.sign).parameters
        except (TypeError, ValueError) as exc:
            raise NotApplicable("cannot inspect sign signature") from exc
        if "prehash" not in params:
            raise NotApplicable("sign has no prehash mode parameter")
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "mode separation")
        pk, sk = kg
        msg = b"mode separation message"
        units = 0
        sigs = {}
        for mode in (False, True):
            s = target.sign(sk, msg, prehash=mode)
            if not ok(s):
                return Finding(None, f"prehash={mode} signing unusable", units, "mode separation")
            sigs[mode] = s.value
            units += 1
            if not ok(target.verify(pk, msg, s.value, prehash=mode)):
                return Finding(None, f"prehash={mode} baseline failed", units, "mode separation")
        for a, b in ((False, True), (True, False)):
            units += 1
            if ok(target.verify(pk, msg, sigs[a], prehash=b)):
                return Finding(False, f"signature made with prehash={a} verified with prehash={b}", units, "cross-mode verification", reproduce="re-run pqcheck sig-mode-domain-separation with the pinned seed")
        return Finding(True, "both modes usable and cross-mode verification rejected", units, "cross-mode verification")


@register
class VerifyLengthExact(SigRelation):
    id = "sig-verify-length-exact"
    property = "verify rejects signatures of any length other than the fixed signature length"
    ceiling = "does not apply to variable-length signature schemes"
    requires = frozenset({Capability.SIG, Capability.EXPLICIT_SIG_LENGTH, Capability.DETACHED_SIG})
    premise_attrs = ("fixed_sig_len", "sig_len_basis")

    def check(self, target, rng):
        if getattr(target, "fixed_sig_len", None) is not True:
            raise NotApplicable("target does not declare a fixed signature length")
        base = _baseline(target, rng)
        if base is None:
            return Finding(None, "baseline failed", 0, "verify length")
        pk, sk, msg, sig = base
        probes = [sig + b"\x00", sig + b"\xff", sig + b"\x00" * 50, sig[:-1]]
        units = 0
        accepted = []
        for p in probes:
            units += 1
            if ok(target.verify(pk, msg, p)):
                accepted.append(len(p))
        if accepted:
            return Finding(False, f"verify accepted signature lengths {accepted} (expected exactly {len(sig)})", units, "verify exact-length probes", reproduce="re-run pqcheck sig-verify-length-exact with the pinned seed")
        return Finding(True, "all off-length signatures rejected", units, "verify exact-length probes")
