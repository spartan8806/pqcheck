"""Shared helpers for relations."""
from __future__ import annotations

import hashlib

from pqcheck.relations.base import Finding, NotApplicable, Relation
from pqcheck.target import Capability, Status

SEED = b"pqcheck-control-seed-v1"


def ok(out) -> bool:
    return getattr(out, "status", None) is Status.OK


def rej(out) -> bool:
    return getattr(out, "status", None) is Status.REJECTED


def val(out):
    return out.value if ok(out) else None


def pair(out):
    v = val(out)
    if isinstance(v, tuple) and len(v) == 2:
        return v
    return None


def kem_baseline(target):
    kg = pair(target.keygen(SEED))
    if kg is None:
        return None
    ek, dk = kg
    enc = pair(target.encaps(ek))
    if enc is None:
        return None
    ss, ct = enc
    dec = target.decaps(dk, ct)
    if not ok(dec) or dec.value != ss:
        return None
    return ek, dk, ss, ct


def sig_baseline(target, msg=b"pqcheck baseline message"):
    kg = pair(target.keygen(SEED))
    if kg is None:
        return None
    pk, sk = kg
    s = target.sign(sk, msg)
    if not ok(s):
        return None
    sig = s.value
    if not ok(target.verify(pk, msg, sig)):
        return None
    return pk, sk, msg, sig


class KemRelation(Relation):
    requires = frozenset({Capability.KEM})
    needs_control = True

    def control(self, target):
        base = kem_baseline(target)
        return (base is not None, "KEM keygen/encaps/decaps round trip" if base else "KEM baseline round trip failed")


class SigRelation(Relation):
    requires = frozenset({Capability.SIG})
    needs_control = True

    def control(self, target):
        base = sig_baseline(target)
        return (base is not None, "SIG keygen/sign/verify round trip" if base else "SIG baseline round trip failed")


class CodecRelation(Relation):
    requires = frozenset({Capability.RAW_DECODE})
    needs_control = True

    def control(self, target):
        from pqcheck.testing.toycodec import pack_int16
        coeffs = (0, 1, -1, 2, -2, 3, -3, 0)
        enc = target.encode(coeffs)
        if not ok(enc):
            return False, "codec encode failed"
        dec = target.decode(enc.value)
        if not ok(dec) or dec.value != pack_int16(coeffs):
            return False, "codec decode(encode(v)) failed"
        return True, "codec round trip"


def flip(data: bytes, offset: int, mask: int) -> bytes:
    b = bytearray(data)
    b[offset] ^= mask
    return bytes(b)


def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()
