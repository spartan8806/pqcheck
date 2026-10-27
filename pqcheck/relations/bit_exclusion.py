"""Mouha bit-exclusion: behaviour must not depend on bytes past the declared length."""
from __future__ import annotations

import random as _random

from pqcheck.relations._common import KemRelation, SigRelation, flip, ok, pair
from pqcheck.relations.base import Finding, register
from pqcheck.target import Capability

FILLS = ("zero", "ff", "random", "zero-again")


def _fill_bytes(kind, rng):
    if kind == "zero" or kind == "zero-again":
        return b"\x00" * 64
    if kind == "ff":
        return b"\xff" * 64
    return rng.randbytes(64)


@register
class KemBitExclusion(KemRelation):
    id = "kem-declared-length-bit-exclusion"
    property = "decaps/encaps results do not depend on the 64 guard bytes past the buffer"
    ceiling = "does not establish memory safety beyond the guarded inputs probed"
    requires = frozenset({Capability.KEM, Capability.GUARD_FILL})

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "kem guard fill")
        ek, dk = kg
        units = 0
        try:
            target.guard(None)
            base_enc = pair(target.encaps(ek))
            if base_enc is None:
                return Finding(None, "encaps failed", 0, "kem guard fill")
            _ss0, ct = base_enc
            results: dict[str, list] = {}
            for kind in FILLS:
                fill = _fill_bytes(kind, rng)
                target.guard(fill)
                d_honest = target.decaps(dk, ct)
                d_flip_first = target.decaps(dk, flip(ct, 0, 1))
                d_flip_last = target.decaps(dk, flip(ct, len(ct) - 1, 1))
                outcomes = [
                    d_honest.value if ok(d_honest) else None,
                    d_flip_first.value if ok(d_flip_first) else None,
                    d_flip_last.value if ok(d_flip_last) else None,
                ]
                units += 3
                if Capability.PINNED_RANDOMNESS in set(getattr(target, "caps", frozenset())):
                    try:
                        e = target.encaps(ek, ct)
                        if ok(e):
                            outcomes.append(e.value[0])
                            units += 1
                    except TypeError:
                        pass
                results[kind] = outcomes
            if results.get("zero") != results.get("zero-again"):
                return Finding(False, "repeated zero guard fill gave a different result (non-determinism under guard)", units, "kem guard-fill sweep", reproduce="re-run pqcheck kem-declared-length-bit-exclusion with the pinned seed")
            base = results.get("zero")
            for kind in ("ff", "random"):
                if results.get(kind) != base:
                    return Finding(False, f"decaps/encaps result depends on the {kind} guard fill past the buffer", units, "kem guard-fill sweep (0x00, 0xFF, random, 0x00)", reproduce="re-run pqcheck kem-declared-length-bit-exclusion with the pinned seed")
            if units == 0:
                return Finding(None, "no guard-fill observations", 0, "kem guard fill")
            return Finding(True, "results are invariant across 64-byte guard fills", units, "kem guard-fill sweep (0x00, 0xFF, random, 0x00)")
        finally:
            try:
                target.guard(None)
            except Exception:
                pass


@register
class SigBitExclusion(SigRelation):
    id = "sig-declared-length-bit-exclusion"
    property = "sign/verify results do not depend on the 64 guard bytes past the buffer"
    ceiling = "does not establish memory safety beyond the guarded inputs probed"
    requires = frozenset({Capability.SIG, Capability.GUARD_FILL})

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "sig guard fill")
        pk, sk = kg
        units = 0
        try:
            results: dict[str, list] = {}
            for kind in FILLS:
                target.guard(_fill_bytes(kind, rng))
                outcomes = []
                for n in (1, 33, 135, 136, 137):
                    msg = rng.randbytes(n)
                    s = target.sign(sk, msg)
                    if ok(s):
                        v = target.verify(pk, msg, s.value)
                        outcomes.append(ok(v))
                        units += 1
                    else:
                        outcomes.append(False)
                # one corrupted signature
                msg = b"guard corrupted probe"
                s = target.sign(sk, msg)
                if ok(s):
                    bad = flip(s.value, len(s.value) - 1, 1)
                    outcomes.append(ok(target.verify(pk, msg, bad)))
                    units += 1
                results[kind] = outcomes
            if results.get("zero") != results.get("zero-again"):
                return Finding(False, "repeated zero guard fill gave a different result", units, "sig guard-fill sweep", reproduce="re-run pqcheck sig-declared-length-bit-exclusion with the pinned seed")
            base = results.get("zero")
            for kind in ("ff", "random"):
                if results.get(kind) != base:
                    return Finding(False, f"sign/verify result depends on the {kind} guard fill past the buffer", units, "sig guard-fill sweep (0x00, 0xFF, random, 0x00)", reproduce="re-run pqcheck sig-declared-length-bit-exclusion with the pinned seed")
            return Finding(True, "results are invariant across 64-byte guard fills", units, "sig guard-fill sweep (0x00, 0xFF, random, 0x00)")
        finally:
            try:
                target.guard(None)
            except Exception:
                pass
