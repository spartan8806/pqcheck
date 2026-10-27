"""Core round-trip, size, and length-boundary invariants."""
from __future__ import annotations

from pqcheck.relations._common import CodecRelation, KemRelation, SigRelation, ok, pair, rej, sig_baseline, val
from pqcheck.relations.base import Finding, NotApplicable, Relation, register
from pqcheck.target import Capability


@register
class KemRoundTrip(Relation):
    id = "core-kem-round-trip"
    property = "KEM decaps(dk, encaps(ek)) returns the encapsulated secret"
    ceiling = "does not establish implicit-rejection correctness or side-channel resistance"
    requires = frozenset({Capability.KEM})
    needs_control = False

    def check(self, target, rng):
        units = 0
        for i in range(2):
            kg = pair(target.keygen(rng.randbytes(16)))
            if kg is None:
                return Finding(False, "keygen failed", max(units, 1), "kem round trip", reproduce="re-run pqcheck core-kem-round-trip with the pinned seed")
            ek, dk = kg
            for _ in range(2):
                enc = pair(target.encaps(ek))
                if enc is None:
                    return Finding(False, "encaps failed", max(units, 1), "kem round trip", reproduce="re-run pqcheck core-kem-round-trip with the pinned seed")
                ss, ct = enc
                dec = target.decaps(dk, ct)
                units += 1
                if not ok(dec) or dec.value != ss:
                    return Finding(False, f"decaps mismatch on keypair {i}", units, "kem keygen/encaps/decaps round trip", reproduce="re-run pqcheck core-kem-round-trip with the pinned seed")
        return Finding(True, "2 keypairs x 2 encapsulations round-tripped", units, "kem keygen/encaps/decaps round trip")


@register
class SigRoundTrip(Relation):
    id = "core-sig-round-trip"
    property = "signatures produced by sign verify under the matching key"
    ceiling = "does not establish unforgeability or canonical encoding"
    requires = frozenset({Capability.SIG})
    needs_control = False

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "sig round trip")
        pk, sk = kg
        refused = 0
        units = 0
        failures = []
        for n in (0, 1, 32, 137, 1024):
            msg = rng.randbytes(n) if n else b""
            s = target.sign(sk, msg)
            units += 1
            if not ok(s):
                refused += 1
                continue
            if not ok(target.verify(pk, msg, s.value)):
                failures.append(n)
        if refused == 5:
            return Finding(False, "keygen succeeded but all 5 signing calls were refused; a signer that refuses every message is defective", units, "sig sign/verify round trip", reproduce="re-run pqcheck core-sig-round-trip with the pinned seed")
        if failures:
            return Finding(False, f"verify refused honest signatures at message lengths {failures}", units, "sig sign/verify round trip", reproduce="re-run pqcheck core-sig-round-trip with the pinned seed")
        if refused:
            return Finding(None, f"{refused} signing calls refused", units, "sig sign/verify round trip")
        return Finding(True, "5 message shapes signed and verified", units, "sig sign/verify round trip")


@register
class CodecRoundTrip(CodecRelation):
    id = "core-codec-round-trip"
    property = "decode(encode(v)) recovers v"
    ceiling = "does not establish rejection of non-canonical streams"
    needs_control = False

    def check(self, target, rng):
        from pqcheck.testing.toycodec import pack_int16, unpack_int16
        vectors = [(0,) * 8, (0, 1, -1, 2, -2, 3, -3, 1), (5, -5, 7, -7, 0, 4, -4, 2)]
        units = 0
        for v in vectors:
            enc = target.encode(v)
            if not ok(enc):
                return Finding(False, "encode refused a reference vector", max(units, 1), "codec round trip", reproduce="re-run pqcheck core-codec-round-trip with the pinned seed")
            dec = target.decode(enc.value)
            units += 1
            if not ok(dec):
                return Finding(False, "decode refused encode output", units, "codec round trip", reproduce="re-run pqcheck core-codec-round-trip with the pinned seed")
            got = unpack_int16(dec.value) if isinstance(dec.value, (bytes, bytearray)) else dec.value
            if tuple(got) != tuple(v):
                return Finding(False, f"decode(encode({v})) = {tuple(got)}", units, "codec round trip", reproduce="re-run pqcheck core-codec-round-trip with the pinned seed")
        return Finding(True, "reference vectors round-tripped under the modelled view", units, "codec encode/decode round trip")


@register
class DeclaredSizes(Relation):
    id = "core-declared-sizes-match-produced"
    property = "declared sizes match the byte lengths actually produced"
    ceiling = "does not establish that produced values are cryptographically correct"
    requires = frozenset()
    needs_control = False
    premise_attrs = ("sizes", "measured_sizes", "size_semantics")

    def check(self, target, rng):
        measured = getattr(target, "measured_sizes", None)
        if measured is None:
            return Finding(None, "measured_sizes is not declared; failing closed", 0, "declared sizes")
        sizes = getattr(target, "sizes", {}) or {}
        produced: dict[str, int] = {}
        caps = set(getattr(target, "caps", frozenset()))
        if Capability.KEM in caps:
            kg = pair(target.keygen(rng.randbytes(16)))
            if kg:
                produced["ek"], produced["dk"] = len(kg[0]), len(kg[1])
                produced["pk"], produced["sk"] = len(kg[0]), len(kg[1])
                enc = pair(target.encaps(kg[0]))
                if enc:
                    produced["ss"], produced["ct"] = len(enc[0]), len(enc[1])
        if Capability.SIG in caps:
            kg = pair(target.keygen(rng.randbytes(16)))
            if kg:
                produced["pk"], produced["sk"] = len(kg[0]), len(kg[1])
                s = target.sign(kg[1], b"size probe")
                if ok(s):
                    produced["sig"] = len(s.value)
        if Capability.RAW_DECODE in caps and "sig" in measured and "sig" not in produced:
            enc = target.encode((0, 1, -1, 2, -2, 3, -3, 0))
            if ok(enc):
                produced["sig"] = len(enc.value)
        units = 0
        bad = []
        semantics = getattr(target, "size_semantics", "exact")
        for key in measured:
            if key not in sizes or key not in produced:
                continue
            units += 1
            declared, actual = sizes[key], produced[key]
            key_semantics = semantics.get(key, "exact") if isinstance(semantics, dict) else semantics
            if key_semantics == "max":
                if actual > declared:
                    bad.append(f"{key}: produced {actual} > declared max {declared}")
            elif actual != declared:
                bad.append(f"{key}: declared {declared} != produced {actual}")
        if units == 0:
            return Finding(None, "no measured sizes could be produced", 0, "declared sizes")
        if bad:
            return Finding(False, "; ".join(bad), units, "declared sizes vs produced lengths", reproduce="re-run pqcheck core-declared-sizes-match-produced with the pinned seed")
        return Finding(True, "declared sizes match produced lengths", units, "declared sizes vs produced lengths")


BOUNDARIES = (16, 32, 64, 72, 104, 128, 136, 144, 168, 255, 256, 512, 1024, 4096, 65536)


@register
class InputLengthBoundaries(SigRelation):
    id = "core-input-length-boundaries"
    property = "sign/verify work at B-1, B, and B+1 around sponge-rate and power-of-two boundaries"
    ceiling = "does not establish correctness for unbounded message lengths"

    def check(self, target, rng):
        base = sig_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "input length boundaries")
        pk, sk, _m, _s = base
        lengths = sorted({0, 1, 2} | {x for b in BOUNDARIES for x in (b - 1, b, b + 1) if x >= 0})
        failed: list[int] = []
        units = 0
        for n in lengths:
            msg = rng.randbytes(n) if n else b""
            s = target.sign(sk, msg)
            units += 1
            if not ok(s) or not ok(target.verify(pk, msg, s.value)):
                failed.append(n)
        if not failed:
            return Finding(True, f"{len(lengths)} boundary lengths signed and verified", units, "sig message-length boundary sweep")
        isolated = [n for n in failed if (n - 1) not in failed and (n + 1) not in failed]
        if isolated:
            return Finding(False, f"isolated boundary failures at lengths {isolated[:5]} (neighbours pass)", units, "sig message-length boundary sweep", reproduce="re-run pqcheck core-input-length-boundaries with the pinned seed")
        return Finding(False, f"contiguous length failures from {min(failed)} (possible size cap)", units, "sig message-length boundary sweep", reproduce="re-run pqcheck core-input-length-boundaries with the pinned seed")
