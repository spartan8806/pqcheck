"""ML-KEM encoding canonicality: ek modulus and dk H(ek) consistency."""
from __future__ import annotations

from pqcheck.relations._common import KemRelation, flip, ok, pair, sha3
from pqcheck.relations.base import Finding, NotApplicable, register
from pqcheck.target import Capability


def _unpack12(data: bytes, count: int | None = None) -> list[int]:
    """FIPS 203 ByteDecode_12: coefficients are 12-bit little-endian.

    Each 3-byte group holds two coefficients:
    c0 = b0 | ((b1 & 0x0F) << 8) and c1 = (b1 >> 4) | (b2 << 4).
    """
    out = []
    for i in range(0, len(data) - 2, 3):
        b0, b1, b2 = data[i], data[i + 1], data[i + 2]
        out.append(b0 | ((b1 & 0x0F) << 8))
        out.append((b1 >> 4) | (b2 << 4))
    return out[:count] if count is not None else out


def _pack12(coeffs) -> bytes:
    """FIPS 203 ByteEncode_12, inverse of _unpack12."""
    coeffs = [int(c) for c in coeffs]
    if len(coeffs) % 2:
        coeffs.append(0)
    out = bytearray()
    for i in range(0, len(coeffs), 2):
        c0, c1 = coeffs[i], coeffs[i + 1]
        out.append(c0 & 0xFF)
        out.append(((c0 >> 8) & 0x0F) | ((c1 & 0x0F) << 4))
        out.append((c1 >> 4) & 0xFF)
    return bytes(out)


def _split_ek(ek: bytes, packed_len: int):
    """Split ek into (coefficient body, trailing bytes).

    In ML-KEM the ek is 384*k bytes of packed coefficients followed by
    the 32-byte rho seed, so the body is ek[:-32] and rho is returned
    untouched. Targets whose ek is exactly the packed body have no tail.
    """
    if len(ek) == packed_len + 32:
        return ek[:-32], ek[-32:]
    return ek[:packed_len], ek[packed_len:]


def _dk_parts(target, dk: bytes):
    sizes = getattr(target, "sizes", {}) or {}
    ek_len = sizes.get("ek")
    if not ek_len or len(dk) < ek_len + 64:
        return None
    z = dk[-32:]
    h = dk[-64:-32]
    ek = dk[-64 - ek_len:-64]
    prefix = dk[:len(dk) - 64 - ek_len]
    return prefix, ek, h, z


@register
class EkModulusCanonical(KemRelation):
    id = "kem-ek-modulus-canonical"
    property = "ek coefficients in [q, 4095] are never key-equivalent to the canonical ek (FIPS 203 modulus canonicality)"
    ceiling = "does not establish that encaps validates and rejects non-canonical input, only that no second byte string is the same key; canonicality of other encodings is also not established"
    constructs_probes = True
    false_positive_modes = (
        "accepting a bumped ek as a *distinct* key is not a defect; only "
        "key-equivalence (decaps under the original dk returns the bumped "
        "secret) is reported",
    )

    def probe_control(self, target):
        packing = getattr(target, "ek_packing", None)
        if not packing:
            return False
        kg = pair(target.keygen(b"pqcheck-ek-probe-control"))
        if kg is None:
            return False
        ek, _dk = kg
        count = packing["n"] * packing["k"]
        packed_len = count * 12 // 8
        if len(ek) < packed_len:
            return False
        # Only the coefficient body (ek[:-32] for ML-KEM) is unpacked;
        # the 32-byte rho tail is not coefficients and stays untouched.
        body, _rho = _split_ek(ek, packed_len)
        if _pack12(_unpack12(body)) != body:
            return False
        return pair(target.encaps(ek)) is not None

    def check(self, target, rng):
        packing = getattr(target, "ek_packing", None)
        if not packing:
            raise NotApplicable("target does not declare 12-bit ek packing")
        q = packing["q"]; count = packing["n"] * packing["k"]
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "ek modulus")
        ek, dk = kg
        packed_len = count * 12 // 8
        body, trailing = _split_ek(ek, packed_len)
        coeffs = _unpack12(body, count)
        units = 0
        equivalent = []
        accepted_distinct = 0
        # Bumpable: c + q must still fit in 12 bits, i.e. c < 4096 - q.
        anchors = [i for i in range(count) if coeffs[i] < 4096 - q][:16]
        for idx in anchors:
            c = coeffs[idx]
            if c + q > 4095:
                continue
            bumped = list(coeffs); bumped[idx] = c + q
            bad_ek = _pack12(bumped) + trailing
            enc = target.encaps(bad_ek)
            units += 1
            if ok(enc):
                # Acceptance alone makes the bumped bytes a *different*
                # key. The canonicality defect is key equivalence: the
                # ciphertext still decapsulates, under the original dk,
                # to the secret the bumped ek produced.
                ss2, ct2 = enc.value
                dec = target.decaps(dk, ct2)
                if ok(dec) and dec.value == ss2:
                    equivalent.append(idx)
                else:
                    accepted_distinct += 1
        if equivalent:
            return Finding(False, f"non-canonical ek coefficients at positions {equivalent} are key-equivalent to the canonical ek (two byte strings, one key)", units, "ek modulus canonicality probes across all polynomials", reproduce="re-run pqcheck kem-ek-modulus-canonical with the pinned seed")
        if units == 0:
            return Finding(None, "no bumpable coefficient found", 0, "ek modulus")
        note = f" ({accepted_distinct} bumped keys accepted as distinct keys, none key-equivalent)" if accepted_distinct else ""
        return Finding(True, "no non-canonical ek coefficient is key-equivalent to the canonical ek" + note, units, "ek modulus canonicality probes across all polynomials")


@register
class DkHashConsistency(KemRelation):
    id = "kem-dk-hash-consistency"
    property = "decaps never returns the honest secret under a dk whose H(ek) field is tampered (FIPS 203 dk consistency)"
    ceiling = "does not establish the full Algorithm 16 key format beyond H(ek)"
    constructs_probes = True

    def probe_control(self, target):
        kg = pair(target.keygen(b"pqcheck-dk-probe-control"))
        if kg is None:
            return False
        ek, dk = kg
        parts = _dk_parts(target, dk)
        if parts is None:
            return False
        _prefix, embedded, h, _z = parts
        return embedded == ek and h == sha3(ek)

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "dk hash")
        ek, dk = kg
        parts = _dk_parts(target, dk)
        if parts is None:
            raise NotApplicable("dk layout does not expose ek/H(ek)/z fields")
        prefix, embedded, h, z = parts
        enc = pair(target.encaps(ek))
        if enc is None:
            return Finding(None, "encaps failed", 0, "dk hash")
        ss, ct = enc
        tampered = [flip(h, 0, 1), flip(h, 5, 8), flip(h, 31, 128), b"\x00" * 32, b"\xff" * 32]
        units = 0
        bad = []
        for th in tampered:
            bad_dk = prefix + embedded + th + z
            a = target.decaps(bad_dk, ct); b = target.decaps(bad_dk, ct)
            units += 2
            if ok(a) and a.value == ss:
                bad.append("honest secret returned")
            if ok(a) and ok(b) and a.value != b.value:
                bad.append("non-deterministic under tampered dk")
        if bad:
            return Finding(False, f"tampered H(ek) in dk: {bad[0]}", units, "dk H(ek) tampering probes", reproduce="re-run pqcheck kem-dk-hash-consistency with the pinned seed")
        return Finding(True, "tampered H(ek) never yields the honest secret and stays deterministic", units, "dk H(ek) tampering probes")
