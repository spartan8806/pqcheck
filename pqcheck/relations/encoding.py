"""Raw codec and hint-encoding relations."""
from __future__ import annotations

from pqcheck.relations._common import CodecRelation, ok
from pqcheck.relations.base import Finding, NotApplicable, register
from pqcheck.target import Capability
from pqcheck.testing.toycodec import encode_coeffs, pack_int16, unpack_int16

_CAL = (0, 1, -1, 2, -2, 3, -3, 0)


def _view(decoded):
    if isinstance(decoded, (bytes, bytearray)):
        return tuple(unpack_int16(bytes(decoded)))
    return tuple(decoded)


@register
class SignedZero(CodecRelation):
    id = "sig-encoding-signed-zero"
    property = "the codec rejects a signed-zero (-0) stream"
    ceiling = "does not establish canonicality of non-zero coefficients"
    constructs_probes = True

    def probe_control(self, target):
        if getattr(target, "codec_kind", None) != "sign_magnitude_unary":
            return False
        enc = target.encode((0,) * 8)
        if not ok(enc):
            return False
        dec = target.decode(enc.value)
        if not ok(dec) or _view(dec.value) != (0,) * 8:
            return False
        return True

    def check(self, target, rng):
        if getattr(target, "codec_kind", None) != "sign_magnitude_unary":
            raise NotApplicable("target is not a sign-magnitude unary codec")
        stream = encode_coeffs((0,) * 8)
        # flip the sign bit of the first coefficient: canonical +0 -> -0 probe
        probe = bytearray(stream)
        probe[0] ^= 0x80
        units = 1
        dec = target.decode(bytes(probe))
        if ok(dec):
            return Finding(False, "codec accepted a signed-zero stream", units, "signed-zero constructed probe", reproduce="re-run pqcheck sig-encoding-signed-zero with the pinned seed")
        return Finding(True, "signed-zero stream rejected", units, "signed-zero constructed probe")


@register
class PadBitsZero(CodecRelation):
    id = "sig-encoding-pad-bits-zero"
    property = "bits after the encoded stream (padding) must be zero and are rejected when set"
    ceiling = "does not establish canonicality inside the stream itself"

    def check(self, target, rng):
        if getattr(target, "codec_kind", None) != "sign_magnitude_unary":
            # A fixed-width codec has no padding region, so this
            # question cannot be asked of it. Reporting "no defect
            # found" here would be reassurance over an untested
            # surface; the runner maps this to NOT_ANSWERABLE.
            raise NotApplicable(
                "fixed-width codec has no padding region to test")
        coeffs = (1, -1, 1, 0, 0, 0, 0, 0)
        enc = target.encode(coeffs)
        if not ok(enc):
            return Finding(None, "encode failed", 0, "pad bits")
        stream = enc.value
        total_bits = len(stream) * 8
        # find pad_start by monotone search: zeroing bits j..end preserves decode
        def holds(j):
            b = bytearray(stream)
            for pos in range(j, total_bits):
                if (b[pos // 8] >> (7 - (pos % 8))) & 1:
                    b[pos // 8] &= ~(1 << (7 - (pos % 8)))
            dec = target.decode(bytes(b))
            return ok(dec) and _view(dec.value) == coeffs
        units = 0
        lo = None
        for j in range(total_bits + 1):
            units += 1
            if holds(j):
                lo = j
                break
        if lo is None:
            return Finding(True, "no settable padding region found", units, "pad-bit monotone search")
        bad = []
        for pos in range(lo, total_bits):
            mutated = bytearray(stream)
            mutated[pos // 8] ^= 1 << (7 - (pos % 8))
            units += 1
            dec = target.decode(bytes(mutated))
            if ok(dec) and _view(dec.value) == coeffs:
                bad.append(pos)
        if bad:
            return Finding(False, f"non-zero padding bits at {bad[:6]} were accepted", units, "pad-bit flip probes", reproduce="re-run pqcheck sig-encoding-pad-bits-zero with the pinned seed")
        return Finding(True, "padding bits are rejected when set", units, "pad-bit flip probes")


@register
class CodecLengthExact(CodecRelation):
    id = "sig-encoding-length-exact"
    property = "the codec rejects streams of any length other than the exact encoded length"
    ceiling = "does not apply to variable-length codecs"

    def check(self, target, rng):
        if getattr(target, "fixed_sig_len", None) is not True:
            raise NotApplicable("codec does not declare a fixed length")
        enc = target.encode(_CAL)
        if not ok(enc):
            return Finding(None, "encode failed", 0, "codec length")
        ref = enc.value
        probes = [ref[:-1], ref + b"\x00", ref + b"\xff", ref + ref]
        stripped = ref.rstrip(b"\x00")
        if stripped != ref:
            probes.append(stripped)
        units = 0
        for p in probes:
            units += 1
            if ok(target.decode(p)):
                return Finding(False, f"codec accepted a stream of length {len(p)} (expected {len(ref)})", units, "codec exact-length probes", reproduce="re-run pqcheck sig-encoding-length-exact with the pinned seed")
        return Finding(True, "off-length codec streams rejected", units, "codec exact-length probes")


@register
class DecodeReencodeIdentity(CodecRelation):
    id = "sig-encoding-decode-reencode-identity"
    property = "encode(view(decode(encode(v)))) == encode(v) at realistic magnitudes"
    ceiling = "does not establish rejection of non-canonical streams"

    def check(self, target, rng):
        units = 0
        span = 64
        for shift in range(6):
            mag = max(1, span >> shift)
            coeffs = tuple(mag if i % 2 == 0 else -mag for i in range(8))
            enc = target.encode(coeffs)
            if not ok(enc):
                return Finding(None, "encode failed", units, "reencode identity")
            dec = target.decode(enc.value)
            units += 1
            if not ok(dec):
                return Finding(False, "decode refused encode output at realistic magnitude", units, "decode-reencode identity", reproduce="re-run pqcheck sig-encoding-decode-reencode-identity with the pinned seed")
            if _view(dec.value) != coeffs:
                return Finding(False, f"decode(encode(v)) lost magnitude at {mag}: got {_view(dec.value)}", units, "decode-reencode identity", reproduce="re-run pqcheck sig-encoding-decode-reencode-identity with the pinned seed")
            re_enc = target.encode(_view(dec.value))
            if not ok(re_enc) or re_enc.value != enc.value:
                return Finding(False, f"decode-reencode is not the identity at magnitude {mag}", units, "decode-reencode identity", reproduce="re-run pqcheck sig-encoding-decode-reencode-identity with the pinned seed")
        return Finding(True, "decode-reencode identity holds across 6 magnitudes", units, "decode-reencode identity")


class HintRelation(CodecRelation):
    def control(self, target):
        if not hasattr(target, "decode_hints"):
            raise NotApplicable("target has no hint codec")
        enc = target.encode_hints([[1, 3], [5]])
        if not ok(enc):
            return False, "hint encode failed"
        dec = target.decode_hints(enc.value)
        return (ok(dec), "hint encode/decode round trip")


@register
class HintStrictOrder(HintRelation):
    id = "mldsa-hint-strict-order"
    property = "hint indices within each row are strictly increasing; repeats and descents are rejected"
    ceiling = "does not establish hint correctness for signatures, only the codec"

    def check(self, target, rng):
        if not hasattr(target, "decode_hints"):
            raise NotApplicable("target has no hint codec")
        rows = [[1, 3]] * getattr(target, "krows", 4)
        enc = target.encode_hints(rows)
        if not ok(enc):
            return Finding(None, "hint encode failed", 0, "hint order")
        ref = target.decode_hints(enc.value)
        if not ok(ref):
            return Finding(None, "hint baseline decode failed", 0, "hint order")
        units = 0
        bad = []
        for r in range(len(rows)):
            for mutant_row in ([1, 1], [3, 1]):
                mutated = [list(x) for x in rows]
                mutated[r] = mutant_row
                m_enc = target.encode_hints(mutated)
                if not ok(m_enc):
                    continue
                # encode may canonicalise; construct via raw mutation instead:
                raw = bytearray(enc.value)
                omega = getattr(target, "omega", 8)
                raw[r * omega] = mutant_row[0]; raw[r * omega + 1] = mutant_row[1]
                units += 1
                if ok(target.decode_hints(bytes(raw))):
                    bad.append((r, mutant_row))
        if bad:
            return Finding(False, f"non-increasing hint rows accepted: {bad[:3]}", units, "hint strict-order probes", reproduce="re-run pqcheck mldsa-hint-strict-order with the pinned seed")
        return Finding(True, "repeated and descending hint rows rejected", units, "hint strict-order probes")


@register
class HintTailZero(HintRelation):
    id = "mldsa-hint-tail-zero"
    property = "unused hint-index bytes after the used count must be zero"
    ceiling = "does not establish hint correctness for signatures, only the codec"

    def check(self, target, rng):
        if not hasattr(target, "decode_hints"):
            raise NotApplicable("target has no hint codec")
        rows = [[1, 3], [5]]
        enc = target.encode_hints(rows)
        if not ok(enc):
            return Finding(None, "hint encode failed", 0, "hint tail")
        omega = getattr(target, "omega", 8)
        krows = getattr(target, "krows", 4)
        units = 0
        bad = []
        # used counts per row from the encoded offsets are 2,3,3,3 cumulative;
        # tail bytes in row 0 are positions 2..omega-1 of the index area.
        for pos in range(2, omega):
            raw = bytearray(enc.value)
            raw[pos] = 0x7F
            units += 1
            if ok(target.decode_hints(bytes(raw))):
                bad.append(pos)
        if bad:
            return Finding(False, f"non-zero unused hint bytes accepted at {bad[:4]}", units, "hint tail-zero probes", reproduce="re-run pqcheck mldsa-hint-tail-zero with the pinned seed")
        return Finding(True, "non-zero unused hint bytes rejected", units, "hint tail-zero probes")
