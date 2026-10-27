"""Standalone codec toy: fixed int16 coefficients plus ML-DSA hint codec."""
from __future__ import annotations

import struct

from pqcheck.target import Capability, Outcome, Status

NCOEF = 8
OMEGA = 8
KROWS = 4


def pack_int16(coeffs) -> bytes:
    return struct.pack(f"<{len(coeffs)}h", *coeffs)


def unpack_int16(data: bytes) -> tuple[int, ...]:
    return struct.unpack(f"<{len(data) // 2}h", data)


# --- sign-magnitude unary codec (Falcon-shaped toy stream) -------------------
def encode_coeffs(coeffs) -> bytes:
    bits: list[int] = []
    for c in coeffs:
        bits.append(1 if c < 0 else 0)
        bits.extend([1] * abs(int(c)))
        bits.append(0)
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for bit in bits[i:i + 8]:
            b = (b << 1) | bit
        out.append(b)
    return bytes(out)


def decode_coeffs(data: bytes, *, accept_minus_zero=False, accept_pad=False, ncoef=NCOEF):
    bits: list[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    pos = 0
    coeffs: list[int] = []
    for _ in range(ncoef):
        if pos >= len(bits):
            raise ValueError("truncated stream")
        sign = bits[pos]; pos += 1
        mag = 0
        while pos < len(bits) and bits[pos] == 1:
            mag += 1; pos += 1
        if pos >= len(bits):
            raise ValueError("truncated unary magnitude")
        pos += 1  # terminator zero
        if sign and mag == 0 and not accept_minus_zero:
            raise ValueError("signed zero is non-canonical")
        coeffs.append(-mag if sign else mag)
    rest = bits[pos:]
    if len(rest) >= 8:
        raise ValueError("trailing bytes after stream")
    if rest and any(rest) and not accept_pad:
        raise ValueError("non-zero padding bits")
    return tuple(coeffs)


# --- hint codec ----------------------------------------------------------------
def encode_hints(rows) -> bytes:
    out = bytearray()
    offsets = []
    total = 0
    for row in rows:
        idx = list(row)
        out.extend(idx + [0] * (OMEGA - len(idx)))
        total += len(idx)
        offsets.append(total)
    # pad rows to KROWS
    while len(offsets) < KROWS:
        out.extend([0] * OMEGA)
        offsets.append(total)
    out.extend(offsets)
    return bytes(out)


def decode_hints(data: bytes, *, accept_order=False, accept_tail=False,
                 order_lax_after_first=False):
    if len(data) != KROWS * OMEGA + KROWS:
        raise ValueError("bad hint block length")
    indices = data[:KROWS * OMEGA]
    offsets = list(data[KROWS * OMEGA:])
    rows: list[list[int]] = []
    prev = 0
    for r in range(KROWS):
        used = offsets[r] - prev
        prev = offsets[r]
        if used < 0 or used > OMEGA:
            raise ValueError("bad hint offset")
        row = list(indices[r * OMEGA:r * OMEGA + used])
        tail = list(indices[r * OMEGA + used:(r + 1) * OMEGA])
        if order_lax_after_first and r > 0:
            pass  # mutant shape: only row 0 is order-checked
        elif not accept_order and any(row[i] >= row[i + 1] for i in range(len(row) - 1)):
            raise ValueError("hint indices not strictly increasing")
        if not accept_tail and any(tail):
            raise ValueError("unused hint bytes must be zero")
        rows.append(row)
    return rows


class ToyCodec:
    name = "ToyCodec"
    oracle = None
    size_semantics = "exact"
    codec_kind = "fixed_int16"
    fixed_sig_len = True
    sig_len_basis = "toy fixed 16-byte codec block"

    def __init__(self, mutant: str | None = None):
        self.mutant = mutant
        self.caps = frozenset({Capability.RAW_DECODE})
        self.sizes = {"sig": 16}
        self.measured_sizes: list[str] = ["sig"]
        self.ncoef = NCOEF
        self.omega = OMEGA
        self.krows = KROWS

    def alive(self):
        return True

    def encode(self, coeffs):
        coeffs = [int(c) for c in coeffs]
        if self.mutant == "lossy_large":
            coeffs = [max(-3, min(3, c)) for c in coeffs]
        return Outcome(Status.OK, value=pack_int16(coeffs))

    def decode(self, data):
        data = bytes(data)
        if self.mutant == "length_lax":
            data = data.ljust(16, b"\x00")[:16]
        elif len(data) != 16:
            return Outcome(Status.REJECTED, detail="bad codec length")
        coeffs = list(unpack_int16(data))
        if self.mutant == "roundtrip_broken":
            coeffs[0] += 1
        return Outcome(Status.OK, value=pack_int16(coeffs))

    def encode_hints(self, rows):
        return Outcome(Status.OK, value=encode_hints(rows))

    def decode_hints(self, data):
        try:
            rows = decode_hints(
                bytes(data),
                accept_order=self.mutant == "hint_order_lax",
                accept_tail=self.mutant == "hint_tail_lax",
                order_lax_after_first=self.mutant == "hint_order_row0_only",
            )
        except ValueError as exc:
            return Outcome(Status.REJECTED, detail=str(exc))
        return Outcome(Status.OK, value=encode_hints(rows))


class ToyStreamCodec:
    """Falcon-shaped standalone stream codec (sign-magnitude unary).

    This is the CODEC_MUTANTS target: a pure RAW_DECODE surface whose
    canonicality defects (signed zero, padding, length, hints) are
    exactly what the codec relations ask about.
    """

    name = "ToyStreamCodec"
    oracle = None
    size_semantics = "exact"
    codec_kind = "sign_magnitude_unary"
    fixed_sig_len = True
    sig_len_basis = "toy fixed-length stream for the reference vector"
    ncoef = NCOEF
    omega = OMEGA
    krows = KROWS

    def __init__(self, mutant: str | None = None):
        self.mutant = mutant
        self.caps = frozenset({Capability.RAW_DECODE})
        self.sizes = {"sig": 4}
        self.measured_sizes: list[str] = ["sig"]

    def alive(self):
        return True

    def encode(self, coeffs):
        out = encode_coeffs([int(c) for c in coeffs])
        if self.mutant == "encoder_random_pad":
            out = out + b"\xa5"
        return Outcome(Status.OK, value=out)

    def decode(self, data):
        data = bytes(data)
        if self.mutant == "encoder_random_pad" and len(data) > 1:
            try:
                return self._decode_stream(data)
            except ValueError:
                data = data[:-1]
        if self.mutant == "accepts_wrong_length":
            ref = encode_coeffs((0, 1, -1, 2, -2, 3, -3, 0))
            data = data[:len(ref)].ljust(len(ref), b"\x00")
        try:
            return self._decode_stream(data)
        except ValueError as exc:
            return Outcome(Status.REJECTED, detail=str(exc))

    def _decode_stream(self, data):
        coeffs = decode_coeffs(
            bytes(data),
            accept_minus_zero=self.mutant == "accepts_minus_zero",
            accept_pad=self.mutant == "accepts_nonzero_pad",
        )
        if self.mutant == "decoder_rejects_own_encoding" and any(abs(c) >= 32 for c in coeffs):
            return Outcome(Status.REJECTED, detail="own encoding rejected at this magnitude")
        return Outcome(Status.OK, value=pack_int16(coeffs))

    def encode_hints(self, rows):
        return Outcome(Status.OK, value=encode_hints(rows))

    def decode_hints(self, data):
        try:
            rows = decode_hints(
                bytes(data),
                accept_order=self.mutant == "hint_accepts_repeat",
                accept_tail=self.mutant == "hint_accepts_nonzero_tail",
                order_lax_after_first=self.mutant == "hint_order_row0_only",
            )
        except ValueError as exc:
            return Outcome(Status.REJECTED, detail=str(exc))
        return Outcome(Status.OK, value=encode_hints(rows))


def _f(m):
    return lambda: ToyCodec(mutant=m)


def _fs(m):
    return lambda: ToyStreamCodec(mutant=m)


CODEC_MUTANTS = {
    "accepts_minus_zero": _fs("accepts_minus_zero"),
    "accepts_nonzero_pad": _fs("accepts_nonzero_pad"),
    "accepts_wrong_length": _fs("accepts_wrong_length"),
    "hint_accepts_repeat": _fs("hint_accepts_repeat"),
    "hint_order_row0_only": _fs("hint_order_row0_only"),
    "hint_accepts_nonzero_tail": _fs("hint_accepts_nonzero_tail"),
    "encoder_random_pad": _fs("encoder_random_pad"),
    "decoder_rejects_own_encoding": _fs("decoder_rejects_own_encoding"),
}
