"""Independent Falcon compression codec (FIPS/Falcon spec Alg. 17/18).

Written from the Falcon specification's compressed encoding, as a
bit-list implementation that shares no code with the Rust upstream
(bit-accumulator) or with toycodec's sign-magnitude toy. Its purpose
is cross-implementation checking: the same encoding must come out of
this code, out of the pinned falcon-rust upstream (vendored in
pqcheck/adapters/rust/), and out of Noble's Falcon signatures.

Format, per coefficient v (spec, "compress"/"decompress"):
  - 1 sign bit (1 iff v < 0)
  - 7 low bits of |v|
  - the high part |v| >> 7 in unary: that many 0 bits, then a 1 bit
The stream is zero-padded to the requested byte length. Decoding
rejects signed zero, magnitudes above 2047, truncated streams, and
non-zero padding.
"""
from __future__ import annotations

MAX_MAGNITUDE = 2047


def compress(coeffs, byte_length: int) -> bytes | None:
    """Encode coefficients into exactly byte_length bytes, or None."""
    bits: list[int] = []
    for value in coeffs:
        v = int(value)
        mag = abs(v)
        if mag > MAX_MAGNITUDE:
            return None
        bits.append(1 if v < 0 else 0)
        for shift in range(6, -1, -1):
            bits.append((mag >> shift) & 1)
        bits.extend([0] * (mag >> 7))
        bits.append(1)
    if len(bits) > byte_length * 8:
        return None
    bits.extend([0] * (byte_length * 8 - len(bits)))
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def decompress(data: bytes, n: int) -> tuple[int, ...] | None:
    """Decode n coefficients, or None if the stream is not canonical."""
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    pos = 0
    coeffs: list[int] = []
    for _ in range(n):
        if pos + 8 > len(bits):
            return None
        sign = bits[pos]
        pos += 1
        mag = 0
        for _ in range(7):
            mag = (mag << 1) | bits[pos]
            pos += 1
        while True:
            if pos >= len(bits):
                return None
            bit = bits[pos]
            pos += 1
            if bit:
                break
            mag += 128
            if mag > MAX_MAGNITUDE:
                return None
        if sign and mag == 0:
            return None  # signed zero is non-canonical
        coeffs.append(-mag if sign else mag)
    if any(bits[pos:]):
        return None  # non-zero padding
    return tuple(coeffs)
