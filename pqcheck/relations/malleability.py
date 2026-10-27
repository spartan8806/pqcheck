"""Signature malleability: bits in the encoding that verify never reads."""
from __future__ import annotations

import itertools

from pqcheck.relations._common import SigRelation, ok, pair
from pqcheck.relations.base import Finding, register


@register
class UnreadBits(SigRelation):
    id = "sig-unread-bits"
    property = "every bit of the signature encoding is read by verify (no malleable unread bits)"
    ceiling = "does not establish strong unforgeability; only encoding-bit coverage up to the combo budget"
    false_positive_modes = (
        "variable-length encodings with declared slack bytes may have "
        "bits verify legitimately does not read; targets must declare "
        "that shape or the finding stands as encoding malleability",
    )
    n_signatures = 8
    max_probes = 40000
    max_combos = 512

    def check(self, target, rng):
        kg = pair(target.keygen(rng.randbytes(16)))
        if kg is None:
            return Finding(None, "keygen failed", 0, "unread bits")
        pk, sk = kg
        sigs: list[tuple[bytes, bytes]] = []
        for _ in range(self.n_signatures):
            msg = rng.randbytes(32)
            s = target.sign(sk, msg)
            if not ok(s) or not ok(target.verify(pk, msg, s.value)):
                return Finding(None, "baseline signature failed", 0, "unread bits")
            sigs.append((msg, s.value))
        # bucket by bit length; sweep backwards from the end of each signature
        by_len: dict[int, list[tuple[bytes, bytes]]] = {}
        for item in sigs:
            by_len.setdefault(len(item[1]) * 8, []).append(item)
        units = 0
        witness = None
        witness_positions: list[int] = []
        for _bits, group in by_len.items():
            for msg, sig in group:
                positions = []
                total_bits = len(sig) * 8
                for pos in range(total_bits - 1, -1, -1):
                    if units >= self.max_probes:
                        break
                    mutated = bytearray(sig)
                    mutated[pos // 8] ^= 1 << (pos % 8)
                    units += 1
                    if ok(target.verify(pk, msg, bytes(mutated))):
                        positions.append(pos)
                if positions:
                    witness = (msg, sig)
                    witness_positions = positions
                    break
            if witness is not None:
                break
        if witness is None:
            return Finding(True, "no unread bit found across the swept signatures", units, f"bit-flip sweep over {len(sigs)} signatures")
        msg, sig = witness
        combos = 0
        accepted_combos = 0
        for r in (2, 3):
            for combo in itertools.combinations(witness_positions[:12], r):
                if combos >= self.max_combos:
                    break
                mutated = bytearray(sig)
                for pos in combo:
                    mutated[pos // 8] ^= 1 << (pos % 8)
                combos += 1
                units += 1
                if ok(target.verify(pk, msg, bytes(mutated))):
                    accepted_combos += 1
        return Finding(
            False,
            f"{len(witness_positions)} unread bit position(s) in one signature; {accepted_combos} multi-bit combos also accepted (encoding multiplicity grows with unread bits)",
            units,
            f"bit-flip sweep over {len(sigs)} signatures plus combination probing",
            reproduce="re-run pqcheck sig-unread-bits with the pinned seed",
        )
