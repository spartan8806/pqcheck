"""Verifier-side ML-DSA hint relations (toy and FIPS 204 hint layouts)."""
from __future__ import annotations

from pqcheck.relations._common import SigRelation, ok, pair
from pqcheck.relations.base import Finding, register
from pqcheck.target import Capability


def _parse_hints(target, sig: bytes):
    """Return (rows, tail_positions) or None if the layout does not parse.

    rows: list of (absolute_index_positions, values) per polynomial row.
    tail_positions: absolute positions of unused hint-index bytes.
    """
    g = getattr(target, "mldsa_hint", None)
    if not g:
        return None
    omega, k = g["omega"], g["k"]
    layout = getattr(target, "hint_layout", "toy")
    if layout == "fips204":
        hint_len = omega + k
        if len(sig) < hint_len:
            return None
        main = len(sig) - hint_len
        indices = sig[main:main + omega]
        offsets = list(sig[main + omega:])
        rows = []
        prev = 0
        for r in range(k):
            if offsets[r] < prev or offsets[r] > omega:
                return None
            positions = list(range(main + prev, main + offsets[r]))
            rows.append((positions, [indices[p - main] for p in positions]))
            prev = offsets[r]
        tail = list(range(main + prev, main + omega))
        return rows, tail
    main = g["ctilde"] + g["z"]
    if len(sig) < main + k * omega + k:
        return None
    indices = sig[main:main + k * omega]
    offsets = list(sig[main + k * omega:main + k * omega + k])
    rows = []
    prev = 0
    for r in range(k):
        used = offsets[r] - prev
        if used < 0 or used > omega:
            return None
        start = main + r * omega
        rows.append((list(range(start, start + used)), list(indices[r * omega:r * omega + used])))
        prev = offsets[r]
    first_used = offsets[0] if offsets else 0
    tail = list(range(main + first_used, main + omega))
    return rows, tail


def _find_hinted_sig(target, rng, need=2):
    kg = pair(target.keygen(rng.randbytes(16)))
    if kg is None:
        return None
    pk, sk = kg
    for _ in range(8):
        msg = rng.randbytes(24)
        s = target.sign(sk, msg)
        if not ok(s) or not ok(target.verify(pk, msg, s.value)):
            continue
        parsed = _parse_hints(target, s.value)
        if parsed is None:
            continue
        rows, tail = parsed
        for positions, values in rows:
            if len(values) >= need:
                return pk, msg, s.value, positions, values, tail
        if need == 1 and rows:
            positions, values = rows[0]
            return pk, msg, s.value, positions, values, tail
    return None


@register
class VerifyHintStrictOrder(SigRelation):
    id = "mldsa-verify-hint-strict-order"
    property = "verify rejects a signature whose hint indices are repeated or descending"
    ceiling = "does not establish hint handling beyond ordering in the verifier"
    false_positive_modes = (
        "a verifier that canonicalises hint order internally before "
        "checking would accept the byte string but not the non-canonical "
        "hint semantics; pqcheck reports the byte-level acceptance",
    )
    requires = frozenset({Capability.SIG, Capability.DETACHED_SIG, Capability.MLDSA_HINT_ENCODING})

    def check(self, target, rng):
        found = _find_hinted_sig(target, rng, need=2)
        if found is None:
            return Finding(None, "no honest signature with a >=2 hint row found in 8 tries", 0, "verify hint order")
        pk, msg, sig, positions, values, _tail = found
        units = 0
        bad = []
        for new_values in ([values[1], values[0]], [values[0], values[0]]):
            mutated = bytearray(sig)
            mutated[positions[0]] = new_values[0]
            mutated[positions[1]] = new_values[1]
            units += 1
            if ok(target.verify(pk, msg, bytes(mutated))):
                bad.append(new_values)
        if bad:
            return Finding(False, f"verify accepted non-increasing hint rows {bad}", units, "verifier hint strict-order probes", reproduce="re-run pqcheck mldsa-verify-hint-strict-order with the pinned seed")
        return Finding(True, "swapped and repeated hint indices rejected by verify", units, "verifier hint strict-order probes")


@register
class VerifyHintTailZero(SigRelation):
    id = "mldsa-verify-hint-tail-zero"
    property = "verify rejects a signature with non-zero bytes in unused hint-index slots"
    ceiling = "does not establish hint handling beyond the zero tail in the verifier"
    requires = frozenset({Capability.SIG, Capability.DETACHED_SIG, Capability.MLDSA_HINT_ENCODING})

    def check(self, target, rng):
        found = _find_hinted_sig(target, rng, need=1)
        if found is None:
            return Finding(None, "no honest signature with a hint row found in 8 tries", 0, "verify hint tail")
        pk, msg, sig, _positions, _values, tail = found
        if not tail:
            return Finding(None, "all hint-index slots are used; no tail to probe", 0, "verify hint tail")
        units = 0
        bad = []
        for pos in tail[:8]:
            mutated = bytearray(sig)
            mutated[pos] = 0x7F
            units += 1
            if ok(target.verify(pk, msg, bytes(mutated))):
                bad.append(pos)
        if bad:
            return Finding(False, f"verify accepted non-zero unused hint bytes at positions {bad[:4]}", units, "verifier hint tail-zero probes", reproduce="re-run pqcheck mldsa-verify-hint-tail-zero with the pinned seed")
        return Finding(True, "non-zero unused hint bytes rejected by verify", units, "verifier hint tail-zero probes")
