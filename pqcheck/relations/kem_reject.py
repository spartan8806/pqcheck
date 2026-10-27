"""Fujisaki-Okamoto implicit-rejection relations."""
from __future__ import annotations

from pqcheck.relations._common import KemRelation, flip, kem_baseline, ok, pair, rej
from pqcheck.relations.base import Finding, register
from pqcheck.target import Capability


def _bad_ss(target, dk, ct):
    out = target.decaps(dk, ct)
    return out.value if ok(out) else None



@register
class CtBitContribution(KemRelation):
    id = "kem-reject-ct-bit-contribution"
    property = "every probed ciphertext byte/bit contributes to the implicit-rejection secret"
    ceiling = "does not establish that the rejection secret is indistinguishable from random"

    def check(self, target, rng):
        base = kem_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "ct bit contribution")
        ek, dk, ss, ct = base
        offsets = sorted({0, 1, len(ct) // 3, len(ct) // 2, len(ct) - 2, len(ct) - 1, 7 % len(ct)})
        seen: set[bytes] = set()
        bad_offsets = []
        units = 0
        comparable = 0
        rejected = 0
        for off in offsets:
            vals = set()
            for bit in (0, 3, 7):
                out = target.decaps(dk, flip(ct, off, 1 << bit))
                units += 1
                if not ok(out):
                    rejected += 1
                    continue
                v = out.value
                if v is not None and v != ss:
                    comparable += 1
                    vals.add(v); seen.add(v)
            if len(vals) < 2:
                bad_offsets.append(off)
        if rejected:
            return Finding(None, "target explicitly rejects corrupted ciphertexts; no implicit-rejection secret to compare", units, "ct bit contribution")
        if comparable < 2:
            return Finding(None, "fewer than 2 comparable rejection values", units, "ct bit contribution")
        if bad_offsets or len(seen) <= 1:
            return Finding(False, f"byte offsets {bad_offsets} do not contribute across bit flips", units, "ct bit-flip contribution to rejection secret", reproduce="re-run pqcheck kem-reject-ct-bit-contribution with the pinned seed")
        return Finding(True, "rejection secret varies per byte offset and bit", units, "ct bit-flip contribution to rejection secret")


@register
class BindsFullCt(KemRelation):
    id = "kem-reject-binds-full-ciphertext"
    property = "the implicit-rejection secret binds the full ciphertext, every byte"
    ceiling = "does not establish FO security against chosen-ciphertext attacks beyond binding"

    def check(self, target, rng):
        base = kem_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "full ct binding")
        ek, dk, ss, ct = base
        units = 0
        unbound = []
        per_byte: dict[int, bytes] = {}
        collisions = []
        rejected = 0
        for off in range(len(ct)):
            vals = []
            for mask in (0x01, 0x02):
                out = target.decaps(dk, flip(ct, off, mask))
                units += 1
                if not ok(out):
                    rejected += 1
                    vals.append(None)
                    continue
                vals.append(out.value)
            if vals[0] is not None and vals[0] == vals[1]:
                unbound.append(off)
            if vals[0] is not None:
                if vals[0] in per_byte.values():
                    collisions.append(off)
                per_byte[off] = vals[0]
        if rejected:
            return Finding(None, "target explicitly rejects corrupted ciphertexts; no implicit-rejection secret to compare", units, "full ct binding")
        if unbound:
            contiguous = len(unbound) > 2 and unbound == list(range(unbound[0], unbound[-1] + 1))
            kind = "contiguous truncated absorb" if contiguous else "scattered unbound bytes (plaintext-checking-oracle leak shape)"
            return Finding(False, f"bytes {unbound[:8]} do not bind the rejection secret ({kind})", units, "full-ciphertext binding sweep, 2 masks per byte", reproduce="re-run pqcheck kem-reject-binds-full-ciphertext with the pinned seed")
        return Finding(True, "every ciphertext byte binds the rejection secret under both masks", units, "full-ciphertext binding sweep, 2 masks per byte")


@register
class BindsZ(KemRelation):
    id = "kem-reject-binds-z-accept-path-does-not"
    property = "implicit rejection binds the decapsulation key's secret z; different keys reject differently"
    ceiling = "does not establish that the honest path is key-independent"

    def check(self, target, rng):
        kg1 = pair(target.keygen(rng.randbytes(16)))
        kg2 = pair(target.keygen(rng.randbytes(16) + b"\x01"))
        if kg1 is None or kg2 is None:
            return Finding(None, "keygen failed", 0, "z binding")
        ek1, dk1 = kg1; ek2, dk2 = kg2
        if ek1 == ek2 or dk1 == dk2:
            return Finding(None, "independent keygens collided; cannot attribute to z", 0, "z binding")
        enc = pair(target.encaps(ek1))
        if enc is None:
            return Finding(None, "encaps failed", 0, "z binding")
        ss, ct = enc
        units = 0
        same = 0
        for off in (0, len(ct) // 2, len(ct) - 1, 3 % len(ct)):
            bad = flip(ct, off, 0x01)
            a, b = _bad_ss(target, dk1, bad), _bad_ss(target, dk2, bad)
            units += 1
            if a is None or b is None:
                return Finding(None, "target explicitly rejects corrupted ciphertexts; no implicit-rejection secret to compare", units, "z binding")
            if a == b:
                same += 1
        if same:
            return Finding(False, f"rejection secret is key-independent at {same} corrupted positions", units, "cross-key rejection comparison", reproduce="re-run pqcheck kem-reject-binds-z-accept-path-does-not with the pinned seed")
        return Finding(True, "rejection secrets differ across keys", units, "cross-key rejection comparison")


@register
class RejectDeterminism(KemRelation):
    id = "kem-reject-determinism"
    property = "implicit rejection is deterministic for a fixed key and ciphertext"
    ceiling = "does not establish constant-time behaviour"

    def check(self, target, rng):
        base = kem_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "reject determinism")
        ek, dk, ss, ct = base
        bad = flip(ct, 0, 0x01)
        units = 0
        for _ in range(8):
            a, b = _bad_ss(target, dk, bad), _bad_ss(target, dk, bad)
            units += 2
            if a is None and b is None:
                return Finding(None, "target explicitly rejects corrupted ciphertexts; no implicit-rejection secret to compare", units, "reject determinism")
            if a is None or a != b:
                return Finding(False, "repeated decapsulation of one corrupted ciphertext gave different secrets", units, "rejection determinism, 8 pairs", reproduce="re-run pqcheck kem-reject-determinism with the pinned seed")
        return Finding(True, "rejection deterministic across 8 pairs", units, "rejection determinism, 8 pairs")


@register
class FoLiveness(KemRelation):
    id = "kem-fo-liveness"
    property = "no corrupted ciphertext decapsulates to the honest secret (FO transform is live)"
    ceiling = "a witness search that finds nothing establishes nothing about FO correctness"
    one_sided = True
    false_positive_modes = (
        "declared encoding slack (reserved/padding ciphertext bytes) is real "
        "malleability, not a dead FO check; the evidence separates the two "
        "via per-byte leaking bit-masks and must not claim the check is absent",
    )

    def check(self, target, rng):
        base = kem_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "FO liveness")
        ek, dk, ss, ct = base
        units = 0
        witnesses: list[int] = []
        swept = 0
        for off in range(len(ct)):
            for bit in (0, 1, 7):
                swept += 1
                v = _bad_ss(target, dk, flip(ct, off, 1 << bit))
                units += 1
                if v is not None and v == ss:
                    witnesses.append(off)
            if len(witnesses) > 4 and swept - len(witnesses) > 0:
                break
        if witnesses:
            shapes = {witnesses.count(w) for w in set(witnesses)}
            note = "witness bytes: " + ",".join(str(w) for w in witnesses[:8])
            return Finding(False, f"corrupted ciphertext returned the honest secret at bytes {witnesses[:8]} ({note})", units, "FO liveness witness search", reproduce="re-run pqcheck kem-fo-liveness with the pinned seed")
        return Finding(True, "no FO witness found in the swept bytes", units, "FO liveness witness search")


@register
class DegenerateCt(KemRelation):
    id = "kem-degenerate-ciphertext"
    property = "degenerate ciphertexts reject deterministically to distinct secrets, never the honest secret"
    ceiling = "does not cover all malformed ciphertext classes"

    def check(self, target, rng):
        base = kem_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "degenerate ct")
        ek, dk, ss, ct = base
        n = len(ct)
        probes = [b"\x00" * n, b"\xff" * n, b"\x00" * (n // 2) + ct[n // 2:], ct[:n // 2] + b"\x00" * (n - n // 2)]
        units = 0
        vals = []
        for p in probes:
            a, b = _bad_ss(target, dk, p), _bad_ss(target, dk, p)
            units += 2
            if a is None and b is None:
                return Finding(None, "target explicitly rejects degenerate ciphertexts; no implicit-rejection secret to compare", units, "degenerate ct")
            if a is None or a != b or a == ss:
                return Finding(False, "degenerate ciphertext was non-deterministic or returned the honest secret", units, "degenerate ciphertext probes", reproduce="re-run pqcheck kem-degenerate-ciphertext with the pinned seed")
            vals.append(a)
        if len(set(vals)) != len(vals):
            return Finding(False, "degenerate ciphertexts collide to one rejection secret", units, "degenerate ciphertext probes", reproduce="re-run pqcheck kem-degenerate-ciphertext with the pinned seed")
        return Finding(True, "degenerate ciphertexts reject deterministically and distinctly", units, "degenerate ciphertext probes")


@register
class DecapsLengthExact(KemRelation):
    id = "kem-decaps-length-exact"
    property = "decaps rejects ciphertexts of any length other than the exact ciphertext length"
    ceiling = "does not establish length handling on other inputs"
    requires = frozenset({Capability.KEM, Capability.EXPLICIT_SIG_LENGTH})

    def check(self, target, rng):
        base = kem_baseline(target)
        if base is None:
            return Finding(None, "baseline failed", 0, "decaps length")
        ek, dk, ss, ct = base
        probes = [ct[:-1], ct + b"\x00", ct[:len(ct) // 2], b"", ct + ct]
        units = 0
        accepted = []
        for p in probes:
            out = target.decaps(dk, p)
            units += 1
            if ok(out):
                accepted.append(len(p))
        if accepted:
            return Finding(False, f"decaps accepted ciphertext lengths {accepted}", units, "decaps exact-length probes", reproduce="re-run pqcheck kem-decaps-length-exact with the pinned seed")
        return Finding(True, "all 5 off-length ciphertexts rejected", units, "decaps exact-length probes")
