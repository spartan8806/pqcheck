"""Acceptance suite: precision, mutant liveness, recall, seed gate."""
from __future__ import annotations

import random
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pqcheck.relations  # noqa: F401  (populates REGISTRY)
from pqcheck.relations.base import REGISTRY
from pqcheck.target import Capability, Status
from pqcheck.testing import (
    CODEC_MUTANTS, FALCON_MUTANTS, KEM_MUTANTS, LWE_MUTANTS, MLDSA_MUTANTS,
    PACKED_EK_MUTANTS, SIG_MUTANTS, PackedEkKem, ToyCodec, ToyFalconSig,
    ToyKem, ToyLweKem, ToyMldsaSig, ToySig, ToyStreamCodec,
)
from pqcheck.testing.precision import PRECISION_TARGETS
from pqcheck.verdict import Report, Subject, Verdict

COMMIT = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"

CLEAN_TARGETS = [
    ("ToyKem", ToyKem), ("ToySig", ToySig), ("ToyCodec", ToyCodec),
    ("ToyLweKem", ToyLweKem), ("PackedEkKem", PackedEkKem),
    ("ToyFalconSig", ToyFalconSig), ("ToyMldsaSig", ToyMldsaSig),
]

ALL_MUTANTS = []
for _table in (KEM_MUTANTS, SIG_MUTANTS, CODEC_MUTANTS, LWE_MUTANTS, PACKED_EK_MUTANTS, FALCON_MUTANTS, MLDSA_MUTANTS):
    ALL_MUTANTS.extend(_table.items())


def _subject(name):
    return Subject(target=name, commit=COMMIT)


def run_all(target, seed="pqcheck-selftest"):
    claims = []
    for rid, relation in sorted(REGISTRY.items()):
        claims.append(relation.run(target, _subject(getattr(target, "name", type(target).__name__)), random.Random(f"{seed}:{rid}")))
    return claims


def defects(claims):
    return [c for c in claims if c.verdict is Verdict.DEFECT_FOUND]


def _status_value(out):
    if getattr(out, "status", None) is None:
        return ("none", None)
    return (out.status.value, out.value if out.status is Status.OK else out.detail)


def probe_behaviour(target):
    """Behavioural fingerprint used only to prove a mutant is live."""
    obs: list = [repr(getattr(target, "sizes", None)), repr(getattr(target, "fixed_sig_len", None))]
    caps = set(getattr(target, "caps", frozenset()))
    if Capability.KEM in caps:
        kg = target.keygen(b"liveness-seed")
        obs.append(_status_value(kg))
        if kg.ok:
            ek, dk = kg.value
            enc = target.encaps(ek, b"\x42" * 32)
            obs.append(_status_value(enc))
            if enc.ok:
                ss, ct = enc.value
                obs.append(_status_value(target.decaps(dk, ct)))
                flipped = bytes([ct[0] ^ 1]) + ct[1:]
                obs.append(_status_value(target.decaps(dk, flipped)))
                obs.append(_status_value(target.decaps(dk, flipped)))
                obs.append(_status_value(target.decaps(dk, b"\x00" * len(ct))))
                obs.append(_status_value(target.decaps(dk, ct[:-1])))
                bad_dk = dk[:-33] + bytes([dk[-33] ^ 1]) + dk[-32:]
                obs.append(_status_value(target.decaps(bad_dk, ct)))
                try:
                    target.guard(b"\xff" * 64)
                    obs.append(_status_value(target.decaps(dk, flipped)))
                    obs.append(_status_value(target.encaps(ek, ct)))
                    target.guard(None)
                except Exception as exc:
                    obs.append(("guard-exc", type(exc).__name__))
                packing = getattr(target, "ek_packing", None)
                if packing:
                    from pqcheck.relations.kem_encoding import _pack12, _unpack12
                    coeffs = _unpack12(ek, packing["n"] * packing["k"])
                    for i, c in enumerate(coeffs):
                        if c + packing["q"] <= 4095:
                            bumped = list(coeffs); bumped[i] = c + packing["q"]
                            obs.append(_status_value(target.encaps(_pack12(bumped))))
                            break
    if Capability.SIG in caps:
        kg = target.keygen(b"liveness-seed")
        obs.append(_status_value(kg))
        if kg.ok:
            pk, sk = kg.value
            for msg in (b"", b"a", b"x" * 136, b"y" * 40):
                try:
                    s = target.sign(sk, msg)
                except TypeError:
                    s = target.sign(sk, msg)
                obs.append(_status_value(s))
                if s.ok:
                    obs.append(_status_value(target.verify(pk, msg, s.value)))
                    obs.append(_status_value(target.verify(pk, msg + b"!", s.value)))
                    obs.append(_status_value(target.verify(pk, msg, b"\x00" * len(s.value))))
                    bad = s.value[:-1] + bytes([s.value[-1] ^ 1])
                    obs.append(_status_value(target.verify(pk, msg, bad)))
                    obs.append(_status_value(target.verify(pk, msg, s.value + b"\x00")))
                    # sweep every bit of one short signature (catches unread bits / -0)
                    if msg == b"a":
                        for pos in range(len(s.value) * 8):
                            mutated = bytearray(s.value)
                            mutated[pos // 8] ^= 1 << (pos % 8)
                            if target.verify(pk, msg, bytes(mutated)).ok:
                                obs.append(("accepted-bitflip", pos))
            # long-message liveness: truncation mutants only differ
            # past their cutoff, so probe beyond 8192 bytes
            long_msg = bytes((i * 7) % 256 for i in range(9000))
            s_long = target.sign(sk, long_msg)
            obs.append(_status_value(s_long))
            if s_long.ok:
                obs.append(_status_value(target.verify(pk, long_msg, s_long.value)))
                altered = bytearray(long_msg); altered[8500] ^= 1
                obs.append(_status_value(target.verify(pk, bytes(altered), s_long.value)))
            try:
                s = target.sign(sk, b"ctx probe", ctx=b"a")
                if s.ok:
                    obs.append(_status_value(target.verify(pk, b"ctx probe", s.value, ctx=b"b")))
            except TypeError:
                pass
            try:
                s0 = target.sign(sk, b"mode probe", prehash=False)
                s1 = target.sign(sk, b"mode probe", prehash=True)
                if s0.ok and s1.ok:
                    obs.append(_status_value(target.verify(pk, b"mode probe", s0.value, prehash=True)))
            except TypeError:
                pass
            try:
                obs.append(_status_value(target.sign(sk, b"z" * 32, declared_len=32 + 65536)))
                obs.append(_status_value(target.sign(sk, b"z" * 32, declared_len=32 + (1 << 32))))
            except TypeError:
                pass
            try:
                target.guard(b"\xff" * 64)
                s = target.sign(sk, b"guard probe")
                if s.ok:
                    bad = s.value[:-1] + bytes([s.value[-1] ^ 1])
                    obs.append(_status_value(target.verify(pk, b"guard probe", bad)))
                target.guard(None)
            except Exception as exc:
                obs.append(("guard-exc", type(exc).__name__))
            g = getattr(target, "mldsa_hint", None)
            if g:
                s = target.sign(sk, b"hint probe")
                if s.ok:
                    sig = s.value
                    main = g["ctilde"] + g["z"]; omega = g["omega"]
                    mutated = bytearray(sig); mutated[main] = 0x7F
                    obs.append(_status_value(target.verify(pk, b"hint probe", bytes(mutated))))
                    mutated2 = bytearray(sig); mutated2[main], mutated2[main + 1] = mutated2[main + 1], mutated2[main]
                    obs.append(_status_value(target.verify(pk, b"hint probe", bytes(mutated2))))
    if Capability.RAW_DECODE in caps:
        for v in ((0,) * 8, (0, 1, -1, 2, -2, 3, -3, 0), (64, -64, 64, -64, 64, -64, 64, -64)):
            enc = target.encode(v)
            obs.append(_status_value(enc))
            if enc.ok:
                obs.append(_status_value(target.decode(enc.value)))
                obs.append(_status_value(target.decode(enc.value[:-1])))
                obs.append(_status_value(target.decode(enc.value + b"\x00")))
        if getattr(target, "codec_kind", None) == "sign_magnitude_unary":
            # constructed canonicality probes: signed zero and set pad bits
            zero_enc = target.encode((0,) * 8)
            if zero_enc.ok:
                probe = bytearray(zero_enc.value); probe[0] ^= 0x80
                obs.append(_status_value(target.decode(bytes(probe))))
            pad_enc = target.encode((1, -1, 1, 0, 0, 0, 0, 0))
            if pad_enc.ok:
                probe = bytearray(pad_enc.value); probe[-1] ^= 0x01
                obs.append(_status_value(target.decode(bytes(probe))))
        if hasattr(target, "decode_hints"):
            enc = target.encode_hints([[1, 3], [5]])
            obs.append(_status_value(enc))
            if enc.ok:
                raw = bytearray(enc.value); raw[0], raw[1] = 1, 1
                obs.append(_status_value(target.decode_hints(bytes(raw))))
                raw2 = bytearray(enc.value); raw2[3] = 0x7F
                obs.append(_status_value(target.decode_hints(bytes(raw2))))
                # a non-increasing second row (catches row-0-only checks)
                enc2 = target.encode_hints([[1, 3], [1, 3]])
                if enc2.ok:
                    om = getattr(target, "omega", 8)
                    raw3 = bytearray(enc2.value); raw3[om], raw3[om + 1] = 1, 1
                    obs.append(_status_value(target.decode_hints(bytes(raw3))))
    return repr(obs)


def _differs_from_clean(clean_factory, mutant_factory, clean_name):
    clean = probe_behaviour(clean_factory())
    mutant = probe_behaviour(mutant_factory())
    return clean != mutant


CLEAN_BY_MUTANT = {}
for _n, _f in KEM_MUTANTS.items():
    CLEAN_BY_MUTANT[("kem", _n)] = ToyKem
for _n, _f in SIG_MUTANTS.items():
    CLEAN_BY_MUTANT[("sig", _n)] = ToySig
for _n, _f in CODEC_MUTANTS.items():
    CLEAN_BY_MUTANT[("codec", _n)] = ToyStreamCodec
for _n, _f in LWE_MUTANTS.items():
    CLEAN_BY_MUTANT[("lwe", _n)] = ToyLweKem
for _n, _f in PACKED_EK_MUTANTS.items():
    CLEAN_BY_MUTANT[("packed", _n)] = PackedEkKem
for _n, _f in FALCON_MUTANTS.items():
    CLEAN_BY_MUTANT[("falcon", _n)] = ToyFalconSig
for _n, _f in MLDSA_MUTANTS.items():
    CLEAN_BY_MUTANT[("mldsa", _n)] = ToyMldsaSig

MUTANT_GROUPS = [
    ("kem", KEM_MUTANTS, ToyKem), ("sig", SIG_MUTANTS, ToySig),
    ("codec", CODEC_MUTANTS, ToyStreamCodec), ("lwe", LWE_MUTANTS, ToyLweKem),
    ("packed", PACKED_EK_MUTANTS, PackedEkKem), ("falcon", FALCON_MUTANTS, ToyFalconSig),
    ("mldsa", MLDSA_MUTANTS, ToyMldsaSig),
]


def seed_discrimination_gate() -> list[str]:
    failures = []
    from pqcheck.relations.malleability import UnreadBits
    degraded_cls = type("UnreadBitsOneSig", (UnreadBits,), {"n_signatures": 1})
    for seed in ("pqcheck-recall-gate-8", "pqcheck-recall-gate-11"):
        target = ToyFalconSig(mutant="accepts_minus_zero")
        claim = REGISTRY["sig-unread-bits"].run(target, _subject("ToyFalconSig"), random.Random(seed))
        if claim.verdict is not Verdict.DEFECT_FOUND:
            failures.append(f"{seed}: n_signatures=8 did not catch accepts_minus_zero (got {claim.verdict.value})")
        target1 = ToyFalconSig(mutant="accepts_minus_zero")
        claim1 = degraded_cls().run(target1, _subject("ToyFalconSig"), random.Random(seed))
        if claim1.verdict is Verdict.DEFECT_FOUND:
            failures.append(f"{seed}: n_signatures=1 unexpectedly caught accepts_minus_zero")
    return failures


def run_once(seed: str = "pqcheck-selftest") -> list[str]:
    """One full precision/liveness/recall sweep under one seed."""
    failures: list[str] = []
    total_defect_claims = 0
    for name, factory in CLEAN_TARGETS:
        claims = run_all(factory(), seed=seed)
        bad = defects(claims)
        total_defect_claims += len(bad)
        for c in bad:
            failures.append(f"precision: clean {name} got DEFECT from {c.method.name}: {c.evidence}")
        for c in claims:
            if c.verdict is Verdict.NOT_REACHED:
                failures.append(f"precision: clean {name} got NOT_REACHED from {c.method.name}: {c.evidence} {c.notes}")
    for name, factory in PRECISION_TARGETS:
        claims = run_all(factory(), seed=seed)
        for c in defects(claims):
            failures.append(f"precision fixture {name} got DEFECT from {c.method.name}: {c.evidence}")
    fired: dict[str, list[str]] = {rid: [] for rid in REGISTRY}
    for group, table, clean_factory in MUTANT_GROUPS:
        for mutant_name, factory in table.items():
            if not _differs_from_clean(clean_factory, factory, mutant_name):
                failures.append(f"mutant inert: {group}/{mutant_name} does not differ from clean")
                continue
            claims = run_all(factory(), seed=seed)
            caught = defects(claims)
            if not caught:
                failures.append(f"mutant uncaught: {group}/{mutant_name}")
            for c in caught:
                fired[c.method.name].append(f"{group}/{mutant_name}")
    for rid, where in sorted(fired.items()):
        if not where:
            failures.append(f"recall: relation {rid} never fired on any mutant")
    failures.extend(seed_discrimination_gate())
    recall = sum(1 for v in fired.values() if v)
    if recall != len(fired):
        pass  # already recorded per-relation above
    print(f"[{seed}] relations with recall: {recall}/{len(fired)}")
    return failures


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="pqcheck-selftest")
    parser.add_argument("--seeds", type=int, default=1,
                        help="sweep N deterministic seeds (default 1: b'pqcheck-selftest')")
    args = parser.parse_args(argv)
    if args.seeds < 1:
        print("--seeds must be >= 1")
        return 1
    seeds = ["pqcheck-selftest"] if args.seeds == 1 else [
        f"pqcheck-selftest-{i}" for i in range(args.seeds)]
    print(f"relations registered: {len(REGISTRY)}")
    print(f"mutants checked: {sum(len(t) for _g, t, _c in MUTANT_GROUPS)}")
    all_failures: list[str] = []
    for seed in seeds:
        failures = run_once(seed)
        for f in failures:
            all_failures.append(f"[{seed}] {f}")
        print(f"[{seed}] {'ok' if not failures else f'{len(failures)} failure(s)'}")
    if all_failures:
        print(f"SELFTEST FAILED ({len(all_failures)}):")
        for f in all_failures:
            print(" -", f)
        return 1
    if len(seeds) > 1:
        print(f"selftest: ok ({len(seeds)} seeds, 0 false positives, "
              "all mutants live and caught on every seed, seed gate holds)")
    else:
        print("selftest: ok (0 false positives, all mutants live and caught, seed gate holds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
