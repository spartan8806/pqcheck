#!/usr/bin/env python3
"""Standalone Python line-protocol harness for pqcheck.

Speaks the universal pqcheck stdin/stdout line protocol so ANY Python
PQC library can be driven without a C binary:

    info                 -> OK kind=kem alg=<name> pk=.. sk=.. ct=.. ss=..
    keygen <seed|->      -> OK <ek-hex> <dk-hex>      (kem)
                         -> OK <pk-hex> <sk-hex>      (sig)
    encaps <ek>          -> OK <ss-hex> <ct-hex>
    decaps <dk> <ct>     -> OK <ss-hex>
    sign <sk> <msg>      -> OK <sig-hex>
    verify <pk> <msg> <sig> -> OK | REJ <reason>
    guard <hex|->        -> OK

Replies are exactly one line: OK / REJ / ERR. Hex is exact-length
validated; over-long input lines are refused with ERR.

This file is a TEMPLATE: the "library" below is a tiny hash-based toy
so the protocol can be executed and tested anywhere. Replace the
sections marked ADAPT with calls into the real library.

Usage:  python_harness.py <kem|sig> <algorithm>
The algorithm may carry a planted-mutant suffix for testing, e.g.
    python_harness.py kem "WireKem[no_reencryption_check]"
"""
import hashlib
import sys

MAX_LINE = 1_000_000


def H(label, *parts, out=32):
    x = hashlib.shake_256()
    x.update(label)
    for p in parts:
        x.update(len(p).to_bytes(8, "big"))
        x.update(p)
    return x.digest(out)


def unhex(text):
    if text == "-":
        return None
    if len(text) % 2 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise ValueError("bad hex")
    return bytes.fromhex(text)


class WireKem:
    """ADAPT: replace keygen/encaps/decaps bodies with the real KEM."""

    sizes = {"pk": 32, "sk": 96, "ct": 32, "ss": 32}

    def __init__(self, mutant=None):
        self.mutant = mutant
        self._last = None
        self._ctr = 0

    def keygen(self, seed):
        seed = seed or b"wire-kem-default-seed"
        ek = H(b"ek", seed)
        dk = ek + hashlib.sha3_256(ek).digest() + H(b"z", seed)
        return ek, dk

    def encaps(self, ek):
        self._ctr += 1
        ct = H(b"ct", ek, self._ctr.to_bytes(8, "big"))
        ss = H(b"ss", ek, ct)
        self._last = (ct, ss)
        return ss, ct

    def decaps(self, dk, ct):
        ek, hh, z = dk[:32], dk[32:64], dk[64:96]
        if self.mutant == "no_reencryption_check" and self._last is not None:
            last_ct, last_ss = self._last
            if len(ct) == len(last_ct) and sum(
                    bin(a ^ b).count("1") for a, b in zip(ct, last_ct)) <= 2:
                return last_ss
        if hh != hashlib.sha3_256(ek).digest():
            return H(b"rej", z, ct)
        return H(b"ss", ek, ct)


class WireSig:
    """ADAPT: replace keygen/sign/verify bodies with the real scheme."""

    sizes = {"pk": 32, "sk": 32, "sig": 64}

    def __init__(self, mutant=None):
        self.mutant = mutant

    def keygen(self, seed):
        seed = seed or b"wire-sig-default-seed"
        sk = H(b"sk", seed)
        return H(b"pk", sk), sk

    def sign(self, sk, msg):
        return H(b"sig", H(b"pk", sk), msg, out=64)

    def verify(self, pk, msg, sig):
        expected = H(b"sig", pk, msg, out=64)
        if self.mutant == "verify_ignores_slack":
            return sig[:63] == expected[:63]
        return sig == expected


def parse_algorithm(token):
    if token.endswith("]") and "[" in token:
        name, mutant = token[:-1].split("[", 1)
        return name, mutant
    return token, None


def main(argv):
    if len(argv) < 3:
        print("ERR usage: python_harness.py <kem|sig> <algorithm>")
        return 1
    kind, token = argv[1].lower(), argv[2]
    _name, mutant = parse_algorithm(token)
    impl = WireKem(mutant) if kind == "kem" else WireSig(mutant)
    for line in sys.stdin:
        if len(line) > MAX_LINE:
            print("ERR line exceeds this harness's input buffer", flush=True)
            continue
        parts = line.split()
        if not parts:
            continue
        verb, args = parts[0], parts[1:]
        try:
            if verb == "info":
                s = impl.sizes
                if kind == "kem":
                    print(f"OK kind=kem alg={token} pk={s['pk']} sk={s['sk']} "
                          f"ct={s['ct']} ss={s['ss']}", flush=True)
                else:
                    print(f"OK kind=sig alg={token} pk={s['pk']} sk={s['sk']} "
                          f"sig={s['sig']}", flush=True)
            elif verb == "keygen":
                a, b = impl.keygen(unhex(args[0]) if args else None)
                print(f"OK {a.hex()} {b.hex()}", flush=True)
            elif verb == "encaps":
                ss, ct = impl.encaps(unhex(args[0]))
                print(f"OK {ss.hex()} {ct.hex()}", flush=True)
            elif verb == "decaps":
                ss = impl.decaps(unhex(args[0]), unhex(args[1]))
                print(f"OK {ss.hex()}", flush=True)
            elif verb == "sign":
                sig = impl.sign(unhex(args[0]), unhex(args[1]) or b"")
                print(f"OK {sig.hex()}", flush=True)
            elif verb == "verify":
                ok = impl.verify(unhex(args[0]), unhex(args[1]) or b"",
                                 unhex(args[2]))
                print("OK" if ok else "REJ signature mismatch", flush=True)
            elif verb == "guard":
                print("OK", flush=True)
            else:
                print(f"ERR unknown verb {verb}", flush=True)
        except (ValueError, IndexError) as exc:
            print(f"ERR {exc}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
