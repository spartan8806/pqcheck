#!/usr/bin/env python3
"""pqcheck line-protocol harness for the vulnerable-kem sample.

Speaks the exec/C-bridge protocol (info/keygen/encaps/decaps/guard)
against vulnkem.py in this folder. argv (kind, algorithm) appended
by pqcheck are accepted; the sample has exactly one algorithm.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vulnkem  # noqa: E402


def hx(b):
    return "-" if not b else bytes(b).hex()


def un(s):
    return b"" if s == "-" else bytes.fromhex(s)


for line in sys.stdin:
    parts = line.split()
    if not parts:
        continue
    cmd = parts[0]
    try:
        if cmd == "info":
            print("OK kind=kem alg=VULN-KEM-256 pk=32 sk=64 ct=48 ss=32", flush=True)
        elif cmd == "keygen":
            ek, dk = vulnkem.keygen(un(parts[1]) if len(parts) > 1 and parts[1] != "-" else None)
            print(f"OK {hx(ek)} {hx(dk)}", flush=True)
        elif cmd == "encaps":
            ss, ct = vulnkem.encaps(un(parts[1]))
            print(f"OK {hx(ss)} {hx(ct)}", flush=True)
        elif cmd == "decaps":
            print(f"OK {hx(vulnkem.decaps(un(parts[1]), un(parts[2])))}", flush=True)
        elif cmd == "guard":
            print("OK", flush=True)
        else:
            print("ERR unknown command", flush=True)
    except Exception as exc:  # library refusal shape
        print(f"REJ {exc}", flush=True)
