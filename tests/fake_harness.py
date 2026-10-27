"""Fake line-protocol harness used to test the Python bridges without a C compiler."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqcheck.testing.toy import ToyKem, ToySig
from pqcheck.testing.toycodec import ToyCodec

kind = sys.argv[1] if len(sys.argv) > 1 else "kem"
alg = sys.argv[2] if len(sys.argv) > 2 else "fake"
kem, sig, codec = ToyKem(), ToySig(), ToyCodec()


def hx(b):
    return "-" if not b else bytes(b).hex()


def un(s):
    return b"" if s == "-" else bytes.fromhex(s)


for line in sys.stdin:
    parts = line.split()
    if not parts:
        continue
    cmd = parts[0]
    if cmd == "info":
        if kind == "kem":
            print("OK kind=kem alg=%s pk=32 sk=96 ct=32 ss=32 guard=1" % alg, flush=True)
        elif kind == "codec":
            print("OK kind=codec ncoef=8 sig=16 fixed=1", flush=True)
        elif kind == "hint":
            print("OK kind=hint omega=8 k=4", flush=True)
        else:
            print("OK kind=sig alg=%s pk=32 sk=32 sig=64 guard=1" % alg, flush=True)
    elif cmd == "keygen":
        t = kem if kind == "kem" else sig
        out = t.keygen(un(parts[1]) if len(parts) > 1 else None)
        print("OK %s %s" % (hx(out.value[0]), hx(out.value[1])), flush=True)
    elif cmd == "encaps":
        out = kem.encaps(un(parts[1]))
        print("OK %s %s" % (hx(out.value[0]), hx(out.value[1])) if out.ok else "REJ refused", flush=True)
    elif cmd == "decaps":
        out = kem.decaps(un(parts[1]), un(parts[2]))
        print("OK %s" % hx(out.value) if out.ok else "REJ refused", flush=True)
    elif cmd == "sign":
        out = sig.sign(un(parts[1]), un(parts[2]))
        print("OK %s" % hx(out.value) if out.ok else "REJ refused", flush=True)
    elif cmd == "verify":
        out = sig.verify(un(parts[1]), un(parts[2]), un(parts[3]))
        print("OK" if out.ok else "REJ refused", flush=True)
    elif cmd == "guard":
        print("OK guard=%d" % (0 if parts[1] == "-" else len(un(parts[1]))), flush=True)
    elif cmd == "encode":
        out = codec.encode([int(x) for x in parts[1:]])
        print("OK %s" % hx(out.value), flush=True)
    elif cmd == "decode":
        out = codec.decode(un(parts[1]))
        print("OK %s" % hx(out.value) if out.ok else "REJ refused", flush=True)
    elif cmd == "encode_hints":
        out = codec.encode_hints([[int(x) for x in row.split(",") if x] for row in parts[1].split(";")])
        print("OK %s" % hx(out.value), flush=True)
    elif cmd == "decode_hints":
        out = codec.decode_hints(un(parts[1]))
        print("OK %s" % hx(out.value) if out.ok else "REJ refused", flush=True)
    else:
        print("ERR unknown command", flush=True)
