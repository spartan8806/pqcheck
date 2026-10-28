"""Revision-reporting fake harness for runtime revision-binding tests.

Speaks the C/exec line protocol for a KEM whose behaviour depends on
the revision it claims to be: PQCHECK_FAKE_REV=<vuln commit> behaves
like the FO-defective build, any other reported revision behaves
clean. PQCHECK_FAKE_REV=none makes it report no revision at all.
The revision is reported as rev= in the info line, exactly like the
enc_rust harness stamps ENC_RUST_REVISION.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqcheck.testing.toy import ToyKem

VULN = "121385c2c9bab5ab509104b3e7b13259fc8a4080"
REV = os.environ.get("PQCHECK_FAKE_REV", "")
kem = ToyKem(mutant="no_reencryption_check") if REV == VULN else ToyKem()
alg = sys.argv[2] if len(sys.argv) > 2 else "fake"


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
        rev = "" if REV == "none" else f" rev={REV}"
        print(f"OK kind=kem alg={alg} pk=32 sk=96 ct=32 ss=32 guard=1{rev}", flush=True)
    elif cmd == "keygen":
        out = kem.keygen(un(parts[1]) if len(parts) > 1 else None)
        print("OK %s %s" % (hx(out.value[0]), hx(out.value[1])), flush=True)
    elif cmd == "encaps":
        out = kem.encaps(un(parts[1]))
        print("OK %s %s" % (hx(out.value[0]), hx(out.value[1])) if out.ok else "REJ refused", flush=True)
    elif cmd == "decaps":
        out = kem.decaps(un(parts[1]), un(parts[2]))
        print("OK %s" % hx(out.value) if out.ok else "REJ refused", flush=True)
    elif cmd == "guard":
        print("OK", flush=True)
    else:
        print("ERR unknown command", flush=True)
