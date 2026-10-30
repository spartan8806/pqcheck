#!/usr/bin/env python3
"""No secret-shaped material (dk/sk/ss/forgeries) may enter a Claim."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.verdict import Claim, ClaimError, Method, Verdict, redact_target_output  # noqa: E402

M = Method(name="probe", oracle=None)
HEX64 = "ab" * 32
B64 = "Ab3dEf6hIjKlMnOpQrStUvWxYz0123456789abcd"

for field, kwargs in (
    ("evidence", {"evidence": HEX64}),
    ("notes", {"notes": f"shared secret was {HEX64}"}),
    ("premises", {"premises": (HEX64,)}),
    ("evidence-b64", {"evidence": B64}),
):
    try:
        fields = {"notes": "n"}
        fields.update(kwargs)
        Claim(subject=SUBJ, property="p", verdict=Verdict.NOT_REACHED, method=M,
              ceiling="c", **fields)
        check(False, f"Claim accepted secret-shaped material in {field}")
    except ClaimError:
        pass
try:
    Claim(subject=SUBJ, property="p", verdict=Verdict.DEFECT_FOUND, method=M,
          ceiling="c", reproduce="run the relation and print " + HEX64 + " verbatim")
    check(False, "Claim accepted secret-shaped material in reproduce")
except ClaimError:
    pass
redacted = redact_target_output(f"target stderr {HEX64}")
check(HEX64 not in redacted, "redact_target_output left a hex blob intact")
print("claim fields refuse hex/base64 secret-shaped blobs; target output is redacted")
passed("no key material in claims")
