"""Standing probe: verdict engine honesty gates still hold."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqcheck.verdict import Claim, ClaimError, Coverage, Method, Report, Subject, Verdict

s = Subject(target="probe", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")
m = Method(name="probe", oracle=None)
try:
    Claim(subject=s, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=m, ceiling="c")
    print("FAIL: NO_DEFECT_FOUND without coverage was constructed")
    raise SystemExit(1)
except ClaimError:
    pass
clean = Claim(subject=s, property="p", verdict=Verdict.NO_DEFECT_FOUND, method=m, ceiling="c", coverage=Coverage("surface", 3))
assert Report((clean,)).exit_code() == 0
try:
    Report((clean,)).score()
    print("FAIL: score() did not raise")
    raise SystemExit(1)
except NotImplementedError:
    pass
print("PASS: verdict honesty gates hold")
