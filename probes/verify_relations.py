"""Standing probe: a clean toy passes and a planted mutant is caught."""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pqcheck.relations.base import REGISTRY
from pqcheck.testing.toy import ToyKem, ToySig
from pqcheck.verdict import Subject, Verdict

S = Subject(target="probe", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")
clean = REGISTRY["core-kem-round-trip"].run(ToyKem(), S, random.Random("probe-clean"))
assert clean.verdict is Verdict.NO_DEFECT_FOUND, clean
mutant = REGISTRY["core-kem-round-trip"].run(ToyKem(mutant="decaps_returns_wrong_secret"), S, random.Random("probe-mutant"))
assert mutant.verdict is Verdict.DEFECT_FOUND, mutant
sig = REGISTRY["sig-wrong-key-rejection"].run(ToySig(), S, random.Random("probe-sig"))
assert sig.verdict is Verdict.NO_DEFECT_FOUND, sig
print("PASS: clean toy passes, planted mutant is caught")
