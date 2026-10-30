#!/usr/bin/env python3
"""README/docs quantitative claims are checked against the live code."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / 'README.md').is_file():
    print('SKIP: README/docs are source-checkout files, not shipped in the wheel')
    raise SystemExit(77)
readme = (ROOT / "README.md").read_text(encoding="utf-8")
docs_readme = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")

import pqcheck.relations  # noqa: E402,F401
from pqcheck.backtest.report import evaluate  # noqa: E402
from pqcheck.relations.base import REGISTRY  # noqa: E402
from pqcheck.testing import (  # noqa: E402
    CODEC_MUTANTS, FALCON_MUTANTS, KEM_MUTANTS, LWE_MUTANTS,
    MLDSA_MUTANTS, PACKED_EK_MUTANTS, SIG_MUTANTS,
)
from pqcheck.verdict import Report  # noqa: E402

NREL = len(REGISTRY)
check(NREL >= 32, f"expected at least 32 relations, got {NREL}")
check(f"{NREL} registered relations" in readme or f"{NREL} relations" in readme,
      f"README does not state the {NREL}-relation count")
print(f"{NREL} relations registered and stated")

groups = {
    "KEM": (KEM_MUTANTS, 10), "SIG": (SIG_MUTANTS, 17),
    "CODEC": (CODEC_MUTANTS, 8), "LWE": (LWE_MUTANTS, 3),
    "PACKED_EK": (PACKED_EK_MUTANTS, 2), "FALCON": (FALCON_MUTANTS, 1),
    "MLDSA": (MLDSA_MUTANTS, 2),
}
total = 0
for name, (table, want) in groups.items():
    check(len(table) == want, f"{name}_MUTANTS has {len(table)}, expected {want}")
    total += len(table)
check(total == 43, f"mutant total is {total}, expected 43")
check("43" in docs_readme, "docs index does not state the 43-mutant count")
print("43 mutants registered across the 7 canonical groups")

counts = evaluate()["counts"]
check(counts == {"DEMONSTRATED": 7, "ARGUED": 5, "PARTIAL": 4,
                 "MISSED": 2, "OUT_OF_SCOPE": 4}, f"backtest counts drifted: {counts}")
check("COVERED" not in counts, "a summed COVERED grade reappeared")
print("backtest per-grade counts match the docs (never summed)")

for token in ("DEFECT_FOUND", "NO_DEFECT_FOUND", "NOT_REACHED", "NOT_ANSWERABLE"):
    check(token in readme, f"README missing verdict {token}")
check("Report.score()" in readme, "README missing the no-score statement")
try:
    Report(()).score()
    check(False, "Report.score() did not refuse")
except NotImplementedError:
    print("no PASS, no score: verdict model claims hold")

pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
check("dependencies = []" in pyproject, "zero-dependency claim broken in pyproject.toml")
for name in ("noble.json", "pqclean.json", "liboqs.json"):
    check((ROOT / "manifests" / name).exists(), f"manifests/{name} missing")
    check(name in (ROOT / "docs" / "START.md").read_text(encoding="utf-8"),
          f"docs/START.md does not walk through {name}")
print("zero dependencies; shipped manifests present and walked through")

for name in ("START.md", "00_SPEC_pqc_assurance.md", "01_SPEC_relations.md",
             "02_VALIDATION.md", "03_RESOLVED_fo_liveness.md",
             "04_BACKTEST.md", "05_REVIEW_REGISTER.md", "06_LIMITATIONS.md",
             "REFERENCES.md"):
    check((ROOT / "docs" / name).exists(), f"docs/{name} missing")
print("full docs suite present")
passed("README claims")
