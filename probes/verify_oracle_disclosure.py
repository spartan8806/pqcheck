#!/usr/bin/env python3
"""The report discloses whether an independent oracle was used."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import SUBJ, check, passed  # noqa: E402

from pqcheck.verdict import Claim, Coverage, Method, Report, Verdict  # noqa: E402

with_oracle = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND,
                    method=Method("probe", "independent-reference-impl"), ceiling="c",
                    coverage=Coverage("surface", 1))
text = Report((with_oracle,)).to_text()
check("Independent oracle used: independent-reference-impl" in text,
      "report does not disclose its oracle")
print("oracle is named in the report footer when one was used")

without = Claim(subject=SUBJ, property="p", verdict=Verdict.NO_DEFECT_FOUND,
                method=Method("probe", None), ceiling="c", coverage=Coverage("surface", 1))
text = Report((without,)).to_text()
check("No independent oracle was used" in text, "self-referential runs are not disclosed as such")
print("absence of an oracle is disclosed too (self-referential invariants)")
passed("oracle disclosure")
