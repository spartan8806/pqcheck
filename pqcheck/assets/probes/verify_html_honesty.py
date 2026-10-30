#!/usr/bin/env python3
"""HTML report honesty: same epistemic rules as the text report."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

from pqcheck.testing.toy import ToyKem, ToySig  # noqa: E402
from pqcheck.verdict import Claim, Method, Report, Subject, Verdict  # noqa: E402

claims = []
claims.append(registry_run("kem-fo-liveness",
                           ToyKem(mutant="no_reencryption_check")))
claims.append(registry_run("kem-fo-liveness", ToyKem()))  # one-sided clean
claims.append(registry_run("core-kem-round-trip", ToyKem()))
claims.append(registry_run("kem-fo-liveness",
                           ToySig(mutant="refuses_every_message")))
subject = Subject(target="html-probe", commit="a1b2c3d4e5f60718293a")
claims.append(Claim(subject=subject, property="escape probe",
                    verdict=Verdict.NOT_REACHED,
                    method=Method(name="html-escape-probe", oracle=None),
                    ceiling="escape ceiling",
                    evidence='a < b & "quoted" <script>alert(1)</script>'))
report = Report(tuple(claims))
text = report.to_html()

check("DEFECT FOUND" in text, "defect bucket missing")
check(text.index("DEFECT FOUND") < text.index("NO DEFECT FOUND"),
      "defects are not rendered above clean claims")
if "NOT REACHED" in text:
    check(text.index("NOT REACHED") < text.index("NO DEFECT FOUND"),
          "NOT REACHED is not rendered above clean claims")
check("NO DEFECT FOUND (one-sided" in text,
      "one-sided NO_DEFECT_FOUND is not separated from conclusive clean")
check("Why is there no percentage score?" in text,
      "score-refusal callout missing")
check("measures tool effort" in text,
      "exact Report.score() refusal message not shown in the callout")
check(not re.search(r"\d+(?:\.\d+)?\s*%", text),
      "a percentage figure appears in the HTML report")
check("letter grade" not in text.lower(), "a letter grade appears")
check("&lt;script&gt;" in text and "<script>alert" not in text,
      "claim text is not HTML-escaped")
check("runner_calls:" in text and "units:" in text and "basis:" in text,
      "coverage fields (units/basis/runner_calls) missing")
check("oracle:" in text and "false_positive_modes:" in text
      and "ceiling (does not establish):" in text
      and "reproducer:" in text,
      "per-claim fields (oracle/ceiling/false_positive_modes/reproducer) missing")
check("@ a1b2c3d4e5f60718293a" in text, "subject target @ commit not rendered")
print("HTML report: defects above clean, one-sided separated, escaped, scoreless")
passed("html honesty")
