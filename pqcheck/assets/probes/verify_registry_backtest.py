"""Standing probe: registry completeness and backtest accounting."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pqcheck.relations  # noqa: F401
from pqcheck.backtest.report import evaluate
from pqcheck.relations.base import REGISTRY

assert len(REGISTRY) == 32, f"expected 32 relations, got {len(REGISTRY)}"
result = evaluate()
assert result["total"] == 22, result["total"]
# Grades are incommensurable and never summed; MISSED is the work queue.
assert result["counts"] == {
    "DEMONSTRATED": 7, "ARGUED": 5, "PARTIAL": 4,
    "MISSED": 2, "OUT_OF_SCOPE": 4,
}, result["counts"]
assert "COVERED" not in result["counts"], result["counts"]
assert [e.id for e in result["work_queue"]] == [
    "clib-xmss-key-reuse", "CVE-2022-37454"], result["work_queue"]
print(f"PASS: 32 relations registered; backtest per-grade counts {result['counts']}")
