#!/usr/bin/env python3
"""constructs_probes relations must override probe_control at register time."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed  # noqa: E402

import pqcheck.relations  # noqa: E402,F401
from pqcheck.relations.base import REGISTRY, Relation, register  # noqa: E402

before = set(REGISTRY)
try:
    @register
    class BadProbeRelation(Relation):
        id = "probe-bad-constructs-probes"
        property = "p"
        ceiling = "c"
        constructs_probes = True

    check(False, "constructs_probes without probe_control was registered")
except TypeError as exc:
    print(f"registration refused without probe_control: {exc}")
check(set(REGISTRY) == before, "failed registration polluted the registry")
passed("probe_control enforcement at register time")
