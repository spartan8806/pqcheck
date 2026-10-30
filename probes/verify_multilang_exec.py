#!/usr/bin/env python3
"""Multi-language exec adapter: python_harness.py over the wire.

Drives the template harness as a subprocess through the exec adapter
on a clean target and on a mutant â€” works without a C compiler.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = next((p for p in _pq_here.parents if (p / "pqcheck" / "__init__.py").is_file()), _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed, registry_run  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pqcheck.cli import open_target  # noqa: E402
from pqcheck.manifest import Manifest  # noqa: E402
from pqcheck.verdict import Subject, Verdict  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'pqcheck' / 'adapters' / 'templates' / 'python_harness.py'
if not HARNESS.is_file():
    import pqcheck as _pq
    HARNESS = Path(_pq.__file__).resolve().parent / 'adapters' / 'templates' / 'python_harness.py'
if not HARNESS.is_file():
    print('SKIP: python_harness.py template is not present')
    raise SystemExit(77)


def run(rid, kind, algorithm):
    manifest = Manifest({
        "target": "python-harness-template", "version": "1.0.0",
        "adapter": "exec", "kind": kind,
        "command": [sys.executable, str(HARNESS)],
        "algorithms": [f"{kind}:{algorithm}"],
    }, ROOT / "manifest.json")
    target = open_target(manifest, f"{kind}:{algorithm}")
    try:
        from pqcheck.relations.base import REGISTRY
        import random
        subject = Subject(target="python-harness-template",
                          commit="1.0.0", algorithm=algorithm)
        return REGISTRY[rid].run(target, subject, random.Random("multilang"))
    finally:
        target.close()


claim = run("kem-fo-liveness", "kem", "WireKem")
check(claim.verdict is Verdict.NO_DEFECT_FOUND,
      f"clean WireKem over exec gave {claim.verdict.value}: {claim.evidence}")
print("clean Python KEM over the subprocess wire -> NO_DEFECT_FOUND")
claim = run("kem-fo-liveness", "kem", "WireKem[no_reencryption_check]")
check(claim.verdict is Verdict.DEFECT_FOUND,
      f"mutant WireKem over exec gave {claim.verdict.value}: {claim.evidence}")
print("mutant Python KEM over the subprocess wire -> DEFECT_FOUND")
claim = run("sig-unread-bits", "sig", "WireSig[verify_ignores_slack]")
check(claim.verdict is Verdict.DEFECT_FOUND,
      f"slack-ignoring WireSig over exec gave {claim.verdict.value}")
print("mutant Python SIG over the subprocess wire -> DEFECT_FOUND")
passed("multilang exec adapter")
