#!/usr/bin/env python3
"""A generated reproducer script executes and speaks pqcheck's exit codes."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import ROOT, check, passed  # noqa: E402

from pqcheck.cli import _write_reproducers  # noqa: E402
from pqcheck.manifest import Manifest  # noqa: E402
from pqcheck.verdict import Claim, Method, Report, Subject, Verdict  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    manifest_path = Path(td) / "manifest.json"
    manifest_path.write_text(json.dumps(
        {"target": "fake", "version": "1.0.0", "adapter": "c",
         "harness": str(ROOT / "tests" / "fake_harness.py"),
         "algorithms": ["fake-kem"], "kind": "kem"}), encoding="utf-8")
    manifest = Manifest.load(manifest_path)
    claim = Claim(
        subject=Subject(target="fake", commit="1.0.0", algorithm="fake-kem"),
        property="p", verdict=Verdict.DEFECT_FOUND, method=Method("core-kem-round-trip", None),
        ceiling="c", reproduce="re-run the pinned relation again now",
    )

    class Args:
        set = []
        seed = None

    outdir = Path(td) / "repro"
    _write_reproducers(outdir, manifest, Args(), Report((claim,)))
    scripts = list(outdir.glob("*.py"))
    check(len(scripts) == 1, "no reproducer script generated")
    proc = subprocess.run([sys.executable, str(scripts[0])], capture_output=True, text=True,
                          cwd=str(ROOT), timeout=120)
    check(proc.returncode in (0, 1, 2), f"reproducer exited {proc.returncode}: {proc.stderr[-300:]}")
    check("core-kem-round-trip" in proc.stdout or "NO DEFECT" in proc.stdout or "DEFECT" in proc.stdout,
          "reproducer did not produce a pqcheck report")
    print(f"generated reproducer executed and exited {proc.returncode} (a pqcheck exit code)")
passed("reproducer round trip")
