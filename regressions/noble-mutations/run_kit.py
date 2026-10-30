#!/usr/bin/env python3
"""Noble mutation regression kit executor (Set 3, Phase 13).

Builds isolated mutated copies of the pinned Noble post-quantum
0.6.1 build, runs pqcheck against each through the normal CLI in a
fresh process, and asserts the expected relations. Detection logic
never sees case names or this file; expectations live only here.

Prerequisite: a checkout of noble-post-quantum at the pinned
revision with its built JavaScript and node_modules present (the
audit layout). Missing or mismatched prerequisites exit 2 so CI
fails loudly instead of silently skipping.

Usage:
    python run_kit.py --src D:\\path\\to\\noble-post-quantum \
        [--cases kem-fo-removed ...] [--seed 1] [--keep] [--workdir DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

KIT = json.loads((Path(__file__).parent / "noble-mutations.json").read_text(encoding="utf-8"))
REPO = Path(__file__).resolve().parents[2]
DEPS = ("hashes", "curves", "ciphers")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_prereqs(src: Path) -> None:
    if not src.is_dir():
        print(f"PREREQUISITE MISSING: Noble source directory not found: {src}", file=sys.stderr)
        raise SystemExit(2)
    pkg = src / "package.json"
    if not pkg.exists() or json.loads(pkg.read_text(encoding="utf-8")).get("version") != KIT["upstream_version"]:
        print(f"PREREQUISITE MISMATCH: {src} is not Noble {KIT['upstream_version']}", file=sys.stderr)
        raise SystemExit(2)
    for name, want in KIT["pinned_built_sha256"].items():
        got = sha256(src / name) if (src / name).exists() else "missing"
        if got != want:
            print(f"PREREQUISITE MISMATCH: {name} sha256 {got} != pinned {want}", file=sys.stderr)
            raise SystemExit(2)
    for dep in DEPS:
        if not (src / "node_modules" / "@noble" / dep).is_dir():
            print(f"PREREQUISITE MISSING: node_modules/@noble/{dep} under {src}", file=sys.stderr)
            raise SystemExit(2)


def build_case(src: Path, case: dict, dest: Path) -> None:
    pkg_dest = dest / "node_modules" / "@noble" / "post-quantum"
    pkg_dest.mkdir(parents=True)
    for item in src.iterdir():
        if item.is_file() and item.suffix in (".js", ".json"):
            shutil.copy2(item, pkg_dest / item.name)
    for dep in DEPS:
        shutil.copytree(src / "node_modules" / "@noble" / dep,
                        dest / "node_modules" / "@noble" / dep)
    for fname, old, new, count in case.get("replacements", []):
        target = pkg_dest / fname
        text = target.read_text(encoding="utf-8")
        found = text.count(old)
        if found != count:
            print(f"ANCHOR FAILURE {case['id']}: {fname} anchor occurs {found}x, expected {count}x; "
                  "refusing to guess (pinned build changed?)", file=sys.stderr)
            raise SystemExit(2)
        target.write_text(text.replace(old, new), encoding="utf-8")


def manifest_for(case_dir: Path, algorithm, ek: str, dk: str) -> Path:
    manifest = {
        "target": f"noble-kit-{case_dir.name}",
        "version": KIT["upstream_version"],
        "adapter": "noble",
        "node_cwd": str(case_dir.resolve()),
        "algorithms": [algorithm] if isinstance(algorithm, str) else list(algorithm),
        "validation": {
            "standard": "FIPS 203",
            "key_format": "ML-KEM serialized keys",
            "ek": ek,
            "dk": dk,
            "basis": "Noble entry points perform FIPS 203 Sections 7.2-7.3 input checking on entry (declared via noble-mutations kit)",
        },
    }
    path = case_dir / "pqcheck.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def run_pqcheck(manifest: Path, seed: int, repro_dir: Path | None = None) -> tuple[int, dict]:
    code = ("from pqcheck.cli import main; import sys; "
            "sys.exit(main(sys.argv[1:]))")
    argv = [sys.executable, "-c", code, "run", str(manifest), "--seed", format(seed, "02x"), "--json"]
    if repro_dir is not None:
        argv += ["--reproducers", str(repro_dir)]
    proc = subprocess.run(argv, capture_output=True, text=True, cwd=REPO, timeout=1200,
                          stdin=subprocess.DEVNULL,
                          env={**os.environ, "PYTHONUTF8": "1"})
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(proc.stdout[-2000:], proc.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"pqcheck run for {manifest} did not emit JSON (exit {proc.returncode})")
    return proc.returncode, report


def defect_relations(report: dict) -> set[str]:
    return {c["method"] for c in report["claims"] if c["verdict"] == "DEFECT_FOUND"}


def not_answerable_relations(report: dict) -> set[str]:
    return {c["method"] for c in report["claims"] if c["verdict"] == "NOT_ANSWERABLE"}


def replay_reproducers(repro_dir: Path, defects: set[str],
                       expected: set[str]) -> tuple[int, int, set[str], int]:
    """Execute generated reproducers and validate what they prove.

    A replay counts only when the script exits 1 AND its stdout is a
    valid pqcheck JSON report whose claims contain DEFECT_FOUND for
    the relation named in the script's filename. An exit code alone
    proves nothing: a script that crashes before testing anything
    also exits 1. There is no retry: exit 3 means invalid invocation
    or manifest, and retrying cannot repair that. Stdout/stderr of
    every replay are preserved next to the script as
    <name>.stdout.txt / <name>.stderr.txt.

    Failures gate the case only for the case's expected relations.
    Incidental findings (e.g. a one-sided witness search that does
    not re-find its witness under a fresh process's hedged signing
    randomness) are still executed and preserved, and their replay
    outcomes are reported, but they do not gate: their absence on
    replay does not contradict the original observation."""
    scripts = sorted(repro_dir.glob("*.py")) if repro_dir.exists() else []
    bad = 0
    bad_incidental = 0
    validated: set[str] = set()
    for script in scripts:
        rid = next((r for r in defects if script.name.startswith(f"reproduce_{r}_")), None)
        proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL,
                              cwd=REPO, timeout=1200, env={**os.environ, "PYTHONUTF8": "1"})
        (repro_dir / f"{script.name}.stdout.txt").write_text(proc.stdout, encoding="utf-8")
        (repro_dir / f"{script.name}.stderr.txt").write_text(proc.stderr, encoding="utf-8")
        proven = False
        if proc.returncode == 1 and rid is not None:
            try:
                report = json.loads(proc.stdout)
                proven = any(c.get("method") == rid and c.get("verdict") == "DEFECT_FOUND"
                             for c in report.get("claims", []))
            except json.JSONDecodeError:
                proven = False
        if proven:
            validated.add(rid)
        elif rid in expected:
            bad += 1
            print(f"REPRODUCER REPLAY FAILURE {script.name}: exit {proc.returncode}, "
                  f"relation {rid!r} not proven defective; stdout/stderr preserved in {repro_dir}",
                  file=sys.stderr)
        else:
            bad_incidental += 1
            print(f"incidental reproducer not reproduced on replay {script.name}: "
                  f"exit {proc.returncode} (reported, not gating; output preserved)",
                  file=sys.stderr)
    return len(scripts), bad, validated, bad_incidental


def case_accepted(bucket: str, expected: set[str], defects: set[str], code: int,
                  replay_bad: int = 0, validated: set[str] | None = None) -> bool:
    """Consistent report/exit combinations only.

    Clean control: no findings and exit 0. Defect case: every
    expected relation defective, exit exactly 1 (a defect report
    paired with exit 0, 2, or 3 is inconsistent and rejected), and
    every expected relation proven by a validated replay."""
    if bucket == "clean-control":
        return not defects and code == 0
    return (expected <= defects and code == 1 and replay_bad == 0
            and expected <= (validated or set()))


def control_accepted(need: set[str], declined: set[str], defects: set[str], code: int) -> bool:
    """Contract controls: the new relations decline, there are no
    findings of any kind, and the exit is the clean 0."""
    return need <= declined and not defects and code == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.environ.get("PQCHECK_NOBLE_SRC", ""))
    ap.add_argument("--cases", nargs="*", default=None)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--workdir", default="")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    if not args.src:
        print("PREREQUISITE MISSING: --src or PQCHECK_NOBLE_SRC must name the pinned Noble checkout",
              file=sys.stderr)
        return 2
    src = Path(args.src)
    verify_prereqs(src)

    wanted = set(args.cases) if args.cases else None
    workroot = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="noble-kit-"))
    workroot.mkdir(parents=True, exist_ok=True)
    rows, failures = [], 0

    jobs = []
    for case in KIT["cases"]:
        if wanted and case["id"] not in wanted:
            continue
        jobs.append(("case", case))
    if not wanted:
        for control in KIT["controls"]:
            jobs.append(("control", control))

    for kind, job in jobs:
        case_dir = workroot / job["id"]
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True)
        if kind == "case":
            build_case(src, job, case_dir)
            manifest = manifest_for(case_dir, job["algorithm"], "validate-on-entry", "validate-on-entry")
            repro_dir = case_dir / "reproducers"
            code, report = run_pqcheck(manifest, args.seed, repro_dir if job["bucket"] != "clean-control" else None)
            defects = defect_relations(report)
            expected = set(job["expected_relations"])
            if job["bucket"] == "clean-control":
                ok = case_accepted(job["bucket"], expected, defects, code)
                detail = f"defects={sorted(defects) or 'none'} exit={code}"
            else:
                n_repro, bad_repro, validated, bad_inc = replay_reproducers(repro_dir, defects, expected)
                ok = case_accepted(job["bucket"], expected, defects, code, bad_repro, validated)
                detail = (f"expected {sorted(expected)} within defects={sorted(defects)} exit={code} "
                          f"reproducers={n_repro} replay_failures={bad_repro} "
                          f"incidental_replay_failures={bad_inc} "
                          f"replay_validated={sorted(validated)}")
        else:
            build_case(src, {"id": job["id"], "replacements": []}, case_dir)
            manifest = manifest_for(case_dir, job["algorithm"], job["validation_ek"], job["validation_dk"])
            code, report = run_pqcheck(manifest, args.seed)
            defects = defect_relations(report)
            declined = not_answerable_relations(report)
            need = {"kem-ek-rejects-noncanonical", "kem-dk-rejects-hash-mismatch"}
            ok = control_accepted(need, declined, defects, code)
            detail = f"declined={sorted(need & declined)} defects={sorted(defects)} exit={code}"
        rows.append((job["id"], "OK" if ok else "MISMATCH", detail))
        failures += 0 if ok else 1

    print(f"{'case':42} {'result':9} detail")
    for cid, result, detail in rows:
        print(f"{cid:42} {result:9} {detail}")
    print(f"{len(rows) - failures}/{len(rows)} kit expectations met (seed {args.seed}, src {src})")
    if not args.keep and not args.workdir:
        shutil.rmtree(workroot, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
