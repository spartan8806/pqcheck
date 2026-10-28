"""pqcheck command line: run | reproduce | relations | adapters | ui."""
from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import asdict
from pathlib import Path

import pqcheck.relations  # noqa: F401  (populates REGISTRY)
from pqcheck.manifest import ADAPTER_SPECS, Manifest, ManifestError
from pqcheck.relations.base import REGISTRY
from pqcheck.target import HarnessProtocolError
from pqcheck.verdict import Claim, Coverage, Method, Report, Verdict

EXIT_OK, EXIT_DEFECT, EXIT_NOTHING, EXIT_BAD = 0, 1, 2, 3


class CliError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CliError(message)


def _infer_kind(algorithm: str, manifest) -> str:
    if getattr(manifest, "kind", None) in ("kem", "sig"):
        return manifest.kind
    name = algorithm.lower()
    if "kem" in name or "kyber" in name:
        return "kem"
    return "sig"


def _split_algorithm(algorithm: str | None):
    """Manifest algorithms may carry a kind prefix: 'kem:ML-KEM-768'."""
    if algorithm and ":" in algorithm:
        kind, name = algorithm.split(":", 1)
        if kind in ("kem", "sig") and name:
            return kind, name
    return None, algorithm


def open_target(manifest: Manifest, algorithm: str | None):
    from pqcheck.adapters.cbridge import CTarget
    from pqcheck.adapters.codec_bridge import CodecTarget
    from pqcheck.adapters.hint_bridge import HintTarget
    from pqcheck.adapters.noble import NobleTarget
    from pqcheck.adapters.python_adapter import load_exec_target, load_python_target

    if manifest.adapter == "python":
        return load_python_target(manifest.module, algorithm, manifest.base)
    if manifest.adapter == "exec":
        kind, name = _split_algorithm(algorithm)
        return load_exec_target(manifest.command, kind or _infer_kind(name or "", manifest), name)
    if manifest.adapter == "c":
        kind, name = _split_algorithm(algorithm)
        return CTarget(str(manifest.harness), kind or _infer_kind(name or "", manifest), name, wsl=manifest.wsl)
    if manifest.adapter == "noble":
        return NobleTarget(str(manifest.node_cwd), algorithm)
    if manifest.adapter == "codec":
        return CodecTarget(str(manifest.harness), oracle=manifest.oracle or "codec harness")
    if manifest.adapter == "hint":
        return HintTarget(str(manifest.harness), oracle=manifest.oracle or "hint harness")
    raise CliError(f"unknown adapter {manifest.adapter}")


def _not_reached_claims(manifest, algorithms, relation_ids, problem):
    claims = []
    for algorithm in algorithms or [None]:
        for rid in relation_ids:
            relation = REGISTRY[rid]
            claims.append(Claim(
                subject=manifest.subject(algorithm),
                property=relation.property or rid,
                verdict=Verdict.NOT_REACHED,
                method=Method(name=rid, oracle=None),
                ceiling=relation.ceiling,
                evidence=problem,
            ))
    return claims


def _manifest_for_path(path_arg, overrides):
    p = Path(path_arg)
    if p.is_dir():
        from pqcheck.discover import discover
        candidates = discover(p)
        manifests = [c for c in candidates if c.kind == "manifest" and c.manifest is not None]
        if manifests:
            return manifests[0].manifest.with_overrides(overrides)
        noble = [c for c in candidates if c.kind == "noble" and c.ready]
        if noble:
            raise CliError(
                "folder has @noble/post-quantum but pqcheck needs a manifest or explicit "
                "--algorithm; create a manifest naming target/version/adapter/algorithms"
            )
        raise CliError(f"no usable manifest or target found under {p}")
    return Manifest.load(p).with_overrides(overrides)


def _seed_random(seed_hex, label):
    if seed_hex:
        try:
            bytes.fromhex(seed_hex)
        except ValueError as exc:
            raise CliError("--seed must be hexadecimal") from exc
        return random.Random(f"{seed_hex}:{label}")
    return random.Random(label)


def _revision_conflict(manifest, target) -> str | None:
    """Revision-bound manifests (version is a full 40-hex commit, as
    in the enc_rust regression) may only run against a binary that
    reports the same revision via its info line (rev=). A mismatch
    or an unreported revision is a provenance conflict: the run must
    establish nothing rather than label one build's results with
    another revision."""
    expected = (manifest.version or "").strip().lower()
    if len(expected) != 40 or any(c not in "0123456789abcdef" for c in expected):
        return None
    reported = getattr(target, "reported_revision", None)
    if not reported:
        return (f"revision-bound target: manifest pins commit {expected} "
                "but the target did not report a revision (no rev= in its "
                "info line); refusing to run relations")
    if str(reported).strip().lower() != expected:
        return (f"revision conflict: manifest pins commit {expected} but "
                f"the harness binary reports rev={reported}; refusing to "
                "run relations against a mismatched build")
    return None


def _run_relations(manifest, algorithms, relation_ids, seed_hex):
    claims = []
    for algorithm in algorithms:
        try:
            target = open_target(manifest, algorithm)
        except (HarnessProtocolError, OSError) as exc:
            claims.extend(_not_reached_claims(manifest, [algorithm], relation_ids, f"target could not be opened: {exc}"))
            continue
        try:
            conflict = _revision_conflict(manifest, target)
            if conflict:
                claims.extend(_not_reached_claims(
                    manifest, [algorithm], relation_ids, conflict))
                continue
            for rid in relation_ids:
                relation = REGISTRY[rid]
                rng = _seed_random(seed_hex, f"{rid}:{algorithm}")
                claims.append(relation.run(target, manifest.subject(algorithm), rng))
        finally:
            close = getattr(target, "close", None)
            if callable(close):
                close()
    return claims


def run_manifest_validated(manifest, algorithms, relation_ids, seed_hex=None) -> Report:
    """The one validated runner shared by run, reproduce, and the
    workbench: provenance problems become NOT_REACHED claims, targets
    are always closed, and an empty algorithms tuple means a single
    algorithm-less target (codec/hint manifests)."""
    algorithms = list(algorithms or [None])
    problems = _manifest_problems(manifest)
    if problems:
        return Report(tuple(_not_reached_claims(
            manifest, algorithms, relation_ids, "; ".join(problems))))
    return Report(tuple(_run_relations(manifest, algorithms, relation_ids, seed_hex)))


def _cmd_run(args) -> int:
    try:
        manifest = _manifest_for_path(args.path, args.set)
        relation_ids = [args.relation] if args.relation else sorted(REGISTRY)
        if args.relation and args.relation not in REGISTRY:
            raise CliError(f"unknown relation {args.relation!r}")
        algorithms = [args.algorithm] if args.algorithm else list(manifest.algorithms or [None])
        report = run_manifest_validated(manifest, algorithms, relation_ids, args.seed)
    except ManifestError as exc:
        print(f"pqcheck: {exc}", file=sys.stderr)
        return EXIT_BAD
    except CliError as exc:
        print(f"pqcheck: {exc}", file=sys.stderr)
        return EXIT_BAD
    if args.reproducers and report.defects():
        _write_reproducers(Path(args.reproducers), manifest, args, report)
    if args.json:
        print(json.dumps(_report_json(report), indent=2))
    else:
        Report.emit(report.to_text())
    if getattr(args, "html", None):
        Path(args.html).write_text(report.to_html(), encoding="utf-8")
        # stderr: stdout must stay valid JSON when --json is also used
        print(f"HTML report written to {args.html}", file=sys.stderr)
    return report.exit_code()


def _report_json(report: Report) -> dict:
    def claim_dict(c: Claim):
        data = {
            "subject": str(c.subject), "property": c.property,
            "verdict": c.verdict.value, "method": c.method.name,
            "oracle": c.method.oracle, "ceiling": c.ceiling,
            "evidence": c.evidence, "reproduce": c.reproduce, "notes": c.notes,
            "premises": list(c.premises), "one_sided": c.one_sided,
            "coverage": asdict(c.coverage) if c.coverage else None,
            "class_refs": [asdict(r) for r in c.class_refs],
        }
        return data
    return {"counts": report.counts(), "conclusive": report.is_conclusive_anywhere(), "claims": [claim_dict(c) for c in report.claims]}


def _safe_filename_part(text: str) -> str:
    """Make a filename component safe on NTFS: a ':' in an algorithm
    name (kem:ML-KEM-768) would otherwise create an NTFS alternate
    data stream instead of a discoverable .py file."""
    import re
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")
    return cleaned or "target"


def _write_reproducers(directory: Path, manifest, args, report: Report):
    directory.mkdir(parents=True, exist_ok=True)
    manifest_arg = str(manifest.path)
    package_root = str(Path(__file__).resolve().parents[1])
    for claim in report.defects():
        rid = claim.method.name
        algorithm = claim.subject.algorithm
        fname = directory / (
            f"reproduce_{_safe_filename_part(rid)}_"
            f"{_safe_filename_part(algorithm or 'target')}.py")
        sets = "".join(f' "--set", "{s}",' for s in (args.set or ()))
        body = f'''"""Standalone reproducer for {rid} on {claim.subject}. Generated by pqcheck."""
import sys
from pathlib import Path
sys.path.insert(0, {package_root!r})
from pqcheck.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["reproduce", {manifest_arg!r}, "--relation", {rid!r}] + (["--algorithm", {algorithm!r}] if {algorithm!r} else []) + [{sets}] + (["--seed", {args.seed!r}] if {args.seed!r} else [])))
'''
        fname.write_text(body, encoding="utf-8")


def _manifest_problems(manifest) -> list[str]:
    """Provenance checks shared by run and reproduce: a target is
    never opened when its paths are missing or its installed version
    disagrees with the manifest's pinned version."""
    problems = list(manifest.missing_paths())
    wrong = manifest.wrong_version()
    if wrong:
        problems.append(wrong)
    return problems


def _cmd_reproduce(args) -> int:
    try:
        manifest = Manifest.load(args.manifest).with_overrides(args.set)
        if args.relation not in REGISTRY:
            raise CliError(f"unknown relation {args.relation!r}")
        algorithms = [args.algorithm] if args.algorithm else list(manifest.algorithms or [None])
        algorithm = algorithms[0]
        report = run_manifest_validated(manifest, [algorithm], [args.relation], args.seed)
    except ManifestError as exc:
        print(f"pqcheck: {exc}", file=sys.stderr)
        return EXIT_BAD
    except CliError as exc:
        print(f"pqcheck: {exc}", file=sys.stderr)
        return EXIT_BAD
    Report.emit(report.to_text())
    return report.exit_code()


def _cmd_relations(args) -> int:
    for rid, relation in sorted(REGISTRY.items()):
        caps = ", ".join(sorted(c.value for c in relation.requires)) or "-"
        flags = []
        if relation.needs_control: flags.append("control")
        if relation.constructs_probes: flags.append("constructs-probes")
        if relation.one_sided: flags.append("one-sided")
        if relation.probes_lie_about_length: flags.append("lying-length")
        print(f"{rid}  requires=[{caps}]" + (f"  ({', '.join(flags)})" if flags else ""))
    return EXIT_OK


def _cmd_adapters(args) -> int:
    for name, spec in sorted(ADAPTER_SPECS.items()):
        print(f"{name}: required={list(spec.required)} optional={list(spec.optional)} algorithms={spec.algorithms}")
    return EXIT_OK


def _demo_run(rid, target, subject_name):
    from pqcheck.verdict import Subject
    relation = REGISTRY[rid]
    subject = Subject(target=subject_name, commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")
    return relation.run(target, subject, random.Random(f"demo:{rid}"))


def _cmd_demo(args) -> int:
    """Four-act judge showcase: precision, recall, loud reporter, guardrails."""
    from pqcheck.testing.precision import ExplicitRejectKem
    from pqcheck.testing.toy import ToyKem, ToySig
    from pqcheck.testing.toycodec import ToyCodec
    from pqcheck.testing.toylwe import PackedEkKem, ToyLweKem
    from pqcheck.testing.toymldsa import ToyMldsaSig
    from pqcheck.verdict import ClaimError, Method, Subject

    failures = []
    demo_claims = []

    print("=== Act 1: precision on clean reference & boundary targets ===")
    clean_targets = [
        ("ToyLweKem", ToyLweKem), ("ToySig", ToySig), ("ToyCodec", ToyCodec),
        ("PackedEkKem", PackedEkKem), ("ToyMldsaSig", ToyMldsaSig),
        ("ExplicitRejectKem", ExplicitRejectKem),
    ]
    for name, factory in clean_targets:
        target = factory()
        counts = {}
        for rid, relation in sorted(REGISTRY.items()):
            claim = _demo_run(rid, target, name)
            counts[claim.verdict.value] = counts.get(claim.verdict.value, 0) + 1
        defects = counts.get("DEFECT_FOUND", 0)
        declines = counts.get("NOT_REACHED", 0) + counts.get("NOT_ANSWERABLE", 0)
        print(f"  {name}: {defects} DEFECT_FOUND, {declines} honest declines "
              f"(NOT_REACHED/NOT_ANSWERABLE), counts={counts}")
        if defects:
            failures.append(f"Act 1: clean {name} produced {defects} DEFECT_FOUND")

    print()
    print("=== Act 2: live recall on real-world PQC bug shapes ===")
    flagships = [
        ("kem-fo-liveness", ToyLweKem(mutant="no_reencryption_check"),
         "ToyLweKem[no_reencryption_check]"),
        ("kem-ek-modulus-canonical", PackedEkKem(mutant="no_ek_modulus_check"),
         "PackedEkKem[no_ek_modulus_check]"),
        ("sig-unread-bits", ToySig(mutant="verify_ignores_slack"),
         "ToySig[verify_ignores_slack]"),
        ("mldsa-verify-hint-strict-order", ToyMldsaSig(mutant="accept_non_strict_hints"),
         "ToyMldsaSig[accept_non_strict_hints]"),
    ]
    for rid, target, label in flagships:
        claim = _demo_run(rid, target, label)
        demo_claims.append(claim)
        report = Report((claim,))
        print(f"--- {rid} on {label} ---")
        Report.emit(report.to_text())
        relation = REGISTRY[rid]
        modes = relation.false_positive_modes or ("none declared",)
        for mode in modes:
            print(f"    false_positive_modes: {mode}")
        if claim.verdict is not Verdict.DEFECT_FOUND:
            failures.append(f"Act 2: {rid} on {label} gave {claim.verdict.value}")

    print()
    print("=== Act 3: the loud reporter guarantee ===")
    broken = ToySig(mutant="refuses_every_message")
    controlled = _demo_run("sig-message-binding", broken, "ToySig[refuses_every_message]")
    demo_claims.append(controlled)
    print(f"  controlled relation sig-message-binding: {controlled.verdict.value} "
          f"({controlled.evidence or controlled.notes})")
    loud = _demo_run("core-sig-round-trip", broken, "ToySig[refuses_every_message]")
    demo_claims.append(loud)
    print(f"  core-sig-round-trip (needs_control=False): {loud.verdict.value} "
          f"({loud.evidence})")
    if controlled.verdict is not Verdict.NOT_REACHED:
        failures.append(f"Act 3: controlled relation gave {controlled.verdict.value}, expected NOT_REACHED")
    if loud.verdict is not Verdict.DEFECT_FOUND:
        failures.append(f"Act 3: core-sig-round-trip gave {loud.verdict.value}, expected DEFECT_FOUND")

    print()
    print("=== Act 4: epistemic & defensive guardrails ===")
    try:
        Report(()).score()
        failures.append("Act 4: Report.score() did not refuse")
        print("  Report.score(): did NOT refuse (unexpected)")
    except NotImplementedError as exc:
        print(f"  Report.score() refuses: {exc}")
    subject = Subject(target="demo", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")
    try:
        Claim(subject=subject, property="demo property", verdict=Verdict.NOT_REACHED,
              method=Method(name="demo", oracle=None), ceiling="demo ceiling",
              evidence="ab" * 32)
        failures.append("Act 4: Claim accepted secret-shaped material")
        print("  Claim with secret-shaped evidence: accepted (unexpected)")
    except ClaimError as exc:
        print(f"  Claim refuses secret-shaped material: {exc}")

    if getattr(args, "html", None):
        Path(args.html).write_text(Report(tuple(demo_claims)).to_html(), encoding="utf-8")
        print(f"HTML report written to {args.html}")

    print()
    if failures:
        print("demo FAILED:")
        for failure in failures:
            print(" -", failure)
        return EXIT_DEFECT
    print("demo: ok (precision holds, flagship mutants caught, broken target is loud, guardrails refuse)")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="pqcheck", description="PQC implementation assurance via metamorphic relations")
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser("run")
    run.add_argument("path")
    run.add_argument("--set", action="append", default=[], dest="set")
    run.add_argument("--relation")
    run.add_argument("--algorithm")
    run.add_argument("--seed")
    run.add_argument("--json", action="store_true")
    run.add_argument("--html", help="also write a single-file HTML report to this path")
    run.add_argument("--reproducers")
    run.set_defaults(fn=_cmd_run)
    repro = sub.add_parser("reproduce")
    repro.add_argument("manifest")
    repro.add_argument("--relation", required=True)
    repro.add_argument("--algorithm")
    repro.add_argument("--seed")
    repro.add_argument("--set", action="append", default=[], dest="set")
    repro.set_defaults(fn=_cmd_reproduce)
    rel = sub.add_parser("relations"); rel.set_defaults(fn=_cmd_relations)
    ad = sub.add_parser("adapters"); ad.set_defaults(fn=_cmd_adapters)
    ui = sub.add_parser("ui"); ui.add_argument("folder", nargs="?")
    ui.set_defaults(fn=lambda a: __import__("pqcheck.tui", fromlist=["run"]).run(a.folder))
    demo = sub.add_parser("demo", help="four-act judge showcase (fast, self-contained)")
    demo.add_argument("--html", help="also write the Act 2/3 claims as a single-file HTML report")
    demo.set_defaults(fn=_cmd_demo)
    web = sub.add_parser("web", help="local browser workbench (127.0.0.1 only)")
    web.add_argument("--port", type=int, default=8420)
    web.set_defaults(fn=lambda a: __import__("pqcheck.web", fromlist=["serve"]).serve(a.port))
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if not getattr(args, "fn", None):
            parser.print_help()
            return EXIT_BAD
        return int(args.fn(args))
    except CliError as exc:
        print(f"pqcheck: {exc}", file=sys.stderr)
        return EXIT_BAD
    except ManifestError as exc:
        print(f"pqcheck: {exc}", file=sys.stderr)
        return EXIT_BAD


if __name__ == "__main__":
    sys.exit(main())
