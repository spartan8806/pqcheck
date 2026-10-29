"""Local browser workbench: stdlib only, bound to 127.0.0.1.

    python -m pqcheck web [--port 8420]

Defensive local use only: the server binds the loopback interface
and is meant for the machine's own user. The default workflow opens
local project folders / pqcheck manifests and runs them through the
CLI's validated runner. Toy fixtures and mutants live in a separate
Demo / Self-test area. Nothing here opens network or remote targets.
"""
from __future__ import annotations

import json
import random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pqcheck.relations  # noqa: F401  (populates REGISTRY)
from pqcheck.relations.base import REGISTRY
from pqcheck.verdict import Report, Subject, Verdict

COMMIT = "0.1.0b1"

_FAILURE_CLASSES = [
    ("kem-fo-liveness", "X-FO-LIVE"),
    ("kem-reject-", "X-REJECT-*"),
    ("kem-ek-modulus-canonical", "X-CANON-*"),
    ("kem-dk-hash-consistency", "X-CANON-*"),
    ("sig-encoding-", "X-CANON-*"),
    ("mldsa-", "X-CANON-*"),
    ("sig-message-binding", "X-BIND-*"),
    ("sig-ctx-binding", "X-BIND-*"),
    ("sig-wrong-key-rejection", "X-BIND-*"),
    ("sig-mode-domain-separation", "X-DOM-*"),
    ("length", "X-LEN-*"),
    ("declared-sizes", "X-LEN-*"),
]


def failure_class(relation_id: str) -> str:
    for prefix, ident in _FAILURE_CLASSES:
        if relation_id.startswith(prefix):
            return ident
    return "-"


def _clean_targets():
    from pqcheck.testing import (
        PackedEkKem, ToyCodec, ToyFalconSig, ToyKem, ToyLweKem,
        ToyMldsaSig, ToySig, ToyStreamCodec,
    )
    return {
        "PackedEkKem": PackedEkKem, "ToyLweKem": ToyLweKem,
        "ToyKem": ToyKem, "ToySig": ToySig, "ToyFalconSig": ToyFalconSig,
        "ToyMldsaSig": ToyMldsaSig, "ToyCodec": ToyCodec,
        "ToyStreamCodec": ToyStreamCodec,
    }


def _mutant_tables():
    from pqcheck.testing import (
        CODEC_MUTANTS, FALCON_MUTANTS, KEM_MUTANTS, LWE_MUTANTS,
        MLDSA_MUTANTS, PACKED_EK_MUTANTS, SIG_MUTANTS,
    )
    return {
        "KEM": KEM_MUTANTS, "SIG": SIG_MUTANTS, "CODEC": CODEC_MUTANTS,
        "LWE": LWE_MUTANTS, "PACKED_EK": PACKED_EK_MUTANTS,
        "FALCON": FALCON_MUTANTS, "MLDSA": MLDSA_MUTANTS,
    }


def targets_catalog() -> dict:
    from pqcheck.testing.precision import CASES
    mutants = []
    for group, table in _mutant_tables().items():
        for name in table:
            mutants.append(f"{group}:{name}")
    return {
        "clean": sorted(_clean_targets()),
        "mutants": mutants,
        "boundary": [case.label for case in CASES],
        "manifest": ["python-reference"],
        # Honest labelling: everything runnable in-process here is a
        # fixture. Real external targets only ever run through a
        # local manifest (see manifests_data / the Reports tab).
        "kinds": {
            "clean": "toy fixture",
            "mutants": "toy fixture (planted mutant)",
            "boundary": "toy fixture (boundary case)",
            "manifest": "reference fixture (in-repo targets, not an external library)",
        },
    }


def manifests_data() -> list[dict]:
    """Shipped manifests the Reports tab can run, with revisions."""
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    dirs = [root / "manifests", root / "pqcheck" / "assets" / "manifests"]
    out = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(path.read_text())
            except Exception:
                continue
            kind = ("reference fixture (in-repo targets)"
                    if path.name == "python-reference.json"
                    else "real target via local manifest")
            out.append({"name": path.name, "target": data.get("target", "?"),
                        "revision": data.get("version", "?"), "kind": kind})
        if out:
            break
    return out


def run_named_manifest(name: str) -> dict:
    """Run a shipped manifest by name (whitelist = manifests_data),
    through the CLI's validated runner: same version checks, targets
    always closed, codec manifests run as one algorithm-less target."""
    from pathlib import Path

    from pqcheck.cli import run_manifest_validated
    from pqcheck.manifest import Manifest

    allowed = {m["name"] for m in manifests_data()}
    if name not in allowed:
        raise ValueError(f"unknown shipped manifest {name!r}")
    root = Path(__file__).resolve().parents[1]
    path = root / "manifests" / name
    if not path.is_file():
        path = root / "pqcheck" / "assets" / "manifests" / name
    manifest = Manifest.load(path)
    report = run_manifest_validated(
        manifest, list(manifest.algorithms or [None]), sorted(REGISTRY))
    result = _report_dict(report, f"manifest:{name}")
    result["revision"] = manifest.version
    result["kind"] = ("reference fixture (in-repo targets)"
                      if name == "python-reference.json"
                      else "real target via local manifest")
    return result


def _platform_label() -> str:
    import platform
    import sys

    return (f"{sys.platform} / {platform.machine()} / "
            f"Python {platform.python_version()}")


def _manifest_identity(manifest, source: str) -> dict:
    return {
        "source": source,
        "target": manifest.target,
        "revision": manifest.version,
        "adapter": manifest.adapter,
        "algorithms": list(manifest.algorithms),
        "platform": _platform_label(),
    }


def _readiness(manifest) -> tuple[list, list]:
    """Readiness = the validated runner's provenance checks, explained
    with exact next steps. Recognizing a target is never readiness."""
    from pqcheck.cli import _manifest_problems
    from pqcheck.manifest import ADAPTER_SPECS

    problems = list(_manifest_problems(manifest))
    steps = []
    if manifest.adapter not in ADAPTER_SPECS:
        problems.append(f"unsupported adapter {manifest.adapter!r}")
        steps.append("Use a supported adapter (c, exec, noble, python, "
                     "codec, hint); see the Adapters tab for the wire formats.")
    for problem in problems:
        if "harness not found" in problem:
            steps.append(
                f"Build the harness first: {problem.split(': ', 1)[-1]}. "
                "Harness sources and build notes live in pqcheck/adapters/ "
                "(C templates), pqcheck/adapters/rust/ (Rust), and "
                "regressions/enc_rust/README.md (enc_rust). Then re-check.")
        elif "node_cwd not found" in problem:
            steps.append(
                "Install the Node target (npm install @noble/post-quantum) "
                "or fix node_cwd in the manifest to the install folder.")
        elif "version" in problem:
            steps.append(
                "Fix the pinned version in the manifest to match the "
                "installed target, or install the pinned revision. "
                "pqcheck will not relabel one build as another.")
        elif "module file not found" in problem:
            steps.append("Point the manifest's module at the target's "
                         "Python module file, or fix the path.")
    if not problems:
        steps.append("Ready. Run checks when you are ready.")
    return problems, steps


def inspect_project(path_str: str) -> dict:
    """Step 1–3 of the project workflow: open, identify, readiness."""
    from pathlib import Path

    from pqcheck.manifest import Manifest, ManifestError

    raw = str(path_str or "").strip()
    result = {"input": raw, "platform": _platform_label(), "found": False,
              "ready": False, "problems": [], "next_steps": [],
              "candidates": []}
    if not raw:
        result["problems"] = ["no project folder or manifest path given"]
        result["next_steps"] = ["Enter a local project folder or a "
                                "pqcheck manifest (.json) path."]
        return result
    path = Path(raw).expanduser()
    if not path.exists():
        result["problems"] = [f"path does not exist: {path}"]
        result["next_steps"] = ["Check the path. pqcheck only opens "
                                "local folders and manifest files."]
        return result
    result["found"] = True
    if path.is_dir():
        from pqcheck.discover import discover

        candidates = discover(path)
        result["candidates"] = [{
            "kind": c.kind, "path": str(c.path), "ready": c.ready,
            "detail": c.detail, "missing": list(c.missing),
            "algorithms": list(c.algorithms),
        } for c in candidates]
        named = [c for c in candidates if c.kind == "manifest" and c.manifest]
        if named:
            manifest = named[0].manifest
            result.update(_manifest_identity(manifest, str(named[0].path)))
            problems, steps = _readiness(manifest)
            result["ready"] = not problems
            result["problems"] = problems
            result["next_steps"] = steps
            return result
        result["problems"] = [
            "no pqcheck manifest found in this folder; recognized files "
            "do not by themselves make a target testable"]
        result["next_steps"] = [
            "Create a manifest naming target, pinned version, adapter, "
            "and algorithms (see manifests/ for examples), or open an "
            "existing manifest file directly."]
        return result
    try:
        manifest = Manifest.load(path)
    except (ManifestError, OSError, ValueError) as exc:
        result["problems"] = [f"unsupported project file: {exc}"]
        result["next_steps"] = ["Open a pqcheck manifest (.json) or a "
                                "project folder containing one."]
        return result
    result.update(_manifest_identity(manifest, str(path)))
    problems, steps = _readiness(manifest)
    result["ready"] = not problems
    result["problems"] = problems
    result["next_steps"] = steps
    return result


def run_project(path_str: str) -> dict:
    """Steps 4–6: run through the validated runner; return the report
    plus exportable artifacts (text / HTML / JSON / reproduction)."""
    from pqcheck.cli import _manifest_for_path, _report_json, run_manifest_validated

    manifest, source = _project_manifest(path_str)
    report = run_manifest_validated(
        manifest, list(manifest.algorithms or [None]), sorted(REGISTRY))
    result = _report_dict(report, source)
    result.update(_manifest_identity(manifest, source))
    result["kind"] = "real project target"
    reproduction = [f"# Reproduction for {manifest.target} @ {manifest.version}",
                    f"Manifest: {source}", ""]
    for claim in report.defects():
        alg = f" --algorithm {claim.subject.algorithm}" if claim.subject.algorithm else ""
        reproduction.append(
            f"python -m pqcheck reproduce \"{source}\" "
            f"--relation {claim.method.name}{alg}")
    if not report.defects():
        reproduction.append(
            f"python -m pqcheck run \"{source}\"   # full re-run")
    result["exports"] = {
        "text": report.to_text(),
        "html": report.to_html(),
        "json": __import__("json").dumps(_report_json(report), indent=2),
        "reproduction": "\n".join(reproduction) + "\n",
    }
    return result


def _project_manifest(path_str: str):
    from pathlib import Path

    from pqcheck.cli import _manifest_for_path

    raw = str(path_str or "").strip()
    path = Path(raw).expanduser()
    if path.is_dir():
        from pqcheck.discover import discover

        named = [c for c in discover(path)
                 if c.kind == "manifest" and c.manifest is not None]
        if named:
            return named[0].manifest, str(named[0].path)
    manifest = _manifest_for_path(raw, [])
    return manifest, str(path)


def _make_target(spec: str):
    """Return (target, display_name) for a whitelisted spec id."""
    kind, _, rest = spec.partition(":")
    if kind == "clean":
        factory = _clean_targets().get(rest)
        if factory is None:
            raise ValueError(f"unknown clean target {rest!r}")
        return factory(), rest
    if kind == "mutant":
        group, _, name = rest.partition(":")
        factory = _mutant_tables().get(group, {}).get(name)
        if factory is None:
            raise ValueError(f"unknown mutant {rest!r}")
        return factory(), f"{group}[{name}]"
    if kind == "boundary":
        from pqcheck.testing.precision import CASES
        for case in CASES:
            if case.label == rest:
                return case.make(), rest
        raise ValueError(f"unknown boundary target {rest!r}")
    raise ValueError(f"unknown target spec {spec!r}")


READER_VERDICTS = {
    "DEFECT_FOUND": "Finding — defect found",
    "NO_DEFECT_FOUND": "Check completed — no defect found",
    "INCONCLUSIVE": "Inconclusive — witness search found nothing (not a pass)",
    "NOT_REACHED": "Not run — nothing was established",
    "NOT_ANSWERABLE": "Not answerable for this target",
}


def _claim_dict(claim) -> dict:
    relation = REGISTRY.get(claim.method.name)
    cov = claim.coverage
    return {
        "reader_verdict": READER_VERDICTS[
            "INCONCLUSIVE" if (claim.verdict is Verdict.NO_DEFECT_FOUND
                                and claim.one_sided)
            else claim.verdict.value],
        "subject": str(claim.subject),
        "target": claim.subject.target,
        "commit": claim.subject.commit,
        "algorithm": claim.subject.algorithm,
        "property": claim.property,
        "verdict": claim.verdict.value,
        "one_sided": claim.one_sided,
        "method": claim.method.name,
        "oracle": claim.method.oracle,
        "ceiling": claim.ceiling,
        "evidence": claim.evidence,
        "reproduce": claim.reproduce,
        "notes": claim.notes,
        "premises": list(claim.premises),
        "false_positive_modes": list(
            getattr(relation, "false_positive_modes", ()) or ()),
        "coverage": {
            "units": cov.units if cov else 0,
            "exercised": cov.exercised if cov else "",
            "observed": cov.observed if cov else "",
        },
    }


def run_target(spec: str) -> dict:
    """Run all relations against one whitelisted target."""
    if spec == "manifest:python-reference":
        return _run_manifest()
    target, name = _make_target(spec)
    subject = Subject(target=name, commit=COMMIT)
    claims = [
        relation.run(target, subject, random.Random(f"web:{spec}:{rid}"))
        for rid, relation in sorted(REGISTRY.items())
    ]
    return _report_dict(Report(tuple(claims)), spec)


def _run_manifest() -> dict:
    from pathlib import Path

    from pqcheck.cli import open_target
    from pqcheck.manifest import Manifest
    manifest = Manifest.load(
        Path(__file__).resolve().parents[1] / "manifests" / "python-reference.json")
    claims = []
    for algorithm in manifest.algorithms:
        target = open_target(manifest, algorithm)
        subject = manifest.subject(algorithm)
        for rid, relation in sorted(REGISTRY.items()):
            claims.append(relation.run(
                target, subject, random.Random(f"web:manifest:{algorithm}:{rid}")))
    return _report_dict(Report(tuple(claims)), "manifest:python-reference")


def _report_dict(report: Report, spec: str) -> dict:
    buckets = {
        "DEFECT_FOUND": [], "NOT_REACHED": [],
        "NO_WITNESS_ESTABLISHES_NOTHING": [], "NO_DEFECT_FOUND": [],
        "NOT_ANSWERABLE": [],
    }
    for claim in report.claims:
        data = _claim_dict(claim)
        if claim.verdict is Verdict.NO_DEFECT_FOUND and claim.one_sided:
            buckets["NO_WITNESS_ESTABLISHES_NOTHING"].append(data)
        else:
            buckets[claim.verdict.value].append(data)
    gaps = buckets["NOT_REACHED"] + buckets["NOT_ANSWERABLE"]
    return {
        "target": spec,
        "revision": sorted({c.subject.commit for c in report.claims}),
        "counts": {k: len(v) for k, v in buckets.items()},
        "conclusive": report.is_conclusive_anywhere(),
        "buckets": buckets,
        # Coverage gaps are first-class output, never folded into clean.
        "gaps": gaps,
    }


def relations_data(query: str = "", fclass: str = "") -> list[dict]:
    out = []
    for rid, relation in sorted(REGISTRY.items()):
        fc = failure_class(rid)
        if query and query.lower() not in rid.lower() \
                and query.lower() not in relation.property.lower():
            continue
        if fclass and fc != fclass:
            continue
        out.append({
            "id": rid,
            "failure_class": fc,
            "property": relation.property,
            "requires": sorted(c.value for c in relation.requires),
            "needs_control": relation.needs_control,
            "constructs_probes": relation.constructs_probes,
            "one_sided": relation.one_sided,
            "ceiling": relation.ceiling,
            "false_positive_modes": list(relation.false_positive_modes),
        })
    return out


def backtest_data() -> dict:
    from pqcheck.backtest.corpus import CORPUS
    from pqcheck.backtest.report import disclosure_state, evaluate
    result = evaluate()
    return {
        "counts": result["counts"],
        "entries": [{
            "id": e.id, "title": e.title, "defect_class": e.defect_class,
            "grade": e.grade, "relations": list(e.relations),
            "ours": e.ours, "origin": e.origin, "note": e.note,
            "disclosure": disclosure_state(e),
        } for e in CORPUS],
        "by_class": result["by_class"],
        "work_queue": [e.id for e in result["work_queue"]],
        "disclosure": result["disclosure"],
    }


ADAPTERS_DATA = [
    {"language": "C / C++", "adapter": "c (binary path) or exec (argv)",
     "how": "Build pqcheck/adapters/c_harness.c against the library; the "
            "manifest names the binary and pqcheck appends <kind> <algorithm>."},
    {"language": "Rust", "adapter": "exec",
     "how": "Compile pqcheck/adapters/templates/rust_kem_sig_harness.rs "
            "with RustCrypto ml-kem/ml-dsa in the ADAPT sections; run via "
            "\"command\": [\"./rust_kem_sig_harness\"]."},
    {"language": "Java", "adapter": "exec",
     "how": "Compile pqcheck/adapters/templates/JavaKemSigHarness.java "
            "(javax.crypto.KEM / java.security.Signature); run via "
            "\"command\": [\"java\", \"-cp\", \"...\", \"JavaKemSigHarness\"]."},
    {"language": "JS (@noble/post-quantum)", "adapter": "noble (built in)",
     "how": "manifests/noble.json with node_cwd pointing at the install; "
            "the Node bridge loads algorithm submodules directly."},
    {"language": "Python", "adapter": "python (in-process) or exec (subprocess)",
     "how": "manifests/python-reference.json names a module plus a target "
            "class per algorithm; templates/python_harness.py shows the "
            "subprocess wire form for any Python library."},
    {"language": "Go / any other", "adapter": "exec",
     "how": "Any binary speaking the 6-verb line protocol (info, keygen, "
            "encaps, decaps, sign, verify, guard) plugs in unchanged."},
]


PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>pqcheck Assurance Workbench</title>
<style>
body{background:#101216;color:#e8e6df;font-family:Georgia,serif;margin:1.5em auto;max-width:72em;padding:0 1em;line-height:1.45}
h1{font-size:1.6em} code,select,button,input{font-family:Consolas,monospace}
button,select,input{background:#1b1e24;color:#e8e6df;border:1px solid #3a3f47;border-radius:5px;padding:.35em .6em}
nav button{margin-right:.4em} nav button.active{border-color:#c8b06a;color:#f0d48a}
table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #2c2f36;padding:.3em .5em;text-align:left;vertical-align:top}
.badge{font-family:Consolas,monospace;font-size:.85em;border:1px solid #3a3f47;border-radius:4px;padding:.05em .4em}
section{border:1px solid #2c2f36;border-radius:6px;padding:.8em 1em;margin:.7em 0;background:#15171c}
.meta{color:#b9b4a6}.hidden{display:none}
</style></head><body>
<h1>pqcheck Assurance Workbench</h1>
<p class="meta">Local only (127.0.0.1). No score is computed, ever.</p>
<nav>
<button data-tab="project" class="active">Project</button>
<button data-tab="reports">Shipped Manifest Reports</button>
<button data-tab="catalogue">Relation Catalogue</button>
<button data-tab="backtest">Historical Backtest Matrix</button>
<button data-tab="adapters">Multi-Language Adapters</button>
<button data-tab="demo">Demo / Self-test</button>
<button data-tab="about">About</button>
</nav>

<div id="tab-project">
<h2>Check a real project</h2>
<p class="meta">1. Open a local project folder or an existing pqcheck manifest.
2. We identify the target and check readiness before anything runs.
3. Checks run through the same validated runner as the CLI.
Recognizing source files does not mean we can test them.</p>
<p><input id="projpath" type="text" size="72" placeholder="C:\path\to\project  or  C:\path\to\manifest.json">
<button id="inspect">Open &amp; check readiness</button></p>
<p class="meta">New here? Open the sample project <code>examples/vulnerable-kem</code> —
it has a planted defect, so you can watch a finding happen on purpose.</p>
<div id="identity"></div>
<p><button id="runproj" disabled>Run checks</button>
<button id="exptext" disabled>Export report (.txt)</button>
<button id="exphtml" disabled>Export report (.html)</button>
<button id="expjson" disabled>Export report (.json)</button>
<button id="exprepro" disabled>Export reproduction instructions</button></p>
<p id="projsummary" class="meta"></p>
<div id="projreport"></div>
</div>

<div id="tab-about" class="hidden">
<h2>How pqcheck works, and why</h2>

<section><h3>Why this exists</h3>
<p>Post-quantum implementations fail quietly: a missing re-encryption check, a
non-canonical encoding, a hint index accepted out of order — the code still
round-trips, still passes its own tests, and is still broken. pqcheck exists to
look for exactly those quiet failures in code you are about to trust.</p></section>

<section><h3>How it works</h3>
<p><b>1. A manifest names the target.</b> A small JSON file pins the target, its
exact revision, an adapter, and its algorithms. pqcheck opens nothing else —
no network targets, no scanning.</p>
<p><b>2. An adapter speaks to the real implementation.</b> Harnesses forward
bytes into the actual library (C, Rust, Node/Noble, Python, or any program
speaking the line protocol). pqcheck never grades a reimplementation of your
code — including its own.</p>
<p><b>3. Relations ask questions with witnesses.</b> Each of the 34 relations
states one property ("no corrupted ciphertext decapsulates to the honest
secret") and probes the target for a counterexample. A finding always comes
with a witness: the concrete bytes that misbehaved.</p>
<p><b>4. Verdicts are gated.</b> A claim of "no defect" must have earned it:
real coverage observed by the runner, and for witness searches, a live control
proving the probe could have fired. Claims that cannot meet the gate are
refused or downgraded at construction time.</p></section>

<section><h3>How to read results</h3>
<table><thead><tr><th>What you see</th><th>Technical verdict</th><th>What it means</th></tr></thead>
<tbody>
<tr><td>Finding — defect found</td><td><code>DEFECT_FOUND</code></td><td>A witness misbehaved. Reproduce it, then fix the code.</td></tr>
<tr><td>Check completed — no defect found</td><td><code>NO_DEFECT_FOUND</code></td><td>The check ran both directions and found nothing, within its stated ceiling.</td></tr>
<tr><td>Inconclusive — witness search found nothing</td><td><code>NO_DEFECT_FOUND</code> (one-sided)</td><td>A search that finds nothing proves nothing. Never a pass.</td></tr>
<tr><td>Not run — nothing was established</td><td><code>NOT_REACHED</code></td><td>The target could not be opened or the check did not execute.</td></tr>
<tr><td>Not answerable for this target</td><td><code>NOT_ANSWERABLE</code></td><td>The question does not apply to this interface, or the adapter cannot express it.</td></tr>
</tbody></table>
<p>There is <b>no score and no percentage</b>. Dividing passed checks by total
checks measures how much tool you ran, not how safe the code is. One finding
outweighs any number of quiet checks.</p></section>

<section><h3>Readiness before running</h3>
<p>Opening a project first identifies the target and checks provenance: the
manifest's pinned revision, the harness actually present, the version the
binary reports about itself. A mismatch stops the run with an explanation
instead of relabeling one build as another. Recognizing source files in a
folder is discovery only — it never means the code can be tested.</p></section>

<section><h3>What pqcheck cannot establish</h3>
<p>It does not prove implementations correct, constant-time, or memory-safe.
It does not audit stateful signature schemes, streaming/hash boundary
behaviour, or sampler mathematics. Every claim in a report carries its own
"does not establish" line — read those before quoting a result. Historical
defects the relations miss are listed openly in the Backtest tab's work queue
rather than smoothed over.</p></section>

<section><h3>Safety posture</h3>
<p>pqcheck is a defensive checker for your own code. It runs locally
(127.0.0.1 only), works from local manifests, refuses secret-shaped material
in its reports so findings are safe to paste into bug trackers, and produces
no key material, forgeries, or exploit output. The Demo / Self-test tab holds
the toy fixtures and planted mutants used to validate pqcheck itself; the
folder <code>examples/vulnerable-kem</code> is a sample project with a planted
defect so you can watch a finding happen on purpose.</p></section>
</div>

<div id="tab-demo" class="hidden">
<h2>Demo / Self-test</h2>
<p class="meta">Toy fixtures, planted mutants, and boundary cases for demonstrating
and self-testing pqcheck itself. Nothing here is a real project target.</p>
<p><select id="target"></select> <button id="run">Run all relations</button></p>
<p id="summary" class="meta"></p>
<div id="report"></div>
</div>

<div id="tab-catalogue" class="hidden">
<p><input id="q" type="search" placeholder="search id or property">
<select id="fclass"><option value="">all failure classes</option></select></p>
<table><thead><tr><th>id</th><th>class</th><th>requires</th><th>control</th>
<th>probes</th><th>one-sided</th><th>property / ceiling / false-positive modes</th></tr></thead>
<tbody id="relbody"></tbody></table>
</div>

<div id="tab-backtest" class="hidden">
<p id="btcounts" class="meta"></p>
<table><thead><tr><th>grade</th><th>id</th><th>defect class</th><th>title</th><th>disclosure (derived)</th></tr></thead>
<tbody id="btbody"></tbody></table>
<h3>Work queue (MISSED)</h3><ul id="queue"></ul>
<h3>By defect class</h3><div id="byclass"></div>
</div>

<div id="tab-adapters" class="hidden"><div id="adapters"></div></div>

<div id="tab-reports" class="hidden">
<p class="meta">Real generated reports for shipped manifests. Each report shows the target,
its pinned revision, the findings, the coverage gaps (NOT_REACHED / NOT_ANSWERABLE, never
counted as clean), and per-claim reproduction instructions. Fixtures are labelled as fixtures.</p>
<p><select id="manifest"></select> <button id="runmanifest">Generate report</button></p>
<p id="mfsummary" class="meta"></p>
<div id="mfreport"></div>
</div>

<script>
const $=id=>document.getElementById(id);
document.querySelectorAll("nav button").forEach(b=>b.addEventListener("click",()=>{
 document.querySelectorAll("nav button").forEach(x=>x.classList.remove("active"));
 b.classList.add("active");
 ["project","reports","catalogue","backtest","adapters","demo","about"].forEach(t=>$("tab-"+t).classList.toggle("hidden",t!==b.dataset.tab));
}));
function esc(s){const d=document.createElement("div");d.textContent=String(s??"");return d.innerHTML}
async function loadTargets(){
 const d=await (await fetch("/api/targets")).json();
 const sel=$("target");sel.innerHTML="";
 const add=(label,spec)=>{const o=document.createElement("option");o.value=spec;o.textContent=label;sel.appendChild(o)};
 d.clean.forEach(n=>add("[toy fixture] clean: "+n,"clean:"+n));
 d.mutants.forEach(n=>add("[toy fixture] mutant: "+n,"mutant:"+n));
 d.boundary.forEach(n=>add("[toy fixture] boundary: "+n,"boundary:"+n));
 d.manifest.forEach(n=>add("[reference fixture] manifest: "+n,"manifest:"+n));
}
async function loadManifests(){
 const d=await (await fetch("/api/manifests")).json();
 const sel=$("manifest");sel.innerHTML="";
 d.forEach(m=>{const o=document.createElement("option");o.value=m.name;
  o.textContent=`${m.name} — ${m.target} @ ${m.revision} [${m.kind}]`;sel.appendChild(o)});
}
$("runmanifest").addEventListener("click",async()=>{
 $("mfsummary").textContent="running...";$("mfreport").innerHTML="";
 const r=await (await fetch("/api/run-manifest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:$("manifest").value})})).json();
 if(r.error){$("mfsummary").textContent="not established: "+r.error;$("mfreport").innerHTML="";return}
 $("mfsummary").textContent=`${r.target} @ revision ${r.revision} [${r.kind||"manifest target"}] | `+
  Object.entries(r.counts).map(([k,v])=>k+": "+v).join(" | ")+(r.conclusive?" | conclusive somewhere":" | ESTABLISHED NOTHING");
 $("mfreport").innerHTML=renderBuckets(r);
});
let lastProject=null;
function download(name, text, type){
 const a=document.createElement("a");
 a.href=URL.createObjectURL(new Blob([text],{type:type||"text/plain"}));
 a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href), 5000);
}
$("inspect").addEventListener("click",async()=>{
 $("identity").innerHTML="checking...";$("runproj").disabled=true;
 const r=await (await fetch("/api/project/inspect",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:$("projpath").value})})).json();
 if(r.error){$("identity").innerHTML=`<section><p>could not open: ${esc(r.error)}</p></section>`;return}
 const id=r.target?`<p><b>Target:</b> ${esc(r.target)} &nbsp; <b>Revision:</b> <code>${esc(r.revision)}</code><br>
  <b>Adapter:</b> ${esc(r.adapter)} &nbsp; <b>Algorithms:</b> ${esc((r.algorithms||[]).join(", ")||"(none)")}<br>
  <b>Platform:</b> ${esc(r.platform)} &nbsp; <b>Source:</b> <code>${esc(r.source||r.input)}</code></p>`:
  `<p class="meta">No testable target identified in <code>${esc(r.input)}</code>.</p>`;
 const probs=(r.problems||[]).map(p=>`<li>${esc(p)}</li>`).join("");
 const steps=(r.next_steps||[]).map(s=>`<li>${esc(s)}</li>`).join("");
 const cands=(r.candidates||[]).map(c=>`<li><code>${esc(c.path)}</code> [${esc(c.kind)}]${c.ready?"":" — not ready"}</li>`).join("");
 $("identity").innerHTML=`<section>${id}
  <p><b>Readiness:</b> ${r.ready?'<span class="badge">ready</span>':'<span class="badge">not ready — nothing has run yet</span>'}</p>
  ${probs?`<p><b>What is missing:</b></p><ul>${probs}</ul>`:""}
  ${steps?`<p><b>Exact next step:</b></p><ul>${steps}</ul>`:""}
  ${cands?`<p class="meta"><b>Recognized in this folder</b> (recognition is not testability):</p><ul>${cands}</ul>`:""}</section>`;
 $("runproj").disabled=!r.ready;
});
$("runproj").addEventListener("click",async()=>{
 $("projsummary").textContent="running checks through the validated runner...";$("projreport").innerHTML="";
 const r=await (await fetch("/api/project/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:$("projpath").value})})).json();
 if(r.error){$("projsummary").textContent="not established: "+r.error;return}
 lastProject=r;
 $("projsummary").textContent=`${r.target} @ revision ${r.revision} | adapter ${r.adapter} | ${r.platform} | `+
  Object.entries(r.counts).map(([k,v])=>k+": "+v).join(" | ")+(r.conclusive?" | conclusive somewhere":" | ESTABLISHED NOTHING");
 $("projreport").innerHTML=renderBuckets(r);
 ["exptext","exphtml","expjson","exprepro"].forEach(i=>$(i).disabled=false);
});
$("exptext").addEventListener("click",()=>lastProject&&download("pqcheck-report.txt",lastProject.exports.text));
$("exphtml").addEventListener("click",()=>lastProject&&download("pqcheck-report.html",lastProject.exports.html,"text/html"));
$("expjson").addEventListener("click",()=>lastProject&&download("pqcheck-report.json",lastProject.exports.json,"application/json"));
$("exprepro").addEventListener("click",()=>lastProject&&download("pqcheck-reproduction.md",lastProject.exports.reproduction));
const HEADINGS={DEFECT_FOUND:"Findings",NO_DEFECT_FOUND:"Completed checks — no defect found",NO_WITNESS_ESTABLISHES_NOTHING:"Inconclusive — witness search found nothing (not a pass)",NOT_REACHED:"Not run — nothing was established",NOT_ANSWERABLE:"Not answerable for this target"};
function renderBuckets(r){
 const order=["DEFECT_FOUND","NO_DEFECT_FOUND","NO_WITNESS_ESTABLISHES_NOTHING","NOT_REACHED","NOT_ANSWERABLE"];
 return order.map(b=>`<h3>${HEADINGS[b]} (${r.buckets[b].length}) <span class="meta">[${b}]</span></h3>`+(r.buckets[b].map(claimHtml).join("")||'<p class="meta">none</p>')).join("")+
  `<h3>Coverage gaps (${(r.gaps||[]).length}) — checks that did not run or cannot be answered; never counted as success</h3>`+
  ((r.gaps||[]).map(claimHtml).join("")||'<p class="meta">none</p>');
}
function claimHtml(c){
 return `<section><p><span class="badge">${esc(c.reader_verdict||c.verdict)}</span> <span class="meta">[technical verdict: ${esc(c.verdict)}]</span> <code>${esc(c.subject)}</code></p>
 <p>${esc(c.property)}</p>
 <p class="meta">method ${esc(c.method)} | oracle ${esc(c.oracle||"none")} | units ${c.coverage.units} | exercised ${esc(c.coverage.exercised)} | runner ${esc(c.coverage.observed)}</p>
 ${c.evidence?`<p>evidence: ${esc(c.evidence)}</p>`:""}
 ${c.reproduce?`<p>reproducer: <code>${esc(c.reproduce)}</code></p>`:""}
 <p class="meta">false_positive_modes: ${esc((c.false_positive_modes||[]).join("; ")||"none declared")}</p>
 <p class="meta">does not establish: ${esc(c.ceiling)}</p></section>`;
}
$("run").addEventListener("click",async()=>{
 $("summary").textContent="running...";$("report").innerHTML="";
 const r=await (await fetch("/api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({target:$("target").value})})).json();
 if(r.error){$("summary").textContent="error: "+r.error;return}
 $("summary").textContent=Object.entries(r.counts).map(([k,v])=>k+": "+v).join(" | ")+(r.conclusive?" | conclusive somewhere":" | ESTABLISHED NOTHING");
 $("report").innerHTML=renderBuckets(r);
});
async function loadRelations(){
 const q=$("q").value,f=$("fclass").value;
 const d=await (await fetch("/api/relations?q="+encodeURIComponent(q)+"&class="+encodeURIComponent(f))).json();
 $("relbody").innerHTML=d.map(r=>`<tr><td><code>${esc(r.id)}</code></td><td>${esc(r.failure_class)}</td>
 <td>${esc(r.requires.join(", ")||"-")}</td><td>${r.needs_control?"control":"loud"}</td>
 <td>${r.constructs_probes?"probe_control":""}</td><td>${r.one_sided?"yes":""}</td>
 <td>${esc(r.property)}<br><span class="meta">not: ${esc(r.ceiling)}</span>
 ${r.false_positive_modes.length?`<br><span class="meta">fp: ${esc(r.false_positive_modes.join("; "))}</span>`:""}</td></tr>`).join("");
}
$("q").addEventListener("input",loadRelations);
$("fclass").addEventListener("change",loadRelations);
async function loadBacktest(){
 const d=await (await fetch("/api/backtest")).json();
 $("btcounts").textContent="per grade (never summed): "+Object.entries(d.counts).map(([k,v])=>k+"="+v).join(" ");
 $("btbody").innerHTML=d.entries.map(e=>`<tr><td><span class="badge">${esc(e.grade)}</span></td>
 <td><code>${esc(e.id)}</code></td><td>${esc(e.defect_class)}</td><td>${esc(e.title)}</td>
 <td class="meta">${esc(e.disclosure)}</td></tr>`).join("");
 $("queue").innerHTML=d.work_queue.map(id=>`<li><code>${esc(id)}</code></li>`).join("");
 $("byclass").innerHTML=Object.entries(d.by_class).map(([k,v])=>`<p><code>${esc(k)}</code>: in_scope=${v.in_scope} DEMONSTRATED=${v.DEMONSTRATED}${v.gap?' <span class="badge">&lt;-- gap</span>':""}</p>`).join("");
}
async function loadAdapters(){
 const d=await (await fetch("/api/adapters")).json();
 $("adapters").innerHTML=d.map(a=>`<section><p><b>${esc(a.language)}</b> — ${esc(a.adapter)}</p><p>${esc(a.how)}</p></section>`).join("");
}
(async()=>{await loadTargets();await loadManifests();
 const fc=new Set((await (await fetch("/api/relations")).json()).map(r=>r.failure_class));
 fc.forEach(c=>{const o=document.createElement("option");o.value=c;o.textContent=c;$("fclass").appendChild(o)});
 await loadRelations();await loadBacktest();await loadAdapters();})();
</script>
</body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "pqcheck-web/1"

    def log_message(self, *args):  # keep the console quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def do_GET(self):
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if parsed.path == "/api/targets":
                return self._json(targets_catalog())
            if parsed.path == "/api/relations":
                qs = parse_qs(parsed.query)
                return self._json(relations_data(
                    qs.get("q", [""])[0], qs.get("class", [""])[0]))
            if parsed.path == "/api/backtest":
                return self._json(backtest_data())
            if parsed.path == "/api/adapters":
                return self._json(ADAPTERS_DATA)
            if parsed.path == "/api/manifests":
                return self._json(manifests_data())
            return self._json({"error": "not found"}, 404)
        except Exception as exc:  # honest error, never a stack trace page
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path not in ("/api/run", "/api/run-manifest",
                               "/api/project/inspect", "/api/project/run"):
            return self._json({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 65536:
                return self._json({"error": "request too large"}, 413)
            payload = json.loads(self.rfile.read(length) or b"{}")
            if parsed.path == "/api/project/inspect":
                return self._json(inspect_project(str(payload.get("path", ""))))
            if parsed.path == "/api/project/run":
                return self._json(run_project(str(payload.get("path", ""))))
            if parsed.path == "/api/run-manifest":
                return self._json(run_named_manifest(str(payload.get("name", ""))))
            spec = str(payload.get("target", ""))
            return self._json(run_target(spec))
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        except Exception as exc:
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


def serve(port: int = 8420) -> int:
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"pqcheck workbench: http://127.0.0.1:{port}/ (loopback only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0

