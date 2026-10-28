"""Local browser workbench: stdlib only, bound to 127.0.0.1.

    python -m pqcheck web [--port 8420]

Defensive local use only: the server binds the loopback interface,
exposes only whitelisted in-repository targets (clean toys, planted
mutants, boundary fixtures, and the shipped python-reference
manifest), and never opens arbitrary paths or commands.
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


def _claim_dict(claim) -> dict:
    relation = REGISTRY.get(claim.method.name)
    cov = claim.coverage
    return {
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
    """Run all 32 relations against one whitelisted target."""
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
<button data-tab="runner" class="active">Live Target Runner</button>
<button data-tab="catalogue">32-Relation Catalogue</button>
<button data-tab="backtest">Historical Backtest Matrix</button>
<button data-tab="adapters">Multi-Language Adapters</button>
<button data-tab="reports">Generated Reports</button>
</nav>

<div id="tab-runner">
<p><select id="target"></select> <button id="run">Run all 32 relations</button></p>
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
 ["runner","catalogue","backtest","adapters","reports"].forEach(t=>$("tab-"+t).classList.toggle("hidden",t!==b.dataset.tab));
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
 const order=["DEFECT_FOUND","NOT_REACHED","NO_WITNESS_ESTABLISHES_NOTHING","NO_DEFECT_FOUND","NOT_ANSWERABLE"];
 $("mfreport").innerHTML=order.map(b=>`<h3>${b} (${r.buckets[b].length})</h3>`+(r.buckets[b].map(claimHtml).join("")||'<p class="meta">none</p>')).join("")+
  `<h3>Coverage gaps (${(r.gaps||[]).length}) — not clean, not counted above as success</h3>`+
  ((r.gaps||[]).map(claimHtml).join("")||'<p class="meta">none</p>');
});
function claimHtml(c){
 return `<section><p><span class="badge">${esc(c.verdict)}</span> <code>${esc(c.subject)}</code></p>
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
 const order=["DEFECT_FOUND","NOT_REACHED","NO_WITNESS_ESTABLISHES_NOTHING","NO_DEFECT_FOUND","NOT_ANSWERABLE"];
 $("report").innerHTML=order.map(b=>`<h3>${b} (${r.buckets[b].length})</h3>`+(r.buckets[b].map(claimHtml).join("")||'<p class="meta">none</p>')).join("");
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
        if parsed.path not in ("/api/run", "/api/run-manifest"):
            return self._json({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 65536:
                return self._json({"error": "request too large"}, 413)
            payload = json.loads(self.rfile.read(length) or b"{}")
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

