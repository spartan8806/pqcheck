"""Single-file HTML assurance report.

Same epistemic rules as Report.to_text(): defects and not-reached
claims first, one-sided NO_DEFECT_FOUND separated from conclusive
NO_DEFECT_FOUND, no score or grade anywhere, every text field HTML
escaped, and the secret-material floor applied to the result.
"""
from __future__ import annotations

import html

from pqcheck.verdict import ClaimError, Report, Verdict, looks_like_secret_material

_CSS = """
body{background:#101216;color:#e8e6df;font-family:Georgia,serif;margin:2em auto;max-width:62em;padding:0 1em;line-height:1.45}
h1{font-size:1.7em} h2{font-size:1.25em;margin-top:1.6em}
code,.mono{font-family:Consolas,monospace;font-size:.92em}
section{border:1px solid #2c2f36;border-radius:6px;padding:.8em 1em;margin:.8em 0;background:#15171c}
.defect{border-color:#8c3a34} .notreached{border-color:#8a6d2f}
.clean{border-color:#3f5a46} .witness{border-color:#5a4a72} .scope{border-color:#3a3f47}
.tag{font-weight:bold} .meta{color:#b9b4a6}
.callout{border:1px dashed #6b7280;border-radius:6px;padding:.8em 1em;background:#171a20}
button{font:inherit;background:#22262e;color:#e8e6df;border:1px solid #3a3f47;border-radius:5px;padding:.3em .8em;cursor:pointer}
.hidden{display:none}
"""


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _score_refusal() -> str:
    try:
        Report(()).score()
    except NotImplementedError as exc:
        return str(exc)
    return "score refused"


def _claim_html(claim) -> str:
    cov = claim.coverage
    coverage = (
        f"units: {_esc(cov.units)} | basis: {_esc(cov.exercised)} | "
        f"runner_calls: {_esc(cov.observed)}"
        if cov is not None else "units: 0 | basis: - | runner_calls: -"
    )
    modes = ("; ".join(_esc(m) for m in claim.false_positive_modes)
             if getattr(claim, "false_positive_modes", ()) else "")
    if not modes:
        from pqcheck.relations.base import REGISTRY
        relation = REGISTRY.get(claim.method.name)
        declared = getattr(relation, "false_positive_modes", ()) if relation else ()
        modes = "; ".join(_esc(m) for m in declared) if declared else "none declared"
    subject = claim.subject
    subject_line = f"{_esc(subject.target)} @ {_esc(subject.commit)}"
    if subject.algorithm:
        subject_line += f" / {_esc(subject.algorithm)}"
    lines = [
        "<section>",
        f'<p><span class="tag">{_esc(claim.verdict.value)}</span> '
        f'<span class="mono">{subject_line}</span></p>',
        f"<p>property: {_esc(claim.property)}</p>",
        f'<p class="meta">method: {_esc(claim.method.name)} | '
        f"oracle: {_esc(claim.method.oracle or 'none (self-referential)')} | "
        f"{coverage}</p>",
    ]
    if claim.evidence:
        lines.append(f"<p>evidence: {_esc(claim.evidence)}</p>")
    if claim.reproduce:
        lines.append(f"<p>reproducer: <code>{_esc(claim.reproduce)}</code></p>")
    if claim.notes:
        lines.append(f"<p>notes: {_esc(claim.notes)}</p>")
    for premise in claim.premises:
        lines.append(f"<p>premise: {_esc(premise)}</p>")
    lines.append(f"<p>false_positive_modes: {modes}</p>")
    lines.append(f"<p>ceiling (does not establish): {_esc(claim.ceiling)}</p>")
    lines.append("</section>")
    return "\n".join(lines)


def report_to_html(report: Report) -> str:
    defects = [c for c in report.claims if c.verdict is Verdict.DEFECT_FOUND]
    not_reached = [c for c in report.claims if c.verdict is Verdict.NOT_REACHED]
    witness = [c for c in report.claims
               if c.verdict is Verdict.NO_DEFECT_FOUND and c.one_sided]
    clean = [c for c in report.claims
             if c.verdict is Verdict.NO_DEFECT_FOUND and not c.one_sided]
    scope = [c for c in report.claims if c.verdict is Verdict.NOT_ANSWERABLE]

    out = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>pqcheck assurance report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>pqcheck assurance report</h1>",
    ]
    if not report.is_conclusive_anywhere():
        out.append('<p class="tag">*** THIS RUN ESTABLISHED NOTHING ***</p>')
    out.append(
        '<div class="callout"><button id="scoreBtn" type="button">'
        "Why is there no percentage score?</button>"
        f'<p id="scoreWhy" class="hidden">{_esc(_score_refusal())}</p></div>'
    )
    out.append("<script>document.getElementById('scoreBtn').addEventListener("
               "'click',function(){document.getElementById('scoreWhy')"
               ".classList.toggle('hidden');});</script>")

    def bucket(title, claims, cls):
        out.append(f'<h2 class="{cls}">{title}: {len(claims)}</h2>')
        for claim in claims:
            out.append(f'<div class="{cls}">{_claim_html(claim)}</div>')

    bucket("DEFECT FOUND", defects, "defect")
    bucket("NOT REACHED", not_reached, "notreached")
    bucket("NO DEFECT FOUND (one-sided — establishes nothing)", witness, "witness")
    bucket("NO DEFECT FOUND", clean, "clean")
    bucket("NOT ANSWERABLE (out of scope for this tool)", scope, "scope")
    if report.ai_receipt:
        r = report.ai_receipt
        created, wiped = r.get("ephemeral_temp_dirs_created"), r.get("ephemeral_temp_dirs_wiped")
        wipe_line = ("100% wiped, 0 wild PoCs on disk" if created == wiped
                     else "WIPE INCOMPLETE")
        out.append(
            '<div class="scope"><h2>Muse AI expansion</h2>'
            f"<p>mode: {_esc(str(r.get('mode')))} "
            f"(model {_esc(str(r.get('model')))})<br>"
            f"core: {_esc(str(r.get('core_relations_ran')))} relations, "
            f"{_esc(str(r.get('core_calls_executed')))} calls executed, "
            f"estimated tokens saved: {_esc(str(r.get('estimated_tokens_saved')))}<br>"
            f"candidates: proposed {_esc(str(r.get('candidates_proposed')))}, "
            f"rejected by clean control "
            f"{_esc(str(r.get('candidates_rejected_by_clean_control')))}, "
            f"verified {_esc(str(r.get('candidates_verified')))}<br>"
            f"ephemeral temp dirs: created {_esc(str(created))}, "
            f"wiped {_esc(str(wiped))} ({wipe_line})</p></div>")
    out.append("</body></html>")
    text = "\n".join(out)
    kind = looks_like_secret_material(text)
    if kind is not None:
        raise ClaimError(
            f"HTML report contains a contiguous {kind}-shaped blob; "
            "reports must be safe to paste into public bug trackers")
    return text
