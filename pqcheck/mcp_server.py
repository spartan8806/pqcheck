"""Read-only MCP server (stdio JSON-RPC, stdlib only).

    python -m pqcheck.mcp_server

Tools exposed:
  - pqcheck.relations : list the registered deterministic relations
  - pqcheck.run_fixture: run relations against in-process toy
    fixtures (clean targets, planted mutants, precision boundary
    cases) and return the report counts/claims
  - pqcheck.backtest  : historical defect-class accounting
  - pqcheck.explain   : plain-English ranking of a fixture report

Read-only by construction: there is no tool that writes files,
opens a manifest, spawns a command, or touches the network. Real
targets only ever run through the operator's own CLI manifest flow,
never through this server.
"""
from __future__ import annotations

import json
import random
import sys

import pqcheck.relations  # noqa: F401  (populates REGISTRY)
from pqcheck.relations.base import REGISTRY
from pqcheck.verdict import Report, Subject

_COMMIT = "0.1.0b1"
_TOOLS = {}


def _tool(name, description, schema):
    def deco(fn):
        _TOOLS[name] = (description, schema, fn)
        return fn
    return deco


@_tool("pqcheck.relations",
       "List registered deterministic relations and their requirements.",
       {"type": "object", "properties": {}})
def _relations(_args):
    return [{"id": rid,
             "property": r.property,
             "requires": sorted(c.value for c in r.requires),
             "one_sided": bool(r.one_sided)}
            for rid, r in sorted(REGISTRY.items())]


def _make_target(spec: str):
    from pqcheck.web import _make_target as make
    return make(spec)


@_tool("pqcheck.run_fixture",
       "Run all relations against a whitelisted in-process fixture "
       "spec ('clean:<Name>', 'mutant:<GROUP>:<name>', "
       "'boundary:<label>') and return report counts.",
       {"type": "object",
        "properties": {"spec": {"type": "string"}},
        "required": ["spec"]})
def _fixture_report(spec: str) -> Report:
    if ":" not in spec or any(ch in spec for ch in "/\\;|&$`\"'<>"):
        raise ValueError("spec must be a whitelisted fixture id")
    target, name = _make_target(spec)
    subject = Subject(target=name, commit=_COMMIT)
    claims = [rel.run(target, subject, random.Random(f"mcp:{spec}:{rid}"))
              for rid, rel in sorted(REGISTRY.items())]
    return Report(tuple(claims))


def _run_fixture(args):
    spec = str(args.get("spec", ""))
    report = _fixture_report(spec)
    return {"spec": spec, "counts": report.counts(),
            "conclusive": report.is_conclusive_anywhere(),
            "claims": [{"method": c.method.name,
                        "verdict": c.verdict.value,
                        "property": c.property}
                       for c in report.claims]}


@_tool("pqcheck.backtest",
       "Historical defect-class accounting (grades never summed).",
       {"type": "object", "properties": {}})
def _backtest(_args):
    from pqcheck.backtest.report import evaluate
    result = evaluate()
    return {"counts": result["counts"], "by_class": result["by_class"]}


@_tool("pqcheck.explain",
       "Plain-English ranked explanation of a fixture report. "
       "Explanation never changes a verdict.",
       {"type": "object",
        "properties": {"spec": {"type": "string"}},
        "required": ["spec"]})
def _explain(args):
    from pqcheck.ai import explain_report
    spec = str(args.get("spec", ""))
    return {"spec": spec,
            "explanation": explain_report(_fixture_report(spec))}


def _handle(request: dict) -> dict | None:
    method = request.get("method")
    rid = request.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "pqcheck-readonly", "version": _COMMIT}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": name, "description": desc,
             "inputSchema": schema}
            for name, (desc, schema, _fn) in sorted(_TOOLS.items())]}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name", "")
        entry = _TOOLS.get(name)
        if entry is None:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32602, "message": f"unknown tool {name!r}"}}
        try:
            result = entry[2](params.get("arguments") or {})
        except Exception as exc:
            return {"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32000,
                "message": f"{type(exc).__name__}: {exc}"}}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text",
                         "text": json.dumps(result)}],
            "structuredContent": result}}
    return {"jsonrpc": "2.0", "id": rid, "error": {
        "code": -32601, "message": f"unknown method {method!r}"}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
