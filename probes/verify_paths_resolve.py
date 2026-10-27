#!/usr/bin/env python3
"""Manifest paths resolve relative to the manifest, with ~ and ${ENV} expanded."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import check, passed  # noqa: E402

from pqcheck.manifest import Manifest  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    path = Path(td) / "manifest.json"
    path.write_text(json.dumps(
        {"target": "x", "version": "1.0.0", "adapter": "c", "harness": "./build/harness",
         "algorithms": ["kem:ML-KEM-768"]}), encoding="utf-8")
    manifest = Manifest.load(path)
    check(manifest.harness == Path(td) / "build" / "harness",
          f"harness resolved to {manifest.harness}, not relative to the manifest directory")
    print("relative harness path resolves against the manifest's directory")
    os.environ["PQCHECK_PROBE_DIR"] = td
    manifest2 = Manifest({"target": "x", "version": "1.0.0", "adapter": "noble",
                          "node_cwd": "${PQCHECK_PROBE_DIR}", "algorithms": ["ml-kem-768"]}, path)
    check(str(manifest2.node_cwd) == td, f"${{ENV}} did not expand: {manifest2.node_cwd}")
    print("${ENV} in node_cwd expands")

# --- documentation paths -------------------------------------------------
# Every relative Markdown link and every repo-shaped backtick path in
# docs/*.md and the top-level README must resolve to a real file.
import re  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
PATH_RE = re.compile(r"`((?:\\.\\./|pqcheck/|probes/|manifests/|tools/|docs/|tests/)[^`\s]+)`")
EXTS = (".py", ".md", ".json", ".sh", ".toml", ".yml", ".mjs", ".c", ".h", ".rs")

checked = 0
for md in sorted((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"]:
    text = md.read_text(encoding="utf-8")
    for link in LINK_RE.findall(text):
        if "://" in link or link.startswith("mailto:"):
            continue
        target = (md.parent / link).resolve()
        check(target.exists(), f"{md.name}: link {link!r} does not resolve")
        checked += 1
    for token in PATH_RE.findall(text):
        if not token.endswith(EXTS) and not token.endswith("/"):
            continue
        base = ROOT if not token.startswith("../") else md.parent
        target = (base / token).resolve()
        check(target.exists(), f"{md.name}: path {token!r} does not resolve")
        checked += 1
check(checked > 20, f"suspiciously few doc paths checked ({checked})")
print(f"documentation paths resolve ({checked} links/paths checked)")
passed("manifest and documentation paths resolve")
