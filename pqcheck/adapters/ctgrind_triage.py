"""Triages Valgrind ctgrind logs against known-issue / benign lists.

    python ctgrind_triage.py <valgrind.log> <ALG>

Reports matching neither list are UNEXPLAINED. An UNEXPLAINED report is
not a finding: marking a public value as secret in a harness produces
exactly this shape, so check the harness first.
"""
from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path

WARNING = (
    "UNEXPLAINED reports are not findings. Check the harness first -- "
    "marking a public value as secret produces exactly this shape."
)

_FRAME_RE = re.compile(r"^(?:==\d+==)?\s*(?:at|by)\s+0x[0-9A-Fa-f]+:\s+(\S+)\s*\(")


def report_frames(log) -> list[list[str]]:
    """Group stack-frame function names by uninitialised-value report."""
    text = Path(log).read_text(encoding="utf-8", errors="replace") if _looks_like_path(log) else str(log)
    reports: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if "uninitialised value" in line.lower() or "conditional jump or move depends" in line.lower():
            if current:
                reports.append(current)
            current = []
            continue
        if current is not None:
            match = _FRAME_RE.match(line)
            if match:
                current.append(match.group(1))
            elif line.strip() == "" and current:
                reports.append(current)
                current = None
    if current:
        reports.append(current)
    return reports


def _looks_like_path(value) -> bool:
    try:
        return Path(value).is_file()
    except (OSError, ValueError):
        return False


def _load_list(name: str) -> list[dict]:
    for candidate in (Path(__file__).with_name(name), Path.cwd() / name):
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, json.JSONDecodeError):
                return []
    return []


def _matches(entry: dict, alg: str, frames: list[str]) -> bool:
    if entry.get("alg") not in (None, alg, "*"):
        return False
    pattern = entry.get("fun", "*")
    return any(fnmatch.fnmatchcase(frame, pattern) for frame in frames)


def triage(log, alg: str) -> list[tuple[str, list[str]]]:
    issues = _load_list("ctgrind_issues.json")
    passes = _load_list("ctgrind_passes.json")
    results = []
    for frames in report_frames(log):
        if any(_matches(entry, alg, frames) for entry in issues):
            label = "KNOWN ISSUE"
        elif any(_matches(entry, alg, frames) for entry in passes):
            label = "BENIGN"
        else:
            label = "UNEXPLAINED"
        results.append((label, frames))
    return results


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: python ctgrind_triage.py <valgrind.log> <ALG>")
        return 3
    log_path = Path(args[0])
    if not log_path.is_file():
        # A missing log means the tool run failed or crashed; that is
        # an ERROR, never a pass.
        print(f"ERROR: valgrind log not found: {log_path} "
              "(tool error or crash; this is not a PASS)")
        return 2
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if "==" not in text and "valgrind" not in text.lower():
        print("ERROR: log contains no valgrind output "
              "(tool error or crash; this is not a PASS)")
        return 2
    results = triage(text, args[1])
    if not results:
        print("no uninitialised-value reports parsed from the log")
        return 0
    status = 0
    for label, frames in results:
        top = frames[0] if frames else "?"
        print(f"{label}: top frame {top} ({len(frames)} frames)")
        if label == "UNEXPLAINED":
            print(WARNING)
            status = 1
        elif label == "KNOWN ISSUE":
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
