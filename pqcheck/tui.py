"""Dependency-free interactive terminal UI (ANSI + msvcrt/termios)."""
from __future__ import annotations

import sys

from pqcheck.verdict import Verdict

_RESET = "\x1b[0m"
_STATES = {
    # worst first; NO_DEFECT_FOUND is plain white, never green
    Verdict.DEFECT_FOUND: ("DEFECT_FOUND", "\x1b[1;31m"),
    Verdict.NOT_REACHED: ("NOT_REACHED", "\x1b[33m"),
    "NO_WITNESS_ESTABLISHES_NOTHING": ("NO_WITNESS_ESTABLISHES_NOTHING", "\x1b[33m"),
    Verdict.NO_DEFECT_FOUND: ("NO_DEFECT_FOUND", "\x1b[37m"),
    Verdict.NOT_ANSWERABLE: ("NOT_ANSWERABLE", "\x1b[2m"),
}
_ORDER = ["DEFECT_FOUND", "NOT_REACHED", "NO_WITNESS_ESTABLISHES_NOTHING", "NO_DEFECT_FOUND", "NOT_ANSWERABLE"]


def state_of(claim) -> tuple[str, str]:
    if claim.verdict is Verdict.NO_DEFECT_FOUND and claim.one_sided:
        return _STATES["NO_WITNESS_ESTABLISHES_NOTHING"]
    return _STATES[claim.verdict]


def render_claim(claim, color=True) -> str:
    name, code = state_of(claim)
    line = f"[{name}] {claim.subject} :: {claim.property}"
    return f"{code}{line}{_RESET}" if color else line


def render_report(report, color=True) -> str:
    counts = report.counts()
    lines = []
    if not report.is_conclusive_anywhere():
        lines.append("*** THIS RUN ESTABLISHED NOTHING ***")
    by_state: dict[str, list] = {name: [] for name in _ORDER}
    for claim in report.claims:
        by_state[state_of(claim)[0]].append(claim)
    for name in _ORDER:
        group = by_state[name]
        if not group:
            continue
        lines.append(f"{name}: {len(group)}")
        for claim in group:
            lines.append("  " + render_claim(claim, color=color))
    return "\n".join(lines)


def _getch():
    try:
        import msvcrt
        return msvcrt.getwch()
    except ImportError:
        pass
    try:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        return sys.stdin.read(1)


def run(folder=None, stream=None) -> int:
    out = stream or sys.stdout
    from pqcheck.discover import discover
    candidates = discover(folder) if folder else []
    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
    out.write("pqcheck ui\n")
    if candidates:
        out.write("candidates:\n")
        for i, c in enumerate(candidates):
            out.write(f"  {i}. [{c.kind}] {c.path} ready={c.ready} missing={list(c.missing)} {c.detail}\n")
    else:
        out.write("no candidates found; pass a folder or run `pqcheck run <manifest>`\n")
    out.write("keys: [r] list relations  [q] quit\n")
    if not interactive:
        return 2 if not candidates else 0
    while True:
        ch = _getch()
        if ch == "" or ch in ("q", "Q", "\x03"):
            return 0
        if ch in ("r", "R"):
            from pqcheck.relations.base import REGISTRY
            for rid in sorted(REGISTRY):
                out.write(f"  {rid}\n")
            out.write("keys: [r] list relations  [q] quit\n")
