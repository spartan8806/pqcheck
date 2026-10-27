"""Runner for standing regression probes in probes/verify_*.py.

Protocol: exit 0 = verified, 77 = skipped (must print a reason),
78 = partial. A probe that prints a line starting with SKIP while
exiting 0 is a protocol violation and fails the run.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_SKIPPED = 77
EXIT_PARTIAL = 78

CONDITIONAL = frozenset({
    "verify_snova.py",
    "verify_snova_count.py",
    "verify_stateful_gate.py",
    "verify_codec_oracle.py",
    "verify_roundtrip_order.py",
    "verify_hint_oracle.py",
})


def _classify(code: int, output: str) -> str:
    """Classify a finished probe strictly by exit status.

    Returns "PASS", "SKIPPED", "PARTIAL", "FAIL", or "protocol" for the
    one dishonest combination: a SKIP line printed with exit 0.
    """
    if code == EXIT_OK:
        if any(line.lstrip().startswith("SKIP") for line in output.splitlines()):
            return "protocol"
        return "PASS"
    if code == EXIT_SKIPPED:
        return "SKIPPED"
    if code == EXIT_PARTIAL:
        return "PARTIAL"
    return "FAIL"


def run_probes(directory=None, timeout=300):
    root = Path(directory) if directory else Path(__file__).resolve().parents[1] / "probes"
    results = []
    scripts = sorted(root.glob("verify_*.py")) if root.is_dir() else []
    for script in scripts:
        try:
            proc = subprocess.run(
                [sys.executable, str(script)], capture_output=True, text=True,
                timeout=timeout, cwd=str(root.parent),
            )
            code, output = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired:
            results.append((script.name, "FAIL", "probe timed out"))
            continue
        kind = _classify(code, output)
        if kind == "protocol":
            results.append((script.name, "FAIL",
                            "skip-protocol: printed a SKIP line and exited 0"))
        elif kind == "PASS":
            results.append((script.name, "PASS", _first_line(output)))
        elif kind == "SKIPPED":
            reason = _first_line(output) or "no reason printed"
            results.append((script.name, "SKIPPED", reason))
        elif kind == "PARTIAL":
            results.append((script.name, "PARTIAL", _first_line(output)))
        else:
            results.append((script.name, "FAIL", f"exit {code}: {_first_line(output)}"))
    failed = any(status == "FAIL" for _n, status, _d in results)
    partial = any(status == "PARTIAL" for _n, status, _d in results)
    exit_code = 1 if failed else (EXIT_PARTIAL if partial and results else 0)
    if not results:
        exit_code = 1
    return results, exit_code


def _first_line(output: str) -> str:
    for line in output.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    directory = argv[0] if argv else None
    results, exit_code = run_probes(directory)
    for name, status, detail in results:
        print(f"{status:8} {name} {detail}")
    if not results:
        print("no probes found")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
