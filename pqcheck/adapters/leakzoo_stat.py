#!/usr/bin/env python3
"""Classify one timing class line from stdin with the dudect scan.

Input:  CLASS <name> <cycles_A_csv> <cycles_B_csv>
Output: FIRES (|t| > 4.5) or silent, with |t|, crop, and medians.
A FIRES result is a lead for re-measurement, not a finding.
"""
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pqcheck.adapters.timing_probe import scan_t


def main() -> int:
    for line in sys.stdin:
        parts = line.split()
        if len(parts) < 4 or parts[0] != "CLASS":
            continue
        name = parts[1]
        try:
            a = [float(x) for x in parts[2].split(",") if x]
            b = [float(x) for x in parts[3].split(",") if x]
        except ValueError:
            print(f"silent {name} (unparseable cycles)")
            continue
        t, at = scan_t(a, b)
        verdict = "FIRES" if t > 4.5 else "silent"
        print(
            f"{verdict} {name} |t|={t:.2f} @crop {at} "
            f"medianA={statistics.median(a) if a else 0:.0f} "
            f"medianB={statistics.median(b) if b else 0:.0f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
