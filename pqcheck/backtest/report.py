"""Backtest coverage accounting, per grade, never summed.

The five grades in GRADES are incommensurable: adding DEMONSTRATED to
ARGUED would add a measurement to an untested prediction, the same
category error Report.score() refuses with an exception. This module
therefore reports each grade separately and never collapses grades
into a single coverage number.
"""
from __future__ import annotations

import sys

import pqcheck.relations  # noqa: F401
from pqcheck.backtest.corpus import CORPUS, GRADES

__all__ = ["GRADES", "grade_of", "status_of", "disclosure_state", "evaluate", "main"]


def grade_of(entry) -> str:
    if entry.grade not in GRADES:
        raise ValueError(f"unknown grade {entry.grade!r} for {entry.id}")
    return entry.grade


# Backwards-compatible alias: the grade is the only status there is.
status_of = grade_of


def disclosure_state(entry) -> str:
    """Derived, not asserted: computed from ours/grade, never stored
    as a free-standing claim on a third-party entry."""
    if entry.ours:
        return f"ours — disclosure: {entry.disclosure}"
    if entry.grade == "OUT_OF_SCOPE":
        return "third-party, out of scope — no disclosure asserted by pqcheck"
    return "third-party — no disclosure asserted by pqcheck"


def evaluate() -> dict:
    rows = [(entry, grade_of(entry)) for entry in CORPUS]
    # Per-grade counts only. No combined total across grades is computed.
    counts = {grade: 0 for grade in GRADES}
    for _entry, grade in rows:
        counts[grade] += 1
    by_class: dict[str, dict] = {}
    for entry, grade in rows:
        info = by_class.setdefault(
            entry.defect_class,
            {"in_scope": 0, **{g: 0 for g in GRADES}, "gap": False})
        info[grade] += 1
        if grade != "OUT_OF_SCOPE":
            info["in_scope"] += 1
    for info in by_class.values():
        info["gap"] = info["in_scope"] > 0 and info["DEMONSTRATED"] == 0
    disclosure: dict[str, list[str]] = {}
    for entry, _grade in rows:
        disclosure.setdefault(disclosure_state(entry), []).append(entry.id)
    return {
        "counts": counts,
        "rows": rows,
        "total": len(rows),
        "by_class": by_class,
        "work_queue": [entry for entry, grade in rows if grade == "MISSED"],
        "disclosure": disclosure,
    }


def to_markdown() -> str:
    result = evaluate()
    lines = [
        "# pqcheck backtest report",
        "",
        "Grades are incommensurable and are never summed into one number.",
        "",
        "## Per-grade counts",
        "",
        "| grade | count |",
        "| --- | --- |",
    ]
    for grade in GRADES:
        lines.append(f"| {grade} | {result['counts'][grade]} |")
    lines += ["", "## Entries", "", "| grade | id | defect class | title |", "| --- | --- | --- | --- |"]
    for entry, grade in result["rows"]:
        lines.append(f"| {grade} | {entry.id} | {entry.defect_class} | {entry.title} |")
    lines += ["", "## By defect class", "",
              "| defect class | in_scope | " + " | ".join(GRADES) + " | gap |",
              "| --- | --- | " + " | ".join("---" for _ in GRADES) + " | --- |"]
    for defect_class, info in result["by_class"].items():
        per = " | ".join(str(info[g]) for g in GRADES)
        lines.append(f"| {defect_class} | {info['in_scope']} | {per} | "
                     f"{'<-- gap' if info['gap'] else ''} |")
    lines += ["", "## Work queue — MISSED", ""]
    if result["work_queue"]:
        for entry in result["work_queue"]:
            lines.append(f"- `{entry.id}`: {entry.title}")
    else:
        lines.append("- (none)")
    lines += ["", "## Disclosure state — derived, not asserted", ""]
    for state, ids in result["disclosure"].items():
        lines.append(f"- {state}: {len(ids)} ({', '.join(ids)})")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="pqcheck-backtest-report")
    parser.add_argument("--md", action="store_true",
                        help="emit the report as Markdown")
    args = parser.parse_args(argv)
    if args.md:
        print(to_markdown())
        return 0
    result = evaluate()
    print(f"backtest corpus: {result['total']} entries "
          "(grades are incommensurable; no combined coverage sum is computed)")
    for entry, grade in result["rows"]:
        print(f"  {grade:13} {entry.id}: {entry.title}")
    print("counts (per grade, never summed):", result["counts"])
    print()
    print("BY DEFECT CLASS")
    for defect_class, info in result["by_class"].items():
        per_grade = " ".join(f"{g}={info[g]}" for g in GRADES)
        flag = " <-- gap" if info["gap"] else ""
        print(f"  {defect_class}: in_scope={info['in_scope']} {per_grade}{flag}")
    print()
    print("WORK QUEUE — MISSED")
    if result["work_queue"]:
        for entry in result["work_queue"]:
            print(f"  {entry.id}: {entry.title}")
    else:
        print("  (none)")
    print()
    print("DISCLOSURE STATE — derived, not asserted")
    for state, ids in result["disclosure"].items():
        print(f"  {state}: {len(ids)} ({', '.join(ids)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
