"""Welch's t-test timing analysis (dudect-style), pure Python.

Local diagnostic only: this measures a maintainer's own build on their
own machine and reports a lead or a bound, never a certificate.
"""
from __future__ import annotations

import math
import os
import statistics

CROPS = (0.10, 0.20, 0.30, 0.40, 0.50, 0.70, 0.90, 1.00)


def welch_t(a, b) -> float:
    a, b = list(a), list(b)
    if len(a) < 2 or len(b) < 2:
        return 0.0
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    denom = math.sqrt(va / len(a) + vb / len(b))
    if denom == 0:
        return 0.0
    return (ma - mb) / denom


def crop(xs, lo=0.0, hi=0.90):
    ordered = sorted(xs)
    if not ordered:
        return []
    lo_i = int(lo * len(ordered))
    hi_i = max(lo_i + 1, int(hi * len(ordered)))
    return ordered[lo_i:hi_i]


def scan_t(a, b):
    """Return (max_abs_t, crop_at_max) across CROPS."""
    best_t, best_crop = 0.0, CROPS[-1]
    for hi in CROPS:
        t = abs(welch_t(crop(a, 0.0, hi), crop(b, 0.0, hi)))
        if t > best_t:
            best_t, best_crop = t, hi
    return best_t, best_crop


CLASSES = (
    ("honest vs random", "honest", "random"),
    ("honest vs all-zero", "honest", "zero"),
    ("random vs random", "random", "random2"),
)


def classify(worst: float, floor: float) -> str:
    if worst > floor:
        return (
            f"POSITIVE: |t| = {worst:.2f} exceeds the floor {floor:.2f}. "
            "A LEAD, not a finding -- re-measure on isolated, "
            "frequency-pinned hardware before believing it."
        )
    if worst > 4.5:
        return (
            f"INCONCLUSIVE: |t| = {worst:.2f} clears 4.5 but NOT the "
            f"negative control (floor {floor:.2f}); the instrument cannot "
            "separate signal from its own noise here."
        )
    return (
        f"No separation detected (|t| = {worst:.2f} <= 4.5). This is a "
        "BOUND ON THIS INSTRUMENT, not a certificate of constant-time behaviour."
    )


def analyse(class_samples: dict[str, tuple[list, list]]) -> dict:
    """class_samples maps class label -> (cycles_A, cycles_B)."""
    results = {}
    for label, (a, b) in class_samples.items():
        results[label] = scan_t(a, b)
    control = results.get("random vs random", (0.0, 1.0))[0]
    floor = max(4.5, control)
    worst = max((t for label, (t, _c) in results.items() if label != "random vs random"), default=0.0)
    return {"results": results, "control": control, "floor": floor, "worst": worst, "verdict": classify(worst, floor)}


def make_ct(kind: str, honest: bytes, ct_len: int) -> bytes:
    if kind == "honest":
        return honest
    if kind == "zero":
        return bytes(ct_len)
    return os.urandom(ct_len)


def run_timing(binary, algorithm, iters=64, timeout=30.0) -> dict:
    """Drive a timing_harness binary and analyse the three ct classes."""
    import subprocess
    from pqcheck.adapters.cbridge import parse_hex_reply

    proc = subprocess.Popen(
        [str(binary), "kem", algorithm], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )

    def call(line):
        proc.stdin.write(line + "\n")
        proc.stdin.flush()
        reply = proc.stdout.readline().strip()
        if not reply.startswith("OK"):
            raise RuntimeError(f"timing harness declined: {reply}")
        return reply[2:].strip()

    try:
        call("info")
        kg = call("keygen -")
        pk_hex, sk_hex = kg.split()
        pk = parse_hex_reply(pk_hex)
        enc = call("encaps " + pk_hex)
        _ss_hex, ct_hex = enc.split()
        honest = parse_hex_reply(ct_hex)
        ct_len = len(honest)
        samples: dict[str, tuple[list, list]] = {}
        for label, kind_a, kind_b in CLASSES:
            ct_a = make_ct(kind_a, honest, ct_len)
            ct_b = make_ct(kind_b, honest, ct_len)
            reply = call(f"measure {sk_hex} {ct_a.hex()} {ct_b.hex()} {iters}")
            a_text, b_text = reply.split()
            samples[label] = (
                [int(x) for x in a_text.split(",") if x],
                [int(x) for x in b_text.split(",") if x],
            )
        return analyse(samples)
    finally:
        try:
            proc.stdin.close()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def main(argv=None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print("usage: python -m pqcheck.adapters.timing_probe <timing_harness> <algorithm> [iters]")
        return 3
    iters = int(args[2]) if len(args) > 2 else 64
    result = run_timing(args[0], args[1], iters=iters)
    for label, (t, at) in result["results"].items():
        print(f"{label}: |t| = {t:.2f} @crop {at}")
    print(f"negative control: |t| = {result['control']:.2f}; floor = {result['floor']:.2f}")
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
