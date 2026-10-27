"""Real-code regression fixture: pinned @noble/post-quantum 0.6.1."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pqcheck.relations  # noqa: F401
from pqcheck.relations import base
from pqcheck.verdict import Subject, Verdict

_FALCON = {"core-input-length-boundaries": 46, "sig-message-binding": 48, "sig-degenerate-values": 3, "sig-unread-bits": 32768, "sig-wrong-key-rejection": 8, "core-declared-sizes-match-produced": 2, "core-sig-round-trip": 5}
_FALCON_PADDED = dict(_FALCON, **{"sig-verify-length-exact": 4, "core-declared-sizes-match-produced": 3})
_MLDSA = {"core-input-length-boundaries": 46, "sig-message-binding": 48, "sig-ctx-binding": 4, "sig-mode-domain-separation": 2, "sig-degenerate-values": 3, "sig-unread-bits": 32768, "sig-verify-length-exact": 4, "sig-wrong-key-rejection": 8, "core-declared-sizes-match-produced": 3, "core-sig-round-trip": 5}


def _kem_reach(ct_units, ek_units):
    return {"kem-fo-liveness": ct_units, "kem-reject-binds-full-ciphertext": ct_units // 3, "kem-reject-binds-z-accept-path-does-not": 4, "kem-reject-ct-bit-contribution": 21, "kem-reject-determinism": 8, "core-declared-sizes-match-produced": 4, "core-kem-round-trip": 4, "kem-ek-modulus-canonical": ek_units, "kem-degenerate-ciphertext": 4, "kem-decaps-length-exact": 5}


NOBLE_061 = {
    "package": "@noble/post-quantum",
    "version": "0.6.1",
    "algorithms": ["falcon512", "falcon512padded", "falcon1024", "falcon1024padded", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "ml-kem-512", "ml-kem-768", "ml-kem-1024"],
    "expected_claims": 10 * len(base.REGISTRY),
    "expected_defects": {("sig-verify-length-exact", "falcon512padded"), ("sig-verify-length-exact", "falcon1024padded")},
    "expected_reach": {
        "falcon512": dict(_FALCON),
        "falcon1024": dict(_FALCON),
        "falcon512padded": dict(_FALCON_PADDED),
        "falcon1024padded": dict(_FALCON_PADDED),
        "ml-dsa-44": dict(_MLDSA),
        "ml-dsa-65": dict(_MLDSA),
        "ml-dsa-87": dict(_MLDSA),
        "ml-kem-512": _kem_reach(2304, 8),
        "ml-kem-768": _kem_reach(3264, 13),
        "ml-kem-1024": _kem_reach(4704, 16),
    },
}


def run_noble(node_cwd) -> int:
    from pqcheck.adapters.noble import NobleTarget
    from pqcheck.verdict import CONCLUSIVE

    root = Path(node_cwd)
    pkg_path = root / "node_modules" / "@noble" / "post-quantum" / "package.json"
    try:
        version = json.loads(pkg_path.read_text(encoding="utf-8")).get("version")
    except Exception as exc:
        print(f"cannot read {pkg_path}: {exc}")
        return 1
    if version != NOBLE_061["version"]:
        print(f"expected @noble/post-quantum {NOBLE_061['version']}, found {version}")
        return 1
    found: set[tuple[str, str]] = set()
    reached: dict[str, set[str]] = {}
    thin: list[str] = []
    unreached: list[str] = []
    total = 0
    for algorithm in NOBLE_061["algorithms"]:
        subj = Subject(target=NOBLE_061["package"], commit=NOBLE_061["version"], algorithm=algorithm)
        try:
            target = NobleTarget(str(root), algorithm)
        except Exception as exc:
            claims = base.unopened_claims(subj, exc)
            total += len(claims)
            unreached.extend(f"{algorithm}:{c.method.name}" for c in claims)
            continue
        reached.setdefault(algorithm, set())
        try:
            for rid, relation in sorted(base.REGISTRY.items()):
                claim = relation.run(target, subj, random.Random(f"noble061:{algorithm}:{rid}"))
                total += 1
                if claim.verdict is Verdict.DEFECT_FOUND:
                    found.add((rid, algorithm))
                if claim.verdict in CONCLUSIVE or (claim.verdict is Verdict.NO_DEFECT_FOUND and claim.one_sided):
                    reached[algorithm].add(rid)
                    floor = NOBLE_061["expected_reach"].get(algorithm, {}).get(rid)
                    if floor is not None and (claim.coverage is None or claim.coverage.units < floor):
                        thin.append(f"{algorithm}:{rid} units={claim.coverage.units if claim.coverage else 0} < floor {floor}")
                if claim.verdict is Verdict.NOT_REACHED:
                    unreached.append(f"{algorithm}:{rid}")
        finally:
            target.close()
    expected_defects = NOBLE_061["expected_defects"]
    missing = expected_defects - found
    extra = found - expected_defects
    lost: set[tuple[str, str]] = set()
    gained: set[tuple[str, str]] = set()
    for algorithm, expected in NOBLE_061["expected_reach"].items():
        exp_reach = {(rid, algorithm) for rid in expected}
        got_reach = {(rid, algorithm) for rid in reached.get(algorithm, set())}
        # reach is tracked per relation below in (relation, algorithm) form
        lost |= {(rid, alg) for (rid, alg) in exp_reach if rid not in reached.get(alg, set())}
        gained |= {(rid, alg) for (rid, alg) in {(r, algorithm) for r in reached.get(algorithm, set())} if rid not in expected}
    failures = []
    if missing: failures.append(f"missing expected defects: {sorted(missing)}")
    if extra: failures.append(f"extra defects: {sorted(extra)}")
    if lost: failures.append(f"lost expected reach: {sorted(lost)[:10]}")
    if gained: print(f"note: relations reaching beyond the minimum floors (not a failure): {sorted(gained)[:10]}")
    if thin: failures.append(f"thin coverage: {thin[:10]}")
    if unreached: failures.append(f"unreached relations: {unreached[:10]}")
    if total != NOBLE_061["expected_claims"]:
        failures.append(f"total claims {total} != expected {NOBLE_061['expected_claims']}")
    if failures:
        print("noble 0.6.1 fixture FAILED:")
        for failure in failures:
            print(" -", failure)
        return 1
    print(f"noble 0.6.1 fixture: ok ({total} claims, defects exactly {sorted(expected_defects)})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m pqcheck.testing.fixtures <node_cwd>")
        raise SystemExit(2)
    raise SystemExit(run_noble(sys.argv[1]))
