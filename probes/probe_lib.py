"""Shared helpers for the standing probes (not itself a probe)."""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pqcheck.relations.base import Finding, Relation  # noqa: E402
from pqcheck.target import Capability, Outcome, Status  # noqa: E402
from pqcheck.verdict import Subject  # noqa: E402

SUBJ = Subject(target="probe-target", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")


def fail(message):
    print(f"FAIL: {message}")
    raise SystemExit(1)


def check(condition, message):
    if not condition:
        fail(message)


def passed(message):
    print(f"PASS: {message}")
    return 0


class FakeTarget:
    """Crash-scenario target: ping() outcome is driven by mode."""

    def __init__(self, mode="clean"):
        self.caps = frozenset({Capability.KEM})
        self.mode = mode
        self._alive = True
        self._calls = 0

    def alive(self):
        return self._alive

    def ping(self, data=b"x"):
        self._calls += 1
        if self.mode == "crash2":
            return Outcome(Status.CRASHED, detail="SIGSEGV: segmentation fault")
        if self.mode == "crash1_alive":
            return Outcome(Status.CRASHED, detail="SIGSEGV: segmentation fault")
        if self.mode == "assert":
            self._alive = False
            return Outcome(Status.CRASHED, detail="assertion failed: precondition violated")
        if self.mode == "assert_then_hard":
            if self._calls == 1:
                self._alive = False
                return Outcome(Status.CRASHED, detail="assertion failed: precondition violated")
            return Outcome(Status.CRASHED, detail="AddressSanitizer: heap-buffer-overflow")
        if self.mode == "external":
            return Outcome(Status.CRASHED, detail="process died from SIGTERM; NOT attributable to the target")
        if self.mode == "deadline":
            return Outcome(Status.CRASHED, detail="killed by pqcheck's own deadline")
        if self.mode == "postmortem":
            return Outcome(Status.CRASHED, detail="[post-mortem] child already dead")
        if self.mode == "timeout2":
            return Outcome(Status.TIMEOUT, detail="per-call deadline exceeded")
        return Outcome(Status.OK, value=b"ok")


def make_relation(check_fn, **attrs):
    attrs.setdefault("id", f"probe-rel-{random.randrange(1 << 30)}")
    return type("ProbeRelation", (Relation,), {
        "property": "probe property holds",
        "ceiling": "does not establish more than the probe property",
        "requires": frozenset({Capability.KEM}),
        "check": check_fn,
        **attrs,
    })()


def run_relation(relation, target):
    return relation.run(target, SUBJ, random.Random("probe"))


def registry_run(relation_id, target, seed="probe"):
    from pqcheck.relations.base import REGISTRY
    return REGISTRY[relation_id].run(
        target, Subject(target=getattr(target, "name", "target"), commit=SUBJ.commit),
        random.Random(f"{seed}:{relation_id}"),
    )
