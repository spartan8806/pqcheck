import random
import unittest

from pqcheck.relations.base import Finding, Relation, _CrashWatch
from pqcheck.target import Capability, Outcome, Status
from pqcheck.verdict import Subject, Verdict

SUBJ = Subject(target="fake", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")


class FakeTarget:
    def __init__(self, mode="clean"):
        self.caps = frozenset({Capability.KEM})
        self.mode = mode
        self._alive = True

    def alive(self):
        return self._alive

    def ping(self, data=b"x"):
        if self.mode in ("crash2", "crash1_alive"):
            return Outcome(Status.CRASHED, detail="SIGSEGV: segmentation fault")
        if self.mode == "assert":
            self._alive = False
            return Outcome(Status.CRASHED, detail="assertion failed: precondition")
        if self.mode == "external":
            return Outcome(Status.CRASHED, detail="died from SIGTERM; NOT attributable to the target")
        if self.mode == "timeout2":
            return Outcome(Status.TIMEOUT, detail="per-call deadline exceeded")
        return Outcome(Status.OK, value=b"ok")


def make_relation(check, **attrs):
    attrs.setdefault("id", "test-rel")
    return type("R", (Relation,), {
        "property": "test property holds",
        "ceiling": "does not establish more",
        "requires": frozenset({Capability.KEM}),
        "check": check, **attrs})()


class RunnerTests(unittest.TestCase):
    def run_rel(self, rel, target):
        return rel.run(target, SUBJ, random.Random(1))

    def test_clean_with_calls(self):
        def check(s, t, r):
            t.ping(); t.ping()
            return Finding(True, "ok", 2, "ping surface")
        c = self.run_rel(make_relation(check), FakeTarget())
        self.assertIs(c.verdict, Verdict.NO_DEFECT_FOUND)
        self.assertIn("calls: 2", c.coverage.observed)

    def test_defect(self):
        def check(s, t, r):
            t.ping()
            return Finding(False, "bad", 1, "ping surface", reproduce="re-run the pinned relation again now")
        c = self.run_rel(make_relation(check), FakeTarget())
        self.assertIs(c.verdict, Verdict.DEFECT_FOUND)

    def test_failed_control(self):
        def check(s, t, r):
            return Finding(True, "ok", 1, "x")
        rel = make_relation(check, needs_control=True, control=lambda s, t: (False, "baseline broken"))
        c = self.run_rel(rel, FakeTarget())
        self.assertIs(c.verdict, Verdict.NOT_REACHED)

    def test_zero_call_spoof(self):
        rel = make_relation(lambda s, t, r: Finding(True, "claimed", 99, "ping surface"))
        c = self.run_rel(rel, FakeTarget())
        self.assertIs(c.verdict, Verdict.NOT_REACHED)

    def test_one_sided_witness_miss(self):
        def check(s, t, r):
            t.ping()
            return Finding(True, "no witness", 1, "ping surface")
        c = self.run_rel(make_relation(check, one_sided=True), FakeTarget())
        self.assertIs(c.verdict, Verdict.NO_DEFECT_FOUND)
        self.assertTrue(c.one_sided)

    def test_external_signal(self):
        def check(s, t, r):
            t.ping(); t.ping()
            return Finding(True, "ok", 2, "ping surface")
        c = self.run_rel(make_relation(check), FakeTarget("external"))
        self.assertIs(c.verdict, Verdict.NOT_REACHED)

    def test_assertion_abort(self):
        def check(s, t, r):
            t.ping()
            return Finding(True, "ok", 1, "ping surface")
        c = self.run_rel(make_relation(check), FakeTarget("assert"))
        self.assertIs(c.verdict, Verdict.NOT_REACHED)

    def test_corroborated_hard_crash(self):
        def check(s, t, r):
            t.ping(); t.ping()
            return Finding(True, "ok", 2, "ping surface")
        c = self.run_rel(make_relation(check), FakeTarget("crash2"))
        self.assertIs(c.verdict, Verdict.DEFECT_FOUND)

    def test_single_crash_alive_not_reached(self):
        def check(s, t, r):
            t.ping()
            return Finding(True, "ok", 1, "ping surface")
        c = self.run_rel(make_relation(check), FakeTarget("crash1_alive"))
        self.assertIs(c.verdict, Verdict.NOT_REACHED)

    def test_double_timeout_is_defect(self):
        def check(s, t, r):
            t.ping(); t.ping()
            return Finding(True, "ok", 2, "ping surface")
        c = self.run_rel(make_relation(check), FakeTarget("timeout2"))
        self.assertIs(c.verdict, Verdict.DEFECT_FOUND)
        self.assertIn("not memory unsafety", c.ceiling)

    def test_missing_capability(self):
        rel = make_relation(lambda s, t, r: Finding(True, "ok", 1, "x"), requires=frozenset({Capability.SIG}))
        c = self.run_rel(rel, FakeTarget())
        self.assertIs(c.verdict, Verdict.NOT_ANSWERABLE)

    def test_crashwatch_blocks_raw(self):
        w = _CrashWatch(FakeTarget())
        with self.assertRaises(AttributeError):
            w._t


if __name__ == "__main__":
    unittest.main()
