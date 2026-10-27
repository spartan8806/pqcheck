"""Relation runner: applicability, controls, crash adjudication, honesty gates."""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass

from pqcheck.target import (
    DEADLINE_KILLED,
    NOT_ATTRIBUTABLE,
    POST_MORTEM,
    Capability,
    Outcome,
    Status,
)
from pqcheck.verdict import Claim, ClassRef, Coverage, Method, Subject, Verdict, redact_target_output

__all__ = ["NotApplicable", "Finding", "Relation", "REGISTRY", "register", "_CrashWatch"]

_NEUTRAL = (
    "EITHER pqcheck could not use this target's reply, OR the target "
    "produced a reply it should not have. This runner cannot tell "
    "which; do not read it as exonerating the target"
)
_ASSERT_RE = re.compile(r"\bassert(ion)?\b(?!\w)|\bpanicked at\b|\bdebug_assert\b", re.I)


class NotApplicable(Exception):
    """The relation does not apply to this target's API or geometry."""


@dataclass(frozen=True)
class Finding:
    held: bool | None
    evidence: str
    units: int
    exercised: str
    reproduce: str = ""
    notes: str = ""


class _CrashWatch:
    """Proxy counting calls and recording crashes; hides the raw target."""

    _BLOCKED = frozenset({"_t", "__target", "_CrashWatch__target"})

    def __init__(self, target):
        object.__setattr__(self, "_CrashWatch__target", target)
        object.__setattr__(self, "calls", 0)
        object.__setattr__(self, "ops", {})
        object.__setattr__(self, "crashes", [])

    def __getattr__(self, name):
        if name in _CrashWatch._BLOCKED or name.startswith("_CrashWatch"):
            raise AttributeError(name)
        target = object.__getattribute__(self, "_CrashWatch__target")
        attr = getattr(target, name)
        if not callable(attr):
            return attr

        @functools.wraps(attr)
        def wrapper(*args, **kwargs):
            object.__setattr__(self, "calls", object.__getattribute__(self, "calls") + 1)
            ops = object.__getattribute__(self, "ops")
            ops[name] = ops.get(name, 0) + 1
            out = attr(*args, **kwargs)
            if isinstance(out, Outcome) and out.is_finding:
                object.__getattribute__(self, "crashes").append((name, out.status, out.detail or ""))
            return out

        return wrapper

    def __setattr__(self, name, value):
        if name in ("calls", "ops", "crashes") or name.startswith("_CrashWatch"):
            object.__setattr__(self, name, value)
            return
        target = object.__getattribute__(self, "_CrashWatch__target")
        setattr(target, name, value)


def _observed(watched: _CrashWatch) -> str:
    parts = ", ".join(f"{k}={watched.ops[k]}" for k in sorted(watched.ops))
    return f"calls: {watched.calls}" + (f" ({parts})" if parts else "")


REGISTRY: dict[str, "Relation"] = {}


def unopened_claims(subject: Subject, exc: BaseException, relation_ids=None):
    """NOT_REACHED claims for every relation when a target cannot be opened."""
    claims = []
    for rid, relation in sorted(REGISTRY.items()):
        if relation_ids is not None and rid not in relation_ids:
            continue
        claims.append(Claim(
            subject=subject,
            property=relation.property or rid,
            verdict=Verdict.NOT_REACHED,
            method=Method(name=rid, oracle=None),
            ceiling=relation.ceiling,
            evidence=redact_target_output(f"target could not be opened: {type(exc).__name__}: {exc}")[:400],
        ))
    return claims


def register(cls):
    if not isinstance(getattr(cls, "id", None), str) or not cls.id:
        raise TypeError(f"{cls.__name__} must define a non-empty string id")
    if getattr(cls, "constructs_probes", False) and "probe_control" not in cls.__dict__:
        raise TypeError(f"{cls.__name__}: constructs_probes requires an overridden probe_control")
    instance = cls()
    if instance.id in REGISTRY:
        raise TypeError(f"duplicate relation id {instance.id!r}")
    REGISTRY[instance.id] = instance
    return cls


class Relation:
    id: str = ""
    property: str = ""
    ceiling: str = "does not establish anything beyond the stated property"
    requires: frozenset[Capability] = frozenset()
    needs_control: bool = False
    constructs_probes: bool = False
    probes_lie_about_length: bool = False
    one_sided: bool = False
    false_positive_modes: tuple[str, ...] = ()
    premise_attrs: tuple[str, ...] = ()
    class_refs: tuple[ClassRef, ...] = ()

    # -- hooks for subclasses -------------------------------------------------
    def control(self, target) -> tuple[bool, str]:
        return True, "no positive control defined"

    def probe_control(self, target) -> bool:
        return False

    def check(self, target, rng) -> Finding:
        raise NotImplementedError

    # -- runner ---------------------------------------------------------------
    def _claim(self, subject, verdict, *, coverage=None, evidence="", reproduce="", notes="", premises=(), ceiling=None, one_sided=None):
        return Claim(
            subject=subject,
            property=self.property or self.id,
            verdict=verdict,
            method=Method(name=self.id, oracle=getattr(self, "_oracle", None)),
            ceiling=ceiling or self.ceiling,
            coverage=coverage,
            evidence=evidence,
            reproduce=reproduce,
            notes=notes,
            class_refs=tuple(self.class_refs),
            premises=tuple(premises),
            one_sided=self.one_sided if one_sided is None else one_sided,
        )

    def _fallback_repro(self) -> str:
        return f"re-run pqcheck relation {self.id} against the pinned target with the same seed"

    def run(self, target, subject: Subject, rng) -> Claim:
        self._oracle = getattr(target, "oracle", None)
        premises: list[str] = []
        for attr in self.premise_attrs:
            if hasattr(target, attr):
                value = repr(getattr(target, attr))
                premises.append(f"{attr}={value[:120]}")
        premises_t = tuple(premises)

        caps = set(getattr(target, "caps", frozenset()) or frozenset())
        missing = set(self.requires) - caps
        if missing:
            names = ", ".join(sorted(getattr(m, "value", str(m)) for m in missing))
            return self._claim(subject, Verdict.NOT_ANSWERABLE, notes=f"missing capabilities: {names}", premises=premises_t)

        if self.needs_control:
            try:
                passed, desc = self.control(target)
            except NotApplicable as exc:
                return self._claim(subject, Verdict.NOT_ANSWERABLE, notes=str(exc) or "positive control not applicable", premises=premises_t)
            except Exception:
                return self._claim(subject, Verdict.NOT_REACHED, notes=_NEUTRAL, premises=premises_t)
            if not passed:
                return self._claim(subject, Verdict.NOT_REACHED, evidence=f"positive control failed: {desc}", premises=premises_t)

        if self.constructs_probes:
            try:
                ok = self.probe_control(target)
            except Exception as exc:
                return self._claim(subject, Verdict.NOT_ANSWERABLE, notes=f"constructed-probe control failed ({type(exc).__name__}); the assumed layout does not describe this target", premises=premises_t)
            if not ok:
                return self._claim(subject, Verdict.NOT_ANSWERABLE, notes="constructed-probe control failed; the assumed layout does not describe this target", premises=premises_t)

        watched = _CrashWatch(target)
        try:
            f = self.check(watched, rng)
        except NotApplicable as exc:
            return self._claim(subject, Verdict.NOT_ANSWERABLE, notes=str(exc) or "not applicable to this target", premises=premises_t)
        except Exception:
            return self._claim(subject, Verdict.NOT_REACHED, notes=_NEUTRAL, premises=premises_t)
        if not isinstance(f, Finding):
            return self._claim(subject, Verdict.NOT_REACHED, notes=_NEUTRAL, premises=premises_t)

        withheld = ""
        if f.held is False and (f.evidence or f.notes):
            withheld = f"relation finding withheld by crash/timeout adjudication: {f.evidence} {f.notes}".strip()

        crashes = list(watched.crashes)
        fresh = [c for c in crashes if POST_MORTEM not in (c[2] or "")]
        external = [c for c in crashes if NOT_ATTRIBUTABLE in (c[2] or "")]
        deadline = [c for c in crashes if DEADLINE_KILLED in (c[2] or "")]
        if crashes and not fresh:
            why = "harness was killed by pqcheck's own deadline during an earlier relation" if deadline else (
                "process was killed by an external signal" if external else "all recorded faults are post-mortem repeats of an earlier death")
            return self._claim(subject, Verdict.NOT_REACHED, evidence=why, notes=withheld, premises=premises_t)
        effective = [c for c in fresh if NOT_ATTRIBUTABLE not in (c[2] or "") and DEADLINE_KILLED not in (c[2] or "")]
        if fresh and not effective:
            why = "harness was killed by pqcheck's own deadline" if deadline else "process was killed by an external signal"
            return self._claim(subject, Verdict.NOT_REACHED, evidence=why, notes=withheld, premises=premises_t)

        timeouts = [c for c in effective if c[1] is Status.TIMEOUT]
        faults = [c for c in effective if c[1] is Status.CRASHED]
        if timeouts and not faults:
            detail = "; ".join(f"{op}: {det}" for op, _s, det in timeouts[:3])
            if len(timeouts) == 1:
                return self._claim(subject, Verdict.NOT_REACHED, evidence=f"single uncorroborated timeout: {detail}", notes=withheld, premises=premises_t)
            return self._claim(
                subject, Verdict.DEFECT_FOUND,
                coverage=Coverage(f.exercised or self.property, max(f.units, len(timeouts)), _observed(watched)),
                evidence=f"{len(timeouts)} reproducible timeouts: {detail}",
                reproduce=f.reproduce or self._fallback_repro(),
                notes=(withheld + " " if withheld else "") + "A reproducible hang is an availability defect, not memory unsafety.",
                premises=premises_t,
                ceiling=self.ceiling + " A reproducible hang is an availability defect, not memory unsafety.",
            )
        if faults and self.probes_lie_about_length:
            return self._claim(subject, Verdict.NOT_REACHED, evidence="crash under a lying-length probe is ambiguous between a target overflow and an adapter falsely declaring declared-length support", notes=withheld, premises=premises_t)
        if faults:
            alive_fn = getattr(target, "alive", None)
            alive = alive_fn() if callable(alive_fn) else None
            confirmed = len(faults) > 1 or (alive is False and bool(faults))
            if not confirmed:
                return self._claim(subject, Verdict.NOT_REACHED, evidence="single uncorroborated fault while the process remains alive", notes=withheld, premises=premises_t)
            soft = [c for c in faults if _ASSERT_RE.search(c[2] or "")]
            hard = [c for c in faults if c not in soft]
            if soft and not hard:
                return self._claim(subject, Verdict.NOT_REACHED, evidence="assertion abort in a debug/precondition build, not memory unsafety: " + "; ".join(c[2] for c in soft[:3]), notes=withheld, premises=premises_t)
            hard_confirmed = len(hard) > 1 or (alive is False and bool(hard))
            if not hard_confirmed:
                return self._claim(subject, Verdict.NOT_REACHED, evidence="single uncorroborated hard fault while the process remains alive", notes=withheld, premises=premises_t)
            detail = "; ".join(f"{op}: {det}" for op, _s, det in hard[:3])
            return self._claim(
                subject, Verdict.DEFECT_FOUND,
                coverage=Coverage(f.exercised or self.property, max(f.units, len(hard)), _observed(watched)),
                evidence=f"{len(hard)} corroborated hard fault(s): {detail}",
                reproduce=f.reproduce or self._fallback_repro(),
                notes=withheld, premises=premises_t,
            )

        if f.held is not None and f.units > 0 and watched.calls == 0:
            return self._claim(subject, Verdict.NOT_REACHED, evidence="relation claimed coverage while making zero calls to the target", notes=f.notes, premises=premises_t)
        if f.held is None or f.units <= 0:
            return self._claim(subject, Verdict.NOT_REACHED, evidence=f.evidence or "no comparable observation obtained", notes=f.notes or "no comparable observation obtained", premises=premises_t)
        coverage = Coverage(f.exercised, f.units, _observed(watched))
        if f.held is True:
            return self._claim(subject, Verdict.NO_DEFECT_FOUND, coverage=coverage, evidence=f.evidence, notes=f.notes, premises=premises_t)
        return self._claim(subject, Verdict.DEFECT_FOUND, coverage=coverage, evidence=f.evidence, reproduce=f.reproduce or self._fallback_repro(), notes=f.notes, premises=premises_t)
