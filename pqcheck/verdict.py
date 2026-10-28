"""Core verdict, claim & report engine for pqcheck.

Structural honesty is enforced in dataclass constructors: a reassuring
or uncheckable claim that has not earned its evidence cannot be built.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "ClaimError",
    "Verdict",
    "CONCLUSIVE",
    "MOVING_REFS",
    "Subject",
    "Method",
    "ClassRef",
    "Coverage",
    "Claim",
    "Report",
    "looks_like_secret_material",
    "redact_target_output",
]


class ClaimError(ValueError):
    """Raised when a claim would state more than its evidence earns."""


class Verdict(str, Enum):
    DEFECT_FOUND = "DEFECT_FOUND"
    NO_DEFECT_FOUND = "NO_DEFECT_FOUND"
    NOT_REACHED = "NOT_REACHED"
    NOT_ANSWERABLE = "NOT_ANSWERABLE"


CONCLUSIVE = frozenset({Verdict.DEFECT_FOUND, Verdict.NO_DEFECT_FOUND})

MOVING_REFS = frozenset({
    "latest", "head", "main", "master", "trunk", "tip", "default",
    "dev", "devel", "develop", "current", "newest", "stable", "release",
    "unknown", "unspecified", "n/a", "na", "none", "null", "tbd", "?",
    "*", "-", "vendored", "liboqs-vendored", "bundled", "local", "wip",
    "test", "temp", "placeholder",
})

_HEX_RE = re.compile(r"[0-9a-fA-F]{48,}")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_REPRODUCE_MIN_CHARS = 12
_REPRODUCE_MIN_WORDS = 3


def _is_secret_run(match_text: str, kind: str) -> bool:
    if kind == "hex":
        return True
    return (
        any(c.islower() for c in match_text)
        and any(c.isupper() for c in match_text)
        and any(c.isdigit() for c in match_text)
    )


def looks_like_secret_material(text: str) -> str | None:
    """Return 'hex' or 'base64' if text holds a secret-shaped blob."""
    if not text:
        return None
    if _HEX_RE.search(text):
        return "hex"
    for m in _B64_RE.finditer(text):
        if _is_secret_run(m.group(0), "base64"):
            return "base64"
    return None


def redact_target_output(text: str) -> str:
    """Redact secret-shaped blobs quoted from a target's own output."""
    if not text:
        return text

    def _hex_sub(m: re.Match[str]) -> str:
        return (
            f"[{len(m.group(0))} hex chars redacted by pqcheck: "
            "quoted from the target]"
        )

    def _b64_sub(m: re.Match[str]) -> str:
        blob = m.group(0)
        if not _is_secret_run(blob, "base64"):
            return blob
        return (
            f"[{len(blob)} base64 chars redacted by pqcheck: "
            "quoted from the target]"
        )

    return _B64_RE.sub(_b64_sub, _HEX_RE.sub(_hex_sub, text))


@dataclass(frozen=True)
class Subject:
    target: str
    commit: str
    algorithm: str | None = None
    component: str | None = None

    def __post_init__(self) -> None:
        if not (self.target or "").strip():
            raise ClaimError("Subject.target must be non-empty")
        commit = (self.commit or "").strip()
        if not commit:
            raise ClaimError(
                "Subject.commit must be a resolved SHA or exact tag, "
                "never empty"
            )
        if commit.lower() in MOVING_REFS:
            raise ClaimError(
                f"Subject.commit {commit!r} is a moving reference; "
                "pin an exact commit SHA or release tag"
            )

    def __str__(self) -> str:
        parts = [self.target, self.commit[:12]]
        if self.algorithm:
            parts.append(self.algorithm)
        if self.component:
            parts.append(self.component)
        return " / ".join(parts)


@dataclass(frozen=True)
class Method:
    name: str
    oracle: str | None
    version: str | None = None

    def __post_init__(self) -> None:
        if not (self.name or "").strip():
            raise ClaimError("Method.name must be non-empty")


@dataclass(frozen=True)
class ClassRef:
    ident: str
    url: str
    what: str

    def __post_init__(self) -> None:
        if not (self.ident or "").strip():
            raise ClaimError("ClassRef.ident must be non-empty")
        if not (self.url or "").strip():
            raise ClaimError("ClassRef.url must be non-empty")
        if not (self.what or "").strip():
            raise ClaimError("ClassRef.what must be non-empty")
        if (
            self.ident.startswith("GHSA-")
            and "/advisories/" in self.url
            and "/security/advisories/" not in self.url
        ):
            raise ClaimError(
                "repository-level GHSA ids must use a "
                "/security/advisories/ URL; the global /advisories/ "
                "form 404s for them"
            )


@dataclass(frozen=True)
class Coverage:
    exercised: str
    units: int = 0
    observed: str = ""

    def is_empty(self) -> bool:
        return self.units <= 0 or not (self.exercised or "").strip()


@dataclass(frozen=True)
class Claim:
    subject: Subject
    property: str
    verdict: Verdict
    method: Method
    ceiling: str
    coverage: Coverage | None = None
    evidence: str = ""
    reproduce: str = ""
    notes: str = ""
    class_refs: tuple[ClassRef, ...] = ()
    premises: tuple[str, ...] = ()
    one_sided: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            raise ClaimError(
                "Claim.verdict must be a Verdict enum member, not a "
                f"plain {type(self.verdict).__name__}; JSON strings "
                "cannot bypass the honesty gates"
            )
        if not (self.property or "").strip():
            raise ClaimError("Claim.property must be non-empty")
        if not (self.ceiling or "").strip():
            raise ClaimError(
                "Claim.ceiling must be non-empty: every claim states "
                "what it does NOT establish"
            )
        if isinstance(self.premises, str) or not isinstance(
            self.premises, tuple
        ):
            raise ClaimError(
                "Claim.premises must be a tuple[str, ...], never a "
                "bare string"
            )
        if not all(isinstance(p, str) for p in self.premises):
            raise ClaimError("Claim.premises must be a tuple[str, ...]")
        if not isinstance(self.class_refs, tuple) or not all(
            isinstance(r, ClassRef) for r in self.class_refs
        ):
            raise ClaimError(
                "Claim.class_refs must be a tuple[ClassRef, ...]"
            )
        if self.verdict is Verdict.NO_DEFECT_FOUND:
            if self.coverage is None or self.coverage.is_empty():
                raise ClaimError(
                    "NO_DEFECT_FOUND requires Coverage with a named "
                    "exercised surface and units > 0"
                )
        if self.verdict is Verdict.DEFECT_FOUND:
            repro = (self.reproduce or "").strip()
            words = len(repro.split())
            has_path = "/" in repro or "\\" in repro
            if len(repro) < _REPRODUCE_MIN_CHARS or not (
                words >= _REPRODUCE_MIN_WORDS or has_path
            ):
                raise ClaimError(
                    "DEFECT_FOUND requires a non-stub reproduce "
                    f"instruction (>= {_REPRODUCE_MIN_CHARS} chars and "
                    f">= {_REPRODUCE_MIN_WORDS} words or a file path)"
                )
        if self.verdict is Verdict.NOT_ANSWERABLE:
            if not (self.notes or "").strip():
                raise ClaimError(
                    "NOT_ANSWERABLE requires notes explaining why "
                    "the question cannot be asked on this target"
                )
        if self.verdict is Verdict.NOT_REACHED:
            if not (self.evidence or "").strip() and not (
                self.notes or ""
            ).strip():
                raise ClaimError(
                    "NOT_REACHED requires evidence or notes "
                    "explaining why the target was not reached"
                )
        for field_name, value in (
            ("property", self.property),
            ("ceiling", self.ceiling),
            ("evidence", self.evidence),
            ("reproduce", self.reproduce),
            ("notes", self.notes),
        ):
            kind = looks_like_secret_material(value or "")
            if kind is not None:
                raise ClaimError(
                    f"Claim.{field_name} contains a contiguous "
                    f"{kind}-shaped blob; reports must be safe to "
                    "paste into public bug trackers"
                )
        for premise in self.premises:
            kind = looks_like_secret_material(premise or "")
            if kind is not None:
                raise ClaimError(
                    "Claim.premises contains a contiguous "
                    f"{kind}-shaped blob; reports must be safe to "
                    "paste into public bug trackers"
                )


@dataclass(frozen=True)
class Report:
    claims: tuple[Claim, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if isinstance(self.claims, Claim) or not isinstance(
            self.claims, (tuple, list)
        ):
            raise ClaimError("Report.claims must be a tuple[Claim, ...]")
        object.__setattr__(self, "claims", tuple(self.claims))
        if not all(isinstance(c, Claim) for c in self.claims):
            raise ClaimError("Report.claims must be a tuple[Claim, ...]")

    def defects(self) -> tuple[Claim, ...]:
        return tuple(
            c for c in self.claims if c.verdict is Verdict.DEFECT_FOUND
        )

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {v.value: 0 for v in Verdict}
        out["NO_WITNESS_ESTABLISHES_NOTHING"] = 0
        for c in self.claims:
            if (
                c.verdict is Verdict.NO_DEFECT_FOUND
                and c.one_sided is True
            ):
                out["NO_WITNESS_ESTABLISHES_NOTHING"] += 1
            else:
                out[c.verdict.value] += 1
        return out

    def is_conclusive_anywhere(self) -> bool:
        return any(
            c.verdict is Verdict.DEFECT_FOUND
            or (
                c.verdict is Verdict.NO_DEFECT_FOUND
                and not c.one_sided
            )
            for c in self.claims
        )

    def exit_code(self) -> int:
        if self.defects():
            return 1
        if not self.is_conclusive_anywhere():
            return 2
        return 0

    def score(self) -> float:
        raise NotImplementedError(
            "pqcheck reports no score, grade, or percentage: dividing "
            "by the number of implemented checks measures tool effort, "
            "not target risk"
        )

    def to_html(self) -> str:
        from pqcheck.html_report import report_to_html
        return report_to_html(self)

    def _format_claim(self, marker: str, claim: Claim) -> list[str]:
        lines = [
            f"  {marker} [{claim.verdict.value}] {claim.subject}",
            f"    property: {claim.property}",
        ]
        if claim.method.oracle:
            lines.append(f"    oracle: {claim.method.oracle}")
        if claim.premises:
            lines.append("    rests on:")
            for premise in claim.premises:
                lines.append(f"      - {premise}")
        if claim.coverage is not None:
            lines.append(
                f"    units: {claim.coverage.units} | observed by the "
                f"runner: {claim.coverage.observed}"
            )
            lines.append(
                f"    exercised: {claim.coverage.exercised}"
            )
        if claim.evidence:
            lines.append(f"    evidence: {claim.evidence}")
        if claim.reproduce:
            lines.append(f"    reproduce: {claim.reproduce}")
        if claim.notes:
            lines.append(f"    notes: {claim.notes}")
        lines.append(f"    does not establish: {claim.ceiling}")
        for ref in claim.class_refs:
            lines.append(f"    class: {ref.ident} {ref.url} {ref.what}")
        return lines

    def to_text(self) -> str:
        defects = list(self.defects())
        not_reached = [
            c for c in self.claims if c.verdict is Verdict.NOT_REACHED
        ]
        clean = [
            c
            for c in self.claims
            if c.verdict is Verdict.NO_DEFECT_FOUND and not c.one_sided
        ]
        no_witness = [
            c
            for c in self.claims
            if c.verdict is Verdict.NO_DEFECT_FOUND and c.one_sided
        ]
        out_of_scope = [
            c
            for c in self.claims
            if c.verdict is Verdict.NOT_ANSWERABLE
        ]
        lines: list[str] = []
        if not self.is_conclusive_anywhere():
            lines.append("*** THIS RUN ESTABLISHED NOTHING ***")
            lines.append("")
        lines.append(f"DEFECTS FOUND: {len(defects)}")
        for c in defects:
            lines.extend(self._format_claim("!", c))
        lines.append(
            f"NOT REACHED: {len(not_reached)}  <- these are NOT "
            "clean; nothing was established here"
        )
        for c in not_reached:
            lines.extend(self._format_claim("?", c))
        lines.append(f"NO DEFECT FOUND: {len(clean)}")
        for c in clean:
            lines.extend(self._format_claim(".", c))
        if no_witness:
            lines.append(
                "NO WITNESS FOUND \u2014 ESTABLISHES NOTHING: "
                f"{len(no_witness)}"
            )
            for c in no_witness:
                lines.extend(self._format_claim("~", c))
        if out_of_scope:
            lines.append(f"OUT OF SCOPE FOR THIS TOOL: {len(out_of_scope)}")
            for c in out_of_scope:
                lines.extend(self._format_claim("-", c))
        oracles = sorted(
            {c.method.oracle for c in self.claims if c.method.oracle}
        )
        if oracles:
            lines.append(
                "Independent oracle used: " + ", ".join(oracles)
            )
        else:
            lines.append(
                "No independent oracle was used; all checks were "
                "self-referential invariants."
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def emit(text: str, stream=None) -> None:
        if stream is None:
            stream = sys.stdout
        encoding = getattr(stream, "encoding", None) or "utf-8"
        try:
            text.encode(encoding)
        except (UnicodeEncodeError, LookupError):
            buffer = getattr(stream, "buffer", None)
            if buffer is None:
                stream.write(
                    text.encode("utf-8", errors="replace").decode(
                        encoding, errors="replace"
                    )
                )
                return
            try:
                stream.flush()
            except Exception:
                pass
            buffer.write(text.encode("utf-8"))
            buffer.flush()
            return
        stream.write(text)


def _self_check() -> None:
    subject = Subject(
        target="example-pqc", commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
        algorithm="ML-KEM-768",
    )
    method = Method(name="pqcheck-verdict-self-check", oracle=None)

    def refused(label, make):
        try:
            make()
        except ClaimError:
            return
        raise AssertionError(f"expected ClaimError: {label}")

    refused("moving ref", lambda: Subject(target="x", commit="main"))
    refused("empty commit", lambda: Subject(target="x", commit="  "))
    refused("plain-string verdict", lambda: Claim(
        subject=subject, property="p", verdict="NO_DEFECT_FOUND",  # type: ignore[arg-type]
        method=method, ceiling="c",
        coverage=Coverage("surface", units=1)))
    refused("clean without coverage", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.NO_DEFECT_FOUND,
        method=method, ceiling="c"))
    refused("clean with zero units", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.NO_DEFECT_FOUND,
        method=method, ceiling="c", coverage=Coverage("surface", units=0)))
    refused("defect without reproduce", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.DEFECT_FOUND,
        method=method, ceiling="c"))
    refused("defect with stub reproduce", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.DEFECT_FOUND,
        method=method, ceiling="c", reproduce="run it"))
    refused("not-answerable without notes", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.NOT_ANSWERABLE,
        method=method, ceiling="c"))
    refused("not-reached without evidence/notes", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.NOT_REACHED,
        method=method, ceiling="c"))
    refused("bare-string premises", lambda: Claim(
        subject=subject, property="p", verdict=Verdict.NOT_REACHED,
        method=method, ceiling="c", notes="n", premises="oops"))  # type: ignore[arg-type]
    refused("secret-shaped property", lambda: Claim(
        subject=subject, property="a" * 48, verdict=Verdict.NOT_REACHED,
        method=method, ceiling="c", notes="n"))
    refused("bad GHSA url", lambda: ClassRef(
        ident="GHSA-xxxx-yyyy-zzzz",
        url="https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        what="example class"))

    clean = Claim(
        subject=subject, property="round trip holds",
        verdict=Verdict.NO_DEFECT_FOUND, method=method,
        ceiling="does not establish side-channel resistance",
        coverage=Coverage("keygen/encaps/decaps", units=4, observed="calls: 4"))
    witness_miss = Claim(
        subject=subject, property="no FO witness found",
        verdict=Verdict.NO_DEFECT_FOUND, method=method,
        ceiling="a one-sided search establishes nothing when it misses",
        coverage=Coverage("ciphertext bit flips", units=10, observed="calls: 10"),
        one_sided=True)
    defect = Claim(
        subject=subject, property="wrong key is rejected",
        verdict=Verdict.DEFECT_FOUND, method=method,
        ceiling="does not establish fault resistance",
        reproduce="run the relation again with the pinned seed")

    assert Report((clean,)).exit_code() == 0
    assert Report((clean,)).is_conclusive_anywhere()
    assert Report((witness_miss,)).exit_code() == 2
    assert not Report((witness_miss,)).is_conclusive_anywhere()
    assert Report((witness_miss,)).counts()[
        "NO_WITNESS_ESTABLISHES_NOTHING"] == 1
    assert Report((defect,)).exit_code() == 1
    assert "*** THIS RUN ESTABLISHED NOTHING ***" in Report(
        (witness_miss,)).to_text()
    text = Report((defect, clean, witness_miss)).to_text()
    assert text.index("DEFECTS FOUND") < text.index("NOT REACHED")
    assert text.index("NOT REACHED") < text.index("NO DEFECT FOUND")
    assert "NO WITNESS FOUND" in text
    redacted = redact_target_output("crash " + "ab" * 32 + " end")
    assert "ab" * 32 not in redacted and "redacted by pqcheck" in redacted
    assert looks_like_secret_material("ab" * 32) == "hex"
    try:
        Report((clean,)).score()
    except NotImplementedError:
        pass
    else:
        raise AssertionError("Report.score() must raise NotImplementedError")
    print("verdict self-check: ok")


if __name__ == "__main__":
    _self_check()
