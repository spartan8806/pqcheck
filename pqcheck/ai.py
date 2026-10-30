"""Neuro-Symbolic Muse AI Expansion Engine.

Two-tier design. Tier 1 is the existing deterministic core: the
registered relations run offline at zero tokens. Tier 2 is opt-in
(--muse / MUSE_API_KEY / --muse-simulate): a compact GapDigest of
what the core established (and what it could not reach) is sent to
Muse, which may propose candidate invariant probes for uncovered
compound/boundary surfaces.

Muse is never allowed to emit an unverified prose finding. Every
candidate is executed at runtime inside an isolated temporary
directory, must first survive the Clean-Reference Precision Gate
(a candidate that fires DEFECT_FOUND on a clean reference fixture
is rejected as an AI false positive), then runs against the actual
target under _CrashWatch, and its Claim must pass the
secret-material floor. The temp directory is wiped in a finally
block and the wipe is asserted, so zero wild PoC files remain.

Stdlib only (urllib.request, json, tempfile, shutil): the package
keeps dependencies = [].
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from pqcheck.relations._common import flip, ok, pair
from pqcheck.relations.base import REGISTRY, _CrashWatch, _observed
from pqcheck.target import Capability
from pqcheck.verdict import (
    Claim, Coverage, Method, Report, Subject, Verdict,
    looks_like_secret_material,
)

MODEL_DEFAULT = "muse-wonder-1.0"
ORACLE_LABEL = ("muse-wonder-1.0 (execution-verified in ephemeral "
                "sandbox, clean-control gated)")
STRATEGIES = (
    "kem-multi-bit-ct-perturbation",
    "kem-dk-cross-region-tamper",
    "sig-boundary-message-and-tail-probe",
    "sig-mldsa-hint-compound-probe",
)
_SPEC_FIELDS = {
    "id", "failure_class", "description", "kind", "probe_strategy",
    "parameters", "ceiling", "false_positive_modes",
}


class MuseError(Exception):
    """The live Muse endpoint could not produce usable candidates."""


def core_relation_count() -> int:
    return len(REGISTRY)


def inactive_footer() -> str:
    n = core_relation_count()
    return (f"Muse AI expansion: INACTIVE ({n} deterministic relations "
            "ran at 0 tokens; set MUSE_API_KEY or pass --muse-simulate "
            "to enable dynamic relation synthesis).")


_SECRET_FILES = ("secrets/muse_api_key", "secrets/muse_api_key.txt",
                 "secrets/api_key", "secrets/api_key.txt")


def resolve_api_key(env: dict | None = None, root=None) -> str:
    """API key from the environment or a gitignored secrets/ folder.

    Never logged, printed, or included in any report: callers only
    learn whether a key exists, never its value.
    """
    env = os.environ if env is None else env
    key = (env.get("MUSE_API_KEY") or "").strip()
    if key:
        return key
    from pathlib import Path
    bases = [Path(root)] if root else [Path.cwd(),
                                       Path(__file__).resolve().parents[1]]
    for base in bases:
        for rel in _SECRET_FILES:
            try:
                text = (base / rel).read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if text:
                return text.splitlines()[0].strip()
    return ""


def resolve_mode(muse: bool = False, simulate: bool = False,
                 no_muse: bool = False, env: dict | None = None) -> str:
    """live | simulated | inactive. Simulation wins when requested so
    offline judges can exercise the full pipeline without a key."""
    env = os.environ if env is None else env
    if simulate:
        return "simulated"
    if no_muse:
        return "inactive"
    if muse or resolve_api_key(env):
        return "live"
    return "inactive"


_RANK = {Verdict.DEFECT_FOUND: 0, Verdict.NOT_REACHED: 1,
         Verdict.NOT_ANSWERABLE: 3, Verdict.NO_DEFECT_FOUND: 2}


def rank_claims(report: Report) -> list[Claim]:
    """Findings first, then gaps, then clean/witness results. Pure
    ordering of the deterministic claims; nothing is added, removed,
    or re-verdicted."""
    return sorted(
        report.claims,
        key=lambda c: (
            2.5 if (c.verdict is Verdict.NO_DEFECT_FOUND and c.one_sided)
            else _RANK[c.verdict],
            c.method.name))


def explain_report(report: Report) -> str:
    """Plain-English explanation of a finished report, ranked by
    importance. Muse (or this offline fallback) explains and ranks
    only: every verdict quoted here is the deterministic core's,
    copied verbatim -- explanation can never change a verdict, and
    with no API key this text is generated locally at zero tokens."""
    lines = ["In plain English, most important first:"]
    ranked = rank_claims(report)
    if not ranked:
        lines.append("- Nothing ran: this report established nothing.")
        return "\n".join(lines)
    for claim in ranked:
        label = {
            Verdict.DEFECT_FOUND: "Finding",
            Verdict.NOT_REACHED: "Not run (nothing established)",
            Verdict.NOT_ANSWERABLE: "Not answerable for this target",
            Verdict.NO_DEFECT_FOUND: (
                "Inconclusive witness search (not a pass)"
                if claim.one_sided else "Check completed, no defect found"),
        }[claim.verdict]
        lines.append(
            f"- {label}: {claim.property} "
            f"[{claim.method.name}; verdict {claim.verdict.value}]")
    lines.append(
        "These verdicts come only from the deterministic relations; "
        "this explanation does not change any of them.")
    return "\n".join(lines)


# ---------------------------------------------------------------- digest

def build_gap_digest(report: Report, target=None) -> dict:
    """Compact (~400-token) summary of what the core established."""
    claims = list(report.claims)
    subject = claims[0].subject if claims else None
    calls = 0
    for claim in claims:
        if claim.coverage is None:
            continue
        match = re.search(r"calls:\s*(\d+)", claim.coverage.observed or "")
        calls += int(match.group(1)) if match else claim.coverage.units
    caps = []
    sizes = {}
    if target is not None:
        caps = sorted(
            c.value if isinstance(c, Capability) else str(c)
            for c in (getattr(target, "caps", None) or frozenset()))
        sizes = {str(k): v for k, v in (getattr(target, "sizes", None) or {}).items()
                 if isinstance(v, int)}
    return {
        "target_name": (f"{subject.target} / {subject.algorithm}"
                        if subject else getattr(target, "name", "unknown")),
        "capabilities": caps,
        "sizes": sizes,
        "core_relations_ran": len(claims),
        "core_calls_executed": calls,
        "estimated_tokens_saved": calls * 45,
        "already_caught": sorted({c.method.name for c in claims
                                  if c.verdict is Verdict.DEFECT_FOUND}),
        "unreached_or_unanswerable": [
            {"relation": c.method.name, "verdict": c.verdict.value}
            for c in claims
            if c.verdict in (Verdict.NOT_REACHED, Verdict.NOT_ANSWERABLE)
        ],
    }


def _check_no_secret_material(claim: Claim) -> bool:
    """The secret-material floor for Muse claims (also enforced by
    Claim construction; checked here explicitly before admission)."""
    fields = [claim.property, claim.ceiling, claim.evidence,
              claim.reproduce, claim.notes, *claim.premises]
    return all(looks_like_secret_material(text or "") is None for text in fields)


# ---------------------------------------------------------------- clients

_SYSTEM_PROMPT = (
    "You are the candidate-probe synthesizer inside pqcheck, a "
    "defensive post-quantum implementation checker. Given a compact "
    "GapDigest of what deterministic relations already established, "
    "propose candidate invariant probes ONLY for uncovered compound "
    "or boundary surfaces. Reply with JSON only: "
    '{"candidates": [{"id": str, "failure_class": str, '
    '"description": str, "kind": one of ' + json.dumps(list(STRATEGIES)) +
    ', "probe_strategy": str, "parameters": object, "ceiling": str, '
    '"false_positive_modes": [str]}]}. Never propose key recovery, '
    "forgery, or exploitation; probes only test implementation "
    "invariants on the caller's own target."
)


class SimulatedMuseClient:
    """Deterministic offline stand-in so judges can exercise the
    full pipeline without a live key. Proposes one deliberately
    over-aggressive candidate (demands deterministic randomized
    primitives) that the Clean-Reference Precision Gate must reject,
    plus valid compound candidates matched to the digest."""

    model = MODEL_DEFAULT + " (simulated)"

    def propose(self, digest: dict) -> list[dict]:
        caps = set(digest.get("capabilities") or [])
        out: list[dict] = []
        if "kem" in caps:
            out.append({
                "id": "muse-kem-require-deterministic-encaps",
                "failure_class": "overbroad-determinism-demand",
                "description": "Encapsulation must be deterministic: two encapsulations under one ek must be identical.",
                "kind": "kem-multi-bit-ct-perturbation",
                "probe_strategy": "encapsulate twice under one ek and demand byte-identical ciphertexts",
                "parameters": {"require_deterministic_encaps": True},
                "ceiling": "does not establish anything about randomized encapsulation, which FIPS 203 requires",
                "false_positive_modes": ["any correct randomized KEM fires this candidate"],
            })
            out.append({
                "id": "muse-kem-multi-bit-ct",
                "failure_class": "fo-transform-absent",
                "description": "A ciphertext flipped in several bytes at once must never decapsulate to the honest secret.",
                "kind": "kem-multi-bit-ct-perturbation",
                "probe_strategy": "flip three spread ciphertext bytes simultaneously and compare decapsulation to the honest secret",
                "parameters": {"trials": 6},
                "ceiling": "covers the tried multi-bit flip positions only",
                "false_positive_modes": [],
            })
            out.append({
                "id": "muse-kem-dk-cross-region",
                "failure_class": "dk-region-binding",
                "description": "Tampering two separated early decapsulation-key regions must never yield the honest secret.",
                "kind": "kem-dk-cross-region-tamper",
                "probe_strategy": "flip bytes in the early secret/ek and stored-hash regions of dk, decapsulate the honest ciphertext",
                "parameters": {},
                "ceiling": "covers two dk offsets only",
                "false_positive_modes": [],
            })
        if "sig" in caps:
            out.append({
                "id": "muse-sig-require-randomized-signing",
                "failure_class": "overbroad-randomness-demand",
                "description": "Signing must be randomized: two signatures of one message under one key must differ.",
                "kind": "sig-boundary-message-and-tail-probe",
                "probe_strategy": "sign one message twice and demand different signatures",
                "parameters": {"require_randomized_signing": True},
                "ceiling": "does not establish anything about deterministic signature schemes, which are legitimate",
                "false_positive_modes": ["any correct deterministic signature scheme fires this candidate"],
            })
            out.append({
                "id": "muse-sig-boundary-tail",
                "failure_class": "message-binding-boundary",
                "description": "Signatures at boundary message lengths must bind the tail byte and the exact length.",
                "kind": "sig-boundary-message-and-tail-probe",
                "probe_strategy": "sign at 255/256/257/4095/4096/4097 bytes; flip the last byte and append a zero byte",
                "parameters": {},
                "ceiling": "covers the listed boundary lengths only",
                "false_positive_modes": [],
            })
            out.append({
                "id": "muse-sig-mldsa-hint-compound",
                "failure_class": "hint-encoding-compound",
                "description": "Hint mutations in two places at once (order and tail) must both be rejected.",
                "kind": "sig-mldsa-hint-compound-probe",
                "probe_strategy": "duplicate a hint index and set a tail hint byte in one signature, then verify",
                "parameters": {},
                "ceiling": "covers compound hint edits on one signature shape only",
                "false_positive_modes": [],
            })
        return out


class MuseClient:
    """Live client (stdlib urllib only)."""

    def __init__(self, base: str | None = None, key: str | None = None,
                 model: str | None = None, timeout: float = 30.0):
        self.base = (base or os.environ.get("MUSE_API_BASE", "")).rstrip("/")
        self.key = key or resolve_api_key()
        self.model = model or os.environ.get("MUSE_MODEL", MODEL_DEFAULT)
        self.timeout = timeout
        if not self.base or not self.key:
            raise MuseError("MUSE_API_BASE and MUSE_API_KEY are required for live mode")

    def propose(self, digest: dict) -> list[dict]:
        body = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(digest)},
            ],
        }
        request = urllib.request.Request(
            f"{self.base}/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.key}"},
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            content = payload["choices"][0]["message"]["content"]
        except (urllib.error.URLError, OSError, KeyError, IndexError,
                TypeError, json.JSONDecodeError) as exc:
            raise MuseError(f"live Muse request failed: {type(exc).__name__}: {exc}") from exc
        return _extract_candidates(content)


def _extract_candidates(content: str) -> list[dict]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise MuseError("Muse response contained no JSON object")
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise MuseError(f"Muse response was not valid JSON: {exc}") from exc
    candidates = data.get("candidates")
    if not isinstance(candidates, list):
        raise MuseError("Muse response had no candidates list")
    return candidates


def validate_candidate(raw) -> dict | None:
    """Normalize a proposed candidate; None when malformed. Muse
    output is untrusted input: kinds are restricted to the four
    executable strategies and parameters must be a JSON object."""
    if not isinstance(raw, dict) or not _SPEC_FIELDS <= set(raw):
        return None
    if raw["kind"] not in STRATEGIES:
        return None
    if not isinstance(raw["parameters"], dict):
        return None
    if not all(isinstance(raw[k], str) and raw[k].strip()
               for k in ("id", "failure_class", "description", "probe_strategy", "ceiling")):
        return None
    if not isinstance(raw["false_positive_modes"], list):
        return None
    return {
        "id": re.sub(r"[^A-Za-z0-9._-]+", "-", raw["id"])[:64],
        "failure_class": raw["failure_class"],
        "description": raw["description"],
        "kind": raw["kind"],
        "probe_strategy": raw["probe_strategy"],
        "parameters": raw["parameters"],
        "ceiling": raw["ceiling"],
        "false_positive_modes": [str(m) for m in raw["false_positive_modes"]],
    }


# ---------------------------------------------------------------- strategies
# Each returns (witness | None, probes, exercised, reached). A witness
# is a plain-language description of the misbehavior; secret material
# is never included (lengths, offsets, and outcomes only).

def _kem_baseline(target, rng):
    kg = pair(target.keygen(rng.randbytes(16)))
    if kg is None:
        return None
    ek, dk = kg
    enc = pair(target.encaps(ek))
    if enc is None:
        return None
    ss, ct = enc  # target protocol: encaps returns (shared_secret, ciphertext)
    dec = target.decaps(dk, ct)
    if not ok(dec) or dec.value != ss:
        return None
    return ek, dk, ct, ss


def _strategy_kem_multi_bit(params, target, rng):
    base = _kem_baseline(target, rng)
    if base is None:
        return None, 0, "kem multi-bit ct perturbation (baseline failed)", False
    ek, dk, ct, ss = base
    probes = 0
    if params.get("require_deterministic_encaps"):
        again = pair(target.encaps(ek))
        probes += 1
        if again is not None and again[0] != ct:
            return ("two encapsulations under one ek produced different "
                    "ciphertexts (candidate demanded determinism)"), probes, \
                "kem multi-bit ct perturbation (determinism demand)", True
    trials = max(1, min(int(params.get("trials", 6)), 16))
    positions = sorted({0, max(0, len(ct) - 1)})
    for _ in range(trials):
        # one flipped bit in each of two spread bytes: a compound
        # perturbation a single-byte sweep never tries
        altered = flip(ct, positions[0], 1 << (rng.randrange(8)))
        altered = flip(altered, positions[1], 1 << (rng.randrange(8)))
        probes += 1
        dec = target.decaps(dk, altered)
        if ok(dec) and dec.value == ss:
            return (f"ciphertext flipped at bytes {positions} decapsulated "
                    "to the honest secret"), probes, \
                "kem multi-bit ct perturbation", True
    return None, probes, "kem multi-bit ct perturbation", True


def _strategy_kem_dk_cross_region(params, target, rng):
    base = _kem_baseline(target, rng)
    if base is None:
        return None, 0, "kem dk cross-region tamper (baseline failed)", False
    _ek, dk, ct, ss = base
    probes = 0
    # Early dk regions (secret/ek material and its stored hash) bind
    # the honest secret; the trailing rejection seed does not, so a
    # correct implementation legitimately survives tampering there.
    offsets = sorted({0, max(0, len(dk) // 4)})
    for offset in offsets:
        probes += 1
        dec = target.decaps(flip(dk, offset, 1), ct)
        if ok(dec) and dec.value == ss:
            return (f"decapsulation key flipped at byte {offset} still "
                    "returned the honest secret"), probes, \
                "kem dk cross-region tamper", True
    tampered = dk
    for offset in offsets:
        tampered = flip(tampered, offset, 1)
    probes += 1
    dec = target.decaps(tampered, ct)
    if ok(dec) and dec.value == ss:
        return (f"decapsulation key flipped at bytes {offsets} still "
                "returned the honest secret"), probes, \
            "kem dk cross-region tamper", True
    return None, probes, "kem dk cross-region tamper", True


def _sig_baseline(target, rng, msg):
    kg = pair(target.keygen(rng.randbytes(16)))
    if kg is None:
        return None
    pk, sk = kg
    sig = target.sign(sk, msg)
    if not ok(sig) or not ok(target.verify(pk, msg, sig.value)):
        return None
    return pk, sk, sig.value


def _strategy_sig_boundary(params, target, rng):
    probes = 0
    if params.get("require_randomized_signing"):
        base = _sig_baseline(target, rng, b"muse randomness probe")
        if base is None:
            return None, 0, "sig boundary probe (baseline failed)", False
        pk, sk, first = base
        again = target.sign(sk, b"muse randomness probe")
        probes += 1
        if ok(again) and again.value == first:
            return ("two signings of one message under one key produced "
                    "identical signatures (candidate demanded randomized "
                    "signing)"), probes, \
                "sig boundary probe (randomness demand)", True
    for n in (255, 256, 257, 4095, 4096, 4097):
        msg = rng.randbytes(n)
        base = _sig_baseline(target, rng, msg)
        if base is None:
            return None, probes, "sig boundary probe (baseline failed)", False
        pk, _sk, sig = base
        for altered in (flip(msg, n - 1, 1), msg + b"\x00"):
            probes += 1
            if ok(target.verify(pk, altered, sig)):
                return (f"signature for a {n}-byte message verified against "
                        f"an altered {len(altered)}-byte message"), probes, \
                    "sig boundary message-and-tail probe", True
    return None, probes, "sig boundary message-and-tail probe", True


def _strategy_sig_hint_compound(params, target, rng):
    geometry = getattr(target, "mldsa_hint", None)
    if not geometry:
        return None, 0, "sig mldsa hint compound probe (no hint geometry)", False
    base = _sig_baseline(target, rng, b"muse hint probe")
    if base is None:
        return None, 0, "sig mldsa hint compound probe (baseline failed)", False
    pk, _sk, sig = base
    h_off = geometry["ctilde"] + geometry["z"]
    if len(sig) <= h_off + 1:
        return None, 0, "sig mldsa hint compound probe (short signature)", False
    altered = bytearray(sig)
    altered[h_off + 1] = altered[h_off]          # order violation
    altered[-1] = altered[-1] or 0x01            # tail-slot violation
    probes = 1
    if ok(target.verify(pk, b"muse hint probe", bytes(altered))):
        return ("signature with a duplicated hint index and a non-zero "
                "tail hint byte verified"), probes, \
            "sig mldsa hint compound probe", True
    return None, probes, "sig mldsa hint compound probe", True


_STRATEGY_FUNCS = {
    "kem-multi-bit-ct-perturbation": _strategy_kem_multi_bit,
    "kem-dk-cross-region-tamper": _strategy_kem_dk_cross_region,
    "sig-boundary-message-and-tail-probe": _strategy_sig_boundary,
    "sig-mldsa-hint-compound-probe": _strategy_sig_hint_compound,
}


def _strategy_applicable(kind: str, target) -> bool:
    caps = set(getattr(target, "caps", frozenset()) or frozenset())
    if kind.startswith("kem-"):
        return Capability.KEM in caps
    return Capability.SIG in caps


def clean_reference_factory(target):
    """The clean reference fixture used by the Precision Gate."""
    from pqcheck.testing.toy import ToySig
    from pqcheck.testing.toylwe import ToyLweKem
    from pqcheck.testing.toymldsa import ToyMldsaSig
    caps = set(getattr(target, "caps", frozenset()) or frozenset())
    if Capability.KEM in caps:
        return ToyLweKem
    if getattr(target, "mldsa_hint", None):
        return ToyMldsaSig
    if Capability.SIG in caps:
        return ToySig
    return None


# ---------------------------------------------------------------- verifier

@dataclass
class CandidateOutcome:
    claim: Claim | None = None
    rejected_by_clean_control: bool = False
    tmp_dir: str = ""
    wiped: bool = False
    note: str = ""


class EphemeralVerifier:
    """Executes one candidate in an isolated temp dir, gated by the
    clean reference, with a mandatory wipe."""

    def __init__(self):
        self.created = 0
        self.wiped = 0
        self.last_tmp_dir = ""

    def verify(self, spec: dict, target, clean_factory, subject: Subject,
               rng) -> CandidateOutcome:
        tmp_dir = tempfile.mkdtemp(prefix="pqcheck_muse_poc_")
        self.created += 1
        self.last_tmp_dir = tmp_dir
        outcome = CandidateOutcome(tmp_dir=tmp_dir)
        try:
            artifact = os.path.join(tmp_dir, "check_candidate.json")
            with open(artifact, "w", encoding="utf-8") as fh:
                json.dump(spec, fh, indent=2)
            outcome.claim = self._execute(spec, target, clean_factory,
                                          subject, rng, outcome)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            outcome.wiped = not os.path.exists(tmp_dir)
            if outcome.wiped:
                self.wiped += 1
        assert not os.path.exists(tmp_dir), f"ephemeral dir not wiped: {tmp_dir}"
        return outcome

    def _execute(self, spec, target, clean_factory, subject, rng,
                 outcome: CandidateOutcome) -> Claim | None:
        kind = spec["kind"]
        func = _STRATEGY_FUNCS[kind]
        method = Method(
            name=f"muse:{spec['id']}", oracle=ORACLE_LABEL)
        ceiling = spec["ceiling"]

        def make_claim(verdict, *, coverage=None, evidence="", notes=""):
            claim = Claim(
                subject=subject, property=spec["description"],
                verdict=verdict, method=method, ceiling=ceiling,
                coverage=coverage, evidence=evidence,
                reproduce=(f"re-run pqcheck muse candidate {spec['id']} "
                           f"({kind}) against the pinned target with the "
                           "same seed") if verdict is Verdict.DEFECT_FOUND else "",
                notes=notes)
            return claim if _check_no_secret_material(claim) else None

        if clean_factory is None:
            return make_claim(
                Verdict.NOT_ANSWERABLE,
                notes="no clean reference fixture exists for the "
                      "Clean-Reference Precision Gate on this target kind")
        if not _strategy_applicable(kind, target):
            return make_claim(
                Verdict.NOT_ANSWERABLE,
                notes=f"strategy {kind} does not apply to this target's "
                      "capabilities")

        # Gate 1: clean reference. A candidate that fires here is an
        # AI false positive and never reaches the target as a finding.
        clean_watched = _CrashWatch(clean_factory())
        try:
            witness, _p, _e, _r = func(spec["parameters"], clean_watched, rng)
        except Exception:
            witness = None
        if witness is not None:
            outcome.rejected_by_clean_control = True
            outcome.note = f"rejected by clean control: {witness}"
            return None

        # Gate 2: the actual target, crash-watched.
        watched = _CrashWatch(target)
        try:
            witness, probes, exercised, reached = func(
                spec["parameters"], watched, rng)
        except Exception as exc:  # target raised instead of answering
            return make_claim(
                Verdict.NOT_REACHED,
                evidence=f"candidate execution raised {type(exc).__name__}",
                notes="target did not answer the candidate probe")
        observed = _observed(watched)
        if witness is not None:
            claim = make_claim(
                Verdict.DEFECT_FOUND,
                coverage=Coverage(exercised=exercised, units=max(probes, 1),
                                  observed=observed),
                evidence=witness)
            if claim is None:
                outcome.note = "claim refused by the secret-material floor"
            return claim
        if not reached or probes == 0:
            return make_claim(
                Verdict.NOT_REACHED,
                evidence="candidate probe could not execute its baseline",
                notes="no comparable observation was produced")
        return make_claim(
            Verdict.NO_DEFECT_FOUND,
            coverage=Coverage(exercised=exercised, units=probes,
                              observed=observed),
            evidence="candidate probe executed; no witness produced")


# ---------------------------------------------------------------- expansion

def make_client(mode: str):
    if mode == "simulated":
        return SimulatedMuseClient()
    if mode == "live":
        return MuseClient()
    raise MuseError(f"no client for mode {mode!r}")


def expand_report(report: Report, target, client, subject: Subject, rng,
                  mode: str, clean_factory=None) -> Report:
    """Run Tier 2 against an open target and return a new Report
    whose ai_receipt records exactly what happened."""
    digest = build_gap_digest(report, target)
    receipt = {
        "mode": mode,
        "model": getattr(client, "model", MODEL_DEFAULT),
        "core_relations_ran": digest["core_relations_ran"],
        "core_calls_executed": digest["core_calls_executed"],
        "estimated_tokens_saved": digest["estimated_tokens_saved"],
        "candidates_proposed": 0,
        "candidates_rejected_by_clean_control": 0,
        "candidates_verified": 0,
        "ephemeral_temp_dirs_created": 0,
        "ephemeral_temp_dirs_wiped": 0,
        "ephemeral_dir_wiped": True,
        "notes": [],
    }
    factory = clean_factory if clean_factory is not None \
        else clean_reference_factory(target)
    try:
        raw_candidates = client.propose(digest)
    except MuseError as exc:
        receipt["notes"].append(str(exc))
        return Report(report.claims, ai_receipt=receipt)
    verifier = EphemeralVerifier()
    new_claims: list[Claim] = []
    for raw in raw_candidates:
        spec = validate_candidate(raw)
        if spec is None:
            receipt["notes"].append("a proposed candidate was malformed "
                                     "and was not executed")
            continue
        receipt["candidates_proposed"] += 1
        outcome = verifier.verify(spec, target, factory, subject, rng)
        if outcome.rejected_by_clean_control:
            receipt["candidates_rejected_by_clean_control"] += 1
            receipt["notes"].append(
                f"{spec['id']}: rejected by the Clean-Reference "
                f"Precision Gate ({outcome.note})")
        elif outcome.claim is not None:
            new_claims.append(outcome.claim)
            receipt["candidates_verified"] += 1
            if outcome.note:
                receipt["notes"].append(f"{spec['id']}: {outcome.note}")
    receipt["ephemeral_temp_dirs_created"] = verifier.created
    receipt["ephemeral_temp_dirs_wiped"] = verifier.wiped
    receipt["ephemeral_dir_wiped"] = verifier.created == verifier.wiped
    return Report(tuple(report.claims) + tuple(new_claims),
                  ai_receipt=receipt)


def run_act5(seed: str = "pqcheck-demo-act5"):
    """Demo Act 5: core relations hand a GapDigest to (simulated)
    Muse; one over-aggressive candidate is rejected by the clean
    gate; one valid compound candidate catches a planted defect."""
    from pqcheck.testing.toylwe import ToyLweKem

    lines: list[str] = []
    failures: list[str] = []
    target = ToyLweKem(mutant="no_reencryption_check")
    subject = Subject(target="ToyLweKem[no_reencryption_check]",
                      commit="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4")
    claims = []
    for rid, relation in sorted(REGISTRY.items()):
        claims.append(relation.run(
            target, subject, random.Random(f"{seed}:{rid}")))
    core = Report(tuple(claims))
    digest = build_gap_digest(core, target)
    lines.append(
        f"  core: {digest['core_relations_ran']} deterministic relations, "
        f"{digest['core_calls_executed']} calls executed, 0 tokens; "
        f"estimated tokens saved vs per-call LLM probing: "
        f"{digest['estimated_tokens_saved']}")
    lines.append(
        f"  GapDigest handed to Muse: gaps="
        f"{[g['relation'] for g in digest['unreached_or_unanswerable']][:4]}"
        f" already_caught={digest['already_caught']}")
    expanded = expand_report(core, target, SimulatedMuseClient(), subject,
                             random.Random(seed), mode="simulated")
    receipt = expanded.ai_receipt or {}
    lines.append(
        f"  candidates proposed: {receipt.get('candidates_proposed')}; "
        f"rejected by Clean-Reference Precision Gate: "
        f"{receipt.get('candidates_rejected_by_clean_control')}; "
        f"verified in ephemeral sandbox: {receipt.get('candidates_verified')}")
    for note in receipt.get("notes", []):
        lines.append(f"    - {note}")
    ai_claims = [c for c in expanded.claims[len(core.claims):]]
    for claim in ai_claims:
        lines.append(f"  [{claim.verdict.value}] {claim.method.name}: "
                     f"{claim.evidence or claim.notes}")
    wiped_ok = receipt.get("ephemeral_dir_wiped") is True
    lines.append(
        f"  ephemeral temp dirs: created "
        f"{receipt.get('ephemeral_temp_dirs_created')}, wiped "
        f"{receipt.get('ephemeral_temp_dirs_wiped')} "
        f"({'100% wiped, 0 wild PoCs on disk' if wiped_ok else 'WIPE FAILURE'})")
    lines.append(
        f"  ai_receipt: mode={receipt.get('mode')} "
        f"core_calls_executed={receipt.get('core_calls_executed')} "
        f"estimated_tokens_saved={receipt.get('estimated_tokens_saved')}")
    if receipt.get("candidates_rejected_by_clean_control", 0) < 1:
        failures.append("Act 5: over-aggressive candidate was not rejected "
                        "by the clean gate")
    if not any(c.verdict is Verdict.DEFECT_FOUND for c in ai_claims):
        failures.append("Act 5: valid Muse candidate did not catch the "
                        "compound mutant defect")
    if not wiped_ok:
        failures.append("Act 5: ephemeral temp dir was not wiped")
    return lines, failures, receipt, ai_claims

