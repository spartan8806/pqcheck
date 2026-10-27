"""Historical defect corpus mapped to pqcheck relations.

Each entry carries exactly one grade from GRADES. The grades are
incommensurable: DEMONSTRATED is a measurement (a relation was run
against the defect shape), ARGUED is an untested prediction, PARTIAL is
a partial measurement, MISSED is a known gap, OUT_OF_SCOPE is outside
pqcheck's functional model. They must never be summed into one number.

Coverage here is accounting of which defect classes this tool can ask
about, not a claim that vulnerable versions were re-run here.
"""
from __future__ import annotations

from dataclasses import dataclass

GRADES = ["DEMONSTRATED", "ARGUED", "PARTIAL", "MISSED", "OUT_OF_SCOPE"]

DISCLOSURE_STATES = frozenset({"pending", "disclosed", "fixed", "not-applicable"})


@dataclass(frozen=True)
class Defect:
    id: str
    title: str
    defect_class: str
    grade: str
    relations: tuple[str, ...] = ()
    origin: str = ""
    ours: bool = False
    disclosure: str = ""
    note: str = ""

    def __post_init__(self):
        if self.grade not in GRADES:
            raise ValueError(f"grade must be one of {GRADES}, got {self.grade!r}")
        if self.ours and not self.disclosure:
            raise ValueError(
                f"{self.id}: ours=True requires a disclosure state; "
                "we do not list our own defects without one")
        if not self.ours and self.disclosure:
            raise ValueError(
                f"{self.id}: disclosure is only asserted for our own "
                "defects; third-party disclosure state is derived in "
                "report.py, not asserted here")
        if self.disclosure and self.disclosure not in DISCLOSURE_STATES:
            raise ValueError(
                f"{self.id}: disclosure must be one of "
                f"{sorted(DISCLOSURE_STATES)}, got {self.disclosure!r}")

    @property
    def out_of_scope(self) -> bool:
        return self.grade == "OUT_OF_SCOPE"


# Backwards-compatible alias: entries were formerly called CorpusEntry.
CorpusEntry = Defect


CORPUS: tuple[Defect, ...] = (
    # DEMONSTRATED: relation run against the defect shape (toy/mutant or
    # real target) in this repository's own test evidence.
    Defect("mlkem-ek-modulus", "Non-canonical ek coefficients >= q are key-equivalent to the canonical ek (two byte strings, one key)", "kem-encoding-canonicality", "DEMONSTRATED", ("kem-ek-modulus-canonical",), "ML-KEM implementations (FIPS 203 canonicality)"),
    Defect("mlkem-dk-hash", "ML-KEM decapsulation ignores a tampered H(ek) inside dk", "kem-encoding-canonicality", "DEMONSTRATED", ("kem-dk-hash-consistency",), "ML-KEM implementations (FIPS 203 Alg. 16)"),
    Defect("fo-liveness-absent", "Corrupted ciphertext decapsulates to the honest secret (FO check absent)", "kem-fujisaki-okamoto", "DEMONSTRATED", ("kem-fo-liveness",), "KEM implementations"),
    Defect("fo-binds-full-ct", "Implicit-rejection secret does not bind the full ciphertext (PCO leak shape)", "kem-fujisaki-okamoto", "DEMONSTRATED", ("kem-reject-binds-full-ciphertext", "kem-reject-ct-bit-contribution"), "KEM implementations"),
    Defect("falcon-signed-zero", "Falcon-shaped codec accepts a signed-zero coefficient stream", "sig-encoding-canonicality", "DEMONSTRATED", ("sig-encoding-signed-zero",), "Falcon / PQClean-shaped codecs"),
    Defect("mldsa-hint-order", "Verifier/codec accepts repeated or descending ML-DSA hint indices", "sig-encoding-canonicality", "DEMONSTRATED", ("mldsa-hint-strict-order", "mldsa-verify-hint-strict-order"), "ML-DSA implementations (FIPS 204)"),
    Defect("planted-roundtrip-control", "Planted control: decapsulation does not invert encapsulation", "planted-control", "DEMONSTRATED", ("core-kem-round-trip", "core-sig-round-trip"), "pqcheck planted mutant (control)", ours=True, disclosure="not-applicable"),
    # ARGUED: a registered relation addresses the shape, but no run
    # against the historical defect instance is claimed.
    Defect("fo-binds-z", "Implicit-rejection secret is independent of the decapsulation key secret", "kem-fujisaki-okamoto", "ARGUED", ("kem-reject-binds-z-accept-path-does-not",), "KEM implementations"),
    Defect("decaps-truncated-ct", "Decapsulation accepts truncated or extended ciphertexts", "kem-length-exactness", "ARGUED", ("kem-decaps-length-exact",), "KEM implementations"),
    Defect("wrong-key-accept", "Signature verifies under an unrelated public key", "sig-verification-binding", "ARGUED", ("sig-wrong-key-rejection",), "Signature implementations (incl. Go/Java crypto defect classes)"),
    Defect("message-binding-failure", "Signature remains valid after the message is edited", "sig-verification-binding", "ARGUED", ("sig-message-binding",), "Signature implementations"),
    Defect("ctx-ambiguity", "ML-DSA context string is not length-framed; ctx/msg splits collide", "sig-verification-binding", "ARGUED", ("sig-ctx-binding",), "ML-DSA implementations (FIPS 204)"),
    # PARTIAL: some, but not all, of the defect shape is reachable.
    Defect("falcon-pad-bits", "Codec accepts non-zero padding bits after the stream", "sig-encoding-canonicality", "PARTIAL", ("sig-encoding-pad-bits-zero",), "Falcon-shaped codecs"),
    Defect("sig-length-lax-verify", "Verify accepts signatures longer or shorter than the fixed length", "sig-length-exactness", "PARTIAL", ("sig-verify-length-exact", "sig-encoding-length-exact"), "Signature implementations"),
    Defect("codec-stream-truncation", "Codec accepts a truncated stream by silently zero-padding it", "sig-encoding-canonicality", "PARTIAL", ("sig-encoding-length-exact", "streaming-incremental-decode"), "Signature/hint codecs", note="Incremental/streaming decode surfaces are not modelled; the fixed-length relation alone is only partial coverage."),
    Defect("past-buffer-guard-read", "Verify/decaps behaviour depends on bytes past the declared buffer length", "declared-length-safety", "PARTIAL", ("kem-declared-length-bit-exclusion", "sig-declared-length-bit-exclusion"), "C PQC libraries (LibOQS/PQClean defect class)"),
    # MISSED: known defects no registered relation catches. Work queue.
    Defect("clib-xmss-key-reuse", "XMSS stateful key reuse in a C library (state reuse across signatures)", "stateful-signature-state", "MISSED", (), "C XMSS implementations", note="Stateful signing state is outside pqcheck's stateless relation model as shipped; no relation asks about state reuse."),
    Defect("CVE-2022-37454", "Keccak/SHA-3 declared-length integer overflow in the reference C code", "declared-length-safety", "MISSED", ("core-declared-length-overflow",), "XKCP / pysha3 and downstream", note="The historical overflow is in C size arithmetic below the API surface the relation probes; the relation exists but does not reach this instance."),
    # OUT_OF_SCOPE: outside pqcheck's functional relation model.
    Defect("clib-fndsa-double-ub", "Double/undefined-behaviour defect in an FN-DSA C implementation", "implementation-memory-safety", "OUT_OF_SCOPE", (), "FN-DSA C implementations", note="Memory/UB defects need a sanitizer or C-level harness, not functional relations."),
    Defect("mouha-update-chunking", "Hash update chunking / streaming-boundary defect (Mouha class)", "streaming-hash-boundaries", "OUT_OF_SCOPE", (), "Hash implementations", note="Streaming update-boundary behaviour is not modelled by pqcheck relations."),
    Defect("KyberSlash-1-2", "Secret-dependent timing division in decapsulation (KyberSlash 1 and 2)", "side-channel-timing", "OUT_OF_SCOPE", (), "ML-KEM implementations", note="Side-channel timing is outside pqcheck's functional relation model; see the timing harness for an instrument-bound check."),
    Defect("GHSA-25rm-9wvm-m38v", "Advisory-class defect tracked as GHSA-25rm-9wvm-m38v", "advisory-tracked", "OUT_OF_SCOPE", (), "Tracked via GitHub advisory", note="Recorded for completeness; the defect shape is outside the shipped relation set."),
)
