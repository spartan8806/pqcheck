"""Auto-import all relation modules so REGISTRY is always complete."""
from pqcheck.relations import (  # noqa: F401
    bit_exclusion,
    core_invariants,
    encoding,
    kem_encoding,
    kem_reject,
    length_overflow,
    malleability,
    mldsa_encoding,
    sig_generic,
)
from pqcheck.relations.base import REGISTRY, Finding, NotApplicable, Relation, register

__all__ = ["REGISTRY", "Finding", "NotApplicable", "Relation", "register"]
