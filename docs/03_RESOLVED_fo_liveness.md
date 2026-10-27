# 03 — Resolved: FO liveness, decryption fibers, and encoding slack

Relation: `kem-fo-liveness`
([pqcheck/relations/kem_reject.py](../pqcheck/relations/kem_reject.py)).
This document records why the relation is shaped the way it is; the
argument was settled during the build and is locked by the precision
suite.

## The question

The Fujisaki–Okamoto transform only gives IND-CCA security if
decapsulation *re-encrypts* the recovered message and compares
against the submitted ciphertext. If that check is dead, a maimed
ciphertext can decapsulate to the **honest** shared secret, and the
KEM silently becomes malleable. `kem-fo-liveness` searches for a
witness: flip bits of an honest ciphertext, one byte at a time, and
see whether any corrupted ciphertext still returns the honest secret.

## Why some KEMs can never produce a witness (ElGamal shape)

In an ElGamal-style KEM, decryption is a function: each ciphertext
has **exactly one** decryption. The set of ciphertexts decrypting to
a given plaintext — the *decryption fiber* — is a singleton on the
honest path, and a corrupted ciphertext decrypts to something else
and is then rejected or implicitly rejected. If the implementation
re-encrypts and compares, the fiber over "honest secret" among
corrupted ciphertexts is empty **by construction**.

`ToyKem[no_reencryption_check]` models the failure: decapsulation
skips the re-encryption comparison, and near-honest ciphertexts
(within a couple of bit flips of the honest one) return the honest
secret directly. The witness coordinates in the demo
(`python -m pqcheck demo`, Act 2) are the byte offsets at which this
happens. The defect is not "malleability" in the abstract; it is a
dead check with named witnesses.

## Why Module-LWE KEMs produce witnesses even when correct

ML-KEM is not in the ElGamal situation. Decryption recovers a message
by decompressing and rounding noisy LWE samples. Compression maps
many coefficient values onto the same output, so the decryption
fiber over a message is **large**: many distinct ciphertext byte
strings decrypt to the same message. A single-bit flip in a
compressed coefficient frequently rounds to the same value —
empirically, a large fraction (design analyses put it around 69% for
typical ML-KEM parameters) of same-message single-bit witnesses
exist at the *decryption* layer.

So on a real Module-LWE KEM, "a corrupted ciphertext returned the
honest secret" has **two** possible explanations:

1. the FO re-encryption check is dead (a defect), or
2. the flip landed in compression/rounding slack, decryption
   recovered the same message, re-encryption produced the *original*
   ciphertext encoding, and the check legitimately passed — while
   the submitted bytes differ from the re-encrypted bytes.

A naive liveness relation cannot distinguish these and would fire on
correct ML-KEM implementations. That is a false positive worse than
a miss.

## How the relation separates the two

`ToyLweKem` exists to keep this honest: it is the LWE-flavoured toy
on which the compression-fiber shape is exercised, and the boundary
suite ([pqcheck/testing/precision.py](../pqcheck/testing/precision.py))
adds three declared-slack KEMs (`WideByteSlackCtKem`,
`InterleavedPadCtKem`, `AlignedCoeffCtKem`) whose slack is *part of
the format*.

`kem-fo-liveness` separates dead-check from slack via **per-byte
leaking bit-masks**: for each ciphertext byte, which bit flips leak
(return the honest secret) is measured per byte. The evidence rules
are enforced by the precision suite's `must_not_say` phrases:

- If exactly the declared slack bytes leak, the finding is reported
  as real ciphertext malleability in those bytes — never as
  "check is ABSENT".
- The phrase "exclude the one benign explanation" and the claim that
  the leaking mask "cannot span that many bytes" are forbidden
  unless the measurement actually excludes slack: witness bytes
  spanning body bytes that no declared slack covers.
- If the mask differs arbitrarily between bytes with no slack
  explanation, that is reported as measured, not theorised.

The relation is `one_sided`: finding no witness establishes nothing
(`NO_WITNESS_ESTABLISHES_NOTHING`), because a witness search over
single-bit flips cannot prove an FO check is live. This asymmetry is
the honest answer, and it is why the relation's clean verdict is
never counted as reassurance in a report.
