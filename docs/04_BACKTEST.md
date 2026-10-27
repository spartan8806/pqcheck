# pqcheck backtest report

Grades are incommensurable and are never summed into one number.

## Per-grade counts

| grade | count |
| --- | --- |
| DEMONSTRATED | 7 |
| ARGUED | 5 |
| PARTIAL | 4 |
| MISSED | 2 |
| OUT_OF_SCOPE | 4 |

## Entries

| grade | id | defect class | title |
| --- | --- | --- | --- |
| DEMONSTRATED | mlkem-ek-modulus | kem-encoding-canonicality | Non-canonical ek coefficients >= q are key-equivalent to the canonical ek (two byte strings, one key) |
| DEMONSTRATED | mlkem-dk-hash | kem-encoding-canonicality | ML-KEM decapsulation ignores a tampered H(ek) inside dk |
| DEMONSTRATED | fo-liveness-absent | kem-fujisaki-okamoto | Corrupted ciphertext decapsulates to the honest secret (FO check absent) |
| DEMONSTRATED | fo-binds-full-ct | kem-fujisaki-okamoto | Implicit-rejection secret does not bind the full ciphertext (PCO leak shape) |
| DEMONSTRATED | falcon-signed-zero | sig-encoding-canonicality | Falcon-shaped codec accepts a signed-zero coefficient stream |
| DEMONSTRATED | mldsa-hint-order | sig-encoding-canonicality | Verifier/codec accepts repeated or descending ML-DSA hint indices |
| DEMONSTRATED | planted-roundtrip-control | planted-control | Planted control: decapsulation does not invert encapsulation |
| ARGUED | fo-binds-z | kem-fujisaki-okamoto | Implicit-rejection secret is independent of the decapsulation key secret |
| ARGUED | decaps-truncated-ct | kem-length-exactness | Decapsulation accepts truncated or extended ciphertexts |
| ARGUED | wrong-key-accept | sig-verification-binding | Signature verifies under an unrelated public key |
| ARGUED | message-binding-failure | sig-verification-binding | Signature remains valid after the message is edited |
| ARGUED | ctx-ambiguity | sig-verification-binding | ML-DSA context string is not length-framed; ctx/msg splits collide |
| PARTIAL | falcon-pad-bits | sig-encoding-canonicality | Codec accepts non-zero padding bits after the stream |
| PARTIAL | sig-length-lax-verify | sig-length-exactness | Verify accepts signatures longer or shorter than the fixed length |
| PARTIAL | codec-stream-truncation | sig-encoding-canonicality | Codec accepts a truncated stream by silently zero-padding it |
| PARTIAL | past-buffer-guard-read | declared-length-safety | Verify/decaps behaviour depends on bytes past the declared buffer length |
| MISSED | clib-xmss-key-reuse | stateful-signature-state | XMSS stateful key reuse in a C library (state reuse across signatures) |
| MISSED | CVE-2022-37454 | declared-length-safety | Keccak/SHA-3 declared-length integer overflow in the reference C code |
| OUT_OF_SCOPE | clib-fndsa-double-ub | implementation-memory-safety | Double/undefined-behaviour defect in an FN-DSA C implementation |
| OUT_OF_SCOPE | mouha-update-chunking | streaming-hash-boundaries | Hash update chunking / streaming-boundary defect (Mouha class) |
| OUT_OF_SCOPE | KyberSlash-1-2 | side-channel-timing | Secret-dependent timing division in decapsulation (KyberSlash 1 and 2) |
| OUT_OF_SCOPE | GHSA-25rm-9wvm-m38v | advisory-tracked | Advisory-class defect tracked as GHSA-25rm-9wvm-m38v |

## By defect class

| defect class | in_scope | DEMONSTRATED | ARGUED | PARTIAL | MISSED | OUT_OF_SCOPE | gap |
| --- | --- | --- | --- | --- | --- | --- | --- |
| kem-encoding-canonicality | 2 | 2 | 0 | 0 | 0 | 0 |  |
| kem-fujisaki-okamoto | 3 | 2 | 1 | 0 | 0 | 0 |  |
| sig-encoding-canonicality | 4 | 2 | 0 | 2 | 0 | 0 |  |
| planted-control | 1 | 1 | 0 | 0 | 0 | 0 |  |
| kem-length-exactness | 1 | 0 | 1 | 0 | 0 | 0 | <-- gap |
| sig-verification-binding | 3 | 0 | 3 | 0 | 0 | 0 | <-- gap |
| sig-length-exactness | 1 | 0 | 0 | 1 | 0 | 0 | <-- gap |
| declared-length-safety | 2 | 0 | 0 | 1 | 1 | 0 | <-- gap |
| stateful-signature-state | 1 | 0 | 0 | 0 | 1 | 0 | <-- gap |
| implementation-memory-safety | 0 | 0 | 0 | 0 | 0 | 1 |  |
| streaming-hash-boundaries | 0 | 0 | 0 | 0 | 0 | 1 |  |
| side-channel-timing | 0 | 0 | 0 | 0 | 0 | 1 |  |
| advisory-tracked | 0 | 0 | 0 | 0 | 0 | 1 |  |

## Work queue — MISSED

- `clib-xmss-key-reuse`: XMSS stateful key reuse in a C library (state reuse across signatures)
- `CVE-2022-37454`: Keccak/SHA-3 declared-length integer overflow in the reference C code

## Disclosure state — derived, not asserted

- third-party — no disclosure asserted by pqcheck: 17 (mlkem-ek-modulus, mlkem-dk-hash, fo-liveness-absent, fo-binds-full-ct, falcon-signed-zero, mldsa-hint-order, fo-binds-z, decaps-truncated-ct, wrong-key-accept, message-binding-failure, ctx-ambiguity, falcon-pad-bits, sig-length-lax-verify, codec-stream-truncation, past-buffer-guard-read, clib-xmss-key-reuse, CVE-2022-37454)
- ours — disclosure: not-applicable: 1 (planted-roundtrip-control)
- third-party, out of scope — no disclosure asserted by pqcheck: 4 (clib-fndsa-double-ub, mouha-update-chunking, KyberSlash-1-2, GHSA-25rm-9wvm-m38v)

---

## Analysis (hand-written; the report above is generated)

Regenerate the report above with:

```sh
python -m pqcheck.backtest.report --md
```

Source: [pqcheck/backtest/corpus.py](../pqcheck/backtest/corpus.py)
and [pqcheck/backtest/report.py](../pqcheck/backtest/report.py).

### Reading the grades

The five grades are incommensurable on purpose. `DEMONSTRATED` is a
measurement: a registered relation was run against the defect shape
(toy mutant or real target) in this repository's own evidence.
`ARGUED` is an untested prediction: a relation addresses the shape
but no run against the historical instance is claimed. `PARTIAL` is
a partial measurement. Adding them into one coverage number would
repeat exactly the category error `Report.score()` refuses to make,
so this document never totals them.

### Ours vs theirs

Exactly one entry is ours: `planted-roundtrip-control`, a mutant we
planted ourselves to prove the harness can catch anything at all,
with disclosure state `not-applicable`. Everything else is a
third-party historical defect, and pqcheck asserts no disclosure
state for those — the disclosure section is *derived* from the
`ours` flag (`Defect.__post_init__` refuses to store a disclosure
claim on a third-party entry), not asserted per entry.

### The work queue

The two `MISSED` entries are the honest frontier:

- `clib-xmss-key-reuse` — stateful XMSS state reuse. pqcheck's
  relations are stateless; nothing asks whether signing state was
  reused across a tree boundary. See
  [06_LIMITATIONS.md](06_LIMITATIONS.md).
- `CVE-2022-37454` — the Keccak declared-length overflow lives in C
  size arithmetic below the API surface `core-declared-length-overflow`
  probes. The relation exists; this instance is out of its reach.

The `<-- gap` rows in the by-class table (any in-scope class with
zero DEMONSTRATED entries: kem-length-exactness,
sig-verification-binding, sig-length-exactness,
declared-length-safety, stateful-signature-state) are where argued
or partial coverage has not yet been converted into a demonstration.
That conversion — pick one historical instance, run the relation
against a real build, keep the evidence — is the highest-value next
work in this corpus, ahead of adding new relations.

### What this backtest is not

Statuses are accounting of which defect classes the shipped
relations can ask about, derived from the live registry and the
selftest evidence. They are not a re-run of vulnerable historical
versions, and this document must not be cited as one.

