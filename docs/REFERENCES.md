# References

## Standards

- **FIPS 203** — Module-Lattice-Based Key-Encapsulation Mechanism
  Standard (ML-KEM). NIST, 2024. Source of the `ek` 12-bit coefficient
  packing (`ByteEncode_12`/`ByteDecode_12`), the `dk` layout with
  `H(ek)`, and modulus canonicality (`c < q`) checked by
  `kem-ek-modulus-canonical` and `kem-dk-hash-consistency`.
- **FIPS 204** — Module-Lattice-Based Digital Signature Standard
  (ML-DSA). NIST, 2024. Source of the context-string framing, the
  hint encoding (`h`: `omega` index bytes plus `k` cumulative
  offsets), and the strict hint ordering checked by the `mldsa-*`
  relations.
- **FIPS 205** — Stateless Hash-Based Digital Signature Standard
  (SLH-DSA). NIST, 2024. Reference point for stateless hash-based
  signatures; contrast with the stateful XMSS reuse gap recorded in
  the backtest work queue.
- **Falcon v1.2** — Fouque et al., "Falcon: Fast-Fourier Lattice-based
  Compact Signatures over NTRU", specification v1.2. Source of the
  sign-magnitude compressed signature encoding whose signed-zero and
  padding canonicality the `sig-encoding-*` relations check.

## Research

- Fenzi, Gilcher, Virdia — TCHES 2026; ePrint 2024/1122.
  Metamorphic/property-based testing perspective for cryptographic
  implementations; citation as supplied for the relations approach.
- Mouha et al. — SHA-3 bit-exclusion / declared-length analysis;
  ePrint 2017/891. Background for the declared-length and
  guard/bit-exclusion relations (`core-declared-length-overflow`,
  `kem-declared-length-bit-exclusion`,
  `sig-declared-length-bit-exclusion`).
- KyberSlash — Bernstein et al., secret-dependent timing divisions in
  Kyber/ML-KEM decapsulation; ePrint 2024/1049. Recorded in the
  backtest corpus as `KyberSlash-1-2` (OUT_OF_SCOPE for functional
  relations; see the timing harness in
  [pqcheck/adapters/timing_probe.py](../pqcheck/adapters/timing_probe.py)).

## Defect reports and advisories

- `liboqs#1315` — liboqs issue 1315; historical defect-class reference
  for the C-library targets exercised through
  [manifests/liboqs.json](../manifests/liboqs.json).
- `PQClean#601` — PQClean issue 601; non-canonical ML-KEM `ek`
  coefficient acceptance class, reproduced in shape by
  `kem-ek-modulus-canonical`.
- `CVE-2022-21449` — "Psychic Signatures": Java ECDSA accepted
  all-zero `(r, s)` values. The `sig-degenerate-values` relation is
  the pqcheck shape for this class.
- `CVE-2022-37454` — Keccak/SHA-3 declared-length integer overflow
  (XKCP and downstream). Recorded in the backtest corpus as MISSED:
  the relation exists, the historical C size-arithmetic instance is
  below the probed API surface.
- Advisory identifiers are cited here only when they resolve in a
  public database (CVE / GitHub Advisory Database / RUSTSEC).
  Unverified identifiers are not cited; historical shapes without a
  public advisory are described by defect class in the backtest
  corpus instead.
