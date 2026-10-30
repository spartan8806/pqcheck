# 01 — Specification of the 34 relations

Code: [pqcheck/relations/](../pqcheck/relations/) — registry in
[pqcheck/relations/base.py](../pqcheck/relations/base.py), shared
controls in [pqcheck/relations/_common.py](../pqcheck/relations/_common.py).
List them live with `python -m pqcheck relations`.

## Controls vocabulary

- `control` (positive control): a baseline round trip the runner
  executes before the check. Failure → `NOT_REACHED`
  ("positive control failed: …"), never a silent pass.
- `probe_control` (constructed-probe control, `constructs_probes=True`):
  for relations that build byte-level probes against an assumed
  layout, the layout itself is validated first (e.g. unpack/repack of
  the `ek` body is byte-identical). Failure → `NOT_ANSWERABLE`:
  the assumed layout does not describe this target.
- `needs_control=False` relations are loud reporters: they may fire
  on targets too broken for any controlled relation to ask its
  question.

## Relation table

| Relation | Property (abbreviated) | Requires | Ceiling (what it does not establish) |
| --- | --- | --- | --- |
| `core-codec-round-trip` | decode(encode(v)) recovers v | raw_decode | rejection of non-canonical streams |
| `core-declared-length-overflow` | declared lengths wrapping 16/32/64-bit arithmetic are rejected | sig, declared_length | overflow handling on untested entry points |
| `core-declared-sizes-match-produced` | declared sizes match produced byte lengths | — | cryptographic correctness of produced values |
| `core-input-length-boundaries` | sign/verify work at B−1, B, B+1 boundaries | sig | correctness for unbounded lengths |
| `core-kem-round-trip` | decaps(dk, encaps(ek)) returns the secret | kem | implicit-rejection correctness, side channels |
| `core-sig-round-trip` | produced signatures verify under the matching key | sig | unforgeability, canonical encoding |
| `kem-decaps-length-exact` | decaps rejects any ciphertext length ≠ exact | kem, explicit_sig_length | length handling on other inputs |
| `kem-declared-length-bit-exclusion` | decaps/encaps do not depend on 64 guard bytes past the buffer | kem, guard_fill | memory safety beyond the guarded inputs |
| `kem-degenerate-ciphertext` | degenerate ciphertexts reject deterministically, distinctly, never to the honest secret | kem | all malformed ciphertext classes |
| `kem-dk-hash-consistency` | tampered `H(ek)` inside `dk` never yields the honest secret (constructs_probes) | kem | full FIPS 203 Algorithm 16 key format beyond `H(ek)` |
| `kem-dk-rejects-hash-mismatch` | a `validate-on-entry` decapsulation entry point rejects a `dk` whose stored `H(ek)` is altered (constructs_probes; Set 3) | kem, declared `validation.dk=validate-on-entry` | key validation under `prevalidated-input`/`unspecified` contracts (declines) |
| `kem-ek-modulus-canonical` | `ek` coefficients in [q, 4095] are never key-equivalent to the canonical `ek` (constructs_probes) | kem | that encaps validates/rejects non-canonical input (only key-equivalence is a defect) |
| `kem-ek-rejects-noncanonical` | a `validate-on-entry` encapsulation entry point rejects `ek` coefficients equal to q or 4095 (≤32 probes; constructs_probes; Set 3) | kem, declared `validation.ek=validate-on-entry` | key validation under `prevalidated-input`/`unspecified` contracts (declines) |
| `kem-fo-liveness` | no corrupted ciphertext decapsulates to the honest secret (one-sided) | kem | FO correctness when no witness is found |
| `kem-reject-binds-full-ciphertext` | implicit-rejection secret binds every ciphertext byte | kem | FO security beyond binding |
| `kem-reject-binds-z-accept-path-does-not` | implicit rejection binds the key's `z`; accept path does not leak it | kem | key-independence of the honest path |
| `kem-reject-ct-bit-contribution` | every probed ciphertext byte/bit contributes to the rejection secret | kem | indistinguishability of the rejection secret |
| `kem-reject-determinism` | implicit rejection is deterministic per (key, ciphertext) | kem | constant-time behaviour |
| `mldsa-hint-strict-order` | hint indices per row strictly increase (codec surface) | raw_decode | hint correctness in signatures |
| `mldsa-hint-tail-zero` | unused hint-index bytes are zero (codec surface) | raw_decode | hint correctness in signatures |
| `mldsa-verify-hint-strict-order` | verify rejects repeated/descending hint indices | sig, detached_sig, mldsa_hint_encoding | hint handling beyond ordering |
| `mldsa-verify-hint-tail-zero` | verify rejects non-zero unused hint slots | sig, detached_sig, mldsa_hint_encoding | hint handling beyond the zero tail |
| `sig-ctx-binding` | context string is length-framed and bound (no `ctx||msg` split ambiguity) | sig, ctx_string | prehash domain separation |
| `sig-declared-length-bit-exclusion` | sign/verify do not depend on 64 guard bytes past the buffer | sig, guard_fill | memory safety beyond the guarded inputs |
| `sig-degenerate-values` | all-zero/all-ones signatures and zero key/signature are rejected | sig | all degenerate algebraic values |
| `sig-encoding-decode-reencode-identity` | encode∘view∘decode∘encode is the identity at realistic magnitudes | raw_decode | rejection of non-canonical streams |
| `sig-encoding-length-exact` | codec rejects any stream length ≠ exact | raw_decode | variable-length codecs (declines) |
| `sig-encoding-pad-bits-zero` | padding bits after the stream must be zero | raw_decode | canonicality inside the stream |
| `sig-encoding-signed-zero` | codec rejects a signed-zero (−0) stream (constructs_probes) | raw_decode | canonicality of non-zero coefficients |
| `sig-message-binding` | a signature binds the exact message bytes and length (short probes plus lengths around 256/512/1024/4096/65536, ≤65,537 bytes, ≤1,024 altered verifications per algorithm; Set 3) | sig | context/mode binding; binding for untested lengths/edit classes |
| `sig-mode-domain-separation` | prehash and direct modes do not cross-verify | sig | correctness of the prehash function |
| `sig-unread-bits` | every signature bit is read by verify | sig | strong unforgeability |
| `sig-verify-length-exact` | verify rejects any signature length ≠ fixed length | sig, detached_sig, explicit_sig_length | variable-length schemes (declines) |
| `sig-wrong-key-rejection` | a signature does not verify under an independent key | sig | unforgeability against chosen-message attacks |

## False-positive modes (declared, per relation)

Relations declare `false_positive_modes` where a correct target can
look defective. The load-bearing ones:

- `kem-fo-liveness`: declared encoding slack is real malleability,
  not a dead FO check. Evidence lists the witness byte offsets;
  separating declared slack from a dead check is the precision suite's job (may_fire), not this relation's.
- `kem-ek-modulus-canonical`: accepting a bumped `ek` as a *distinct*
  key is not a defect; only key-equivalence is reported.
- `sig-unread-bits`: variable-length encodings with declared slack
  may legitimately have unread bits.
- `mldsa-verify-hint-strict-order`: a verifier that canonicalises
  hint order internally accepts the byte string; pqcheck reports the
  byte-level acceptance and says so.

All other relations inherit the empty tuple: no known false-positive
mode beyond the stated ceiling. The precision suite
([02_VALIDATION.md](02_VALIDATION.md)) is the enforcement mechanism:
a relation that fires outside its declared `may_fire` set on a
correct boundary target fails the build.
