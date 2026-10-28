# Harness templates: plug any language into pqcheck

pqcheck keeps the target behind a tiny stdin/stdout line protocol.
A harness reads one request per line, writes exactly one reply per
line, with hex payloads and exact-length hex decoding.

## The protocol (6 verbs plus `info`)

```
info                    -> OK kind=kem alg=<name> pk=.. sk=.. ct=.. ss=..
                        -> OK kind=sig alg=<name> pk=.. sk=.. sig=..
keygen <seed|->         -> OK <pk-hex> <sk-hex>     ("-" = no seed pinned)
encaps <pk-hex>         -> OK <ss-hex> <ct-hex>
decaps <sk-hex> <ct>    -> OK <ss-hex>
sign <sk-hex> <msg>     -> OK <sig-hex>
verify <pk> <msg> <sig> -> OK | REJ <reason>
guard <hex|->           -> OK
```

Replies begin `OK`, `REJ` (the target rejected the input), or `ERR`
(the harness itself could not process the request — this makes
pqcheck report a protocol problem, not a target defect). A line
longer than the harness's buffer must get `ERR` and be discarded,
never truncated into a valid request.

## Connecting a language

- **Python** — [python_harness.py](python_harness.py); either as a
  subprocess (below) or in-process via `"adapter": "python"`, where
  the manifest names a module and a target class per algorithm
  (see [manifests/python-reference.json](../../../manifests/python-reference.json)).
- **Java** — [JavaKemSigHarness.java](JavaKemSigHarness.java)
  (JDK `javax.crypto.KEM` for ML-KEM, `java.security.Signature` for
  ML-DSA). Launched through the `exec` adapter:
  `"command": ["java", "-cp", "...", "JavaKemSigHarness"]`.
- **Rust** — [rust_kem_sig_harness.rs](rust_kem_sig_harness.rs)
  (std only; swap the `Library` stub for RustCrypto `ml-kem`/`ml-dsa`).
- **C/C++** — the direct `c` adapter takes a binary path; see
  [pqcheck/adapters/c_harness.c](../c_harness.c). C++ can speak either
  that protocol or the `exec` protocol unchanged.
- **Go** — no template ships; the `exec` adapter with any Go binary
  implementing the 6 verbs above works. Follow
  [python_harness.py](python_harness.py) line for line.
- **JS** — `@noble/post-quantum` is built in via the `noble` adapter;
  other JS libraries can be wrapped with `exec` + `node harness.mjs`.

## The two ways pqcheck launches a harness

1. `"adapter": "exec"` with `"command": ["java", "-cp", "...", "PqHarness"]`
   — pqcheck appends `<kind> <algorithm>` to the argv and speaks the
   line protocol. Any language runtime works this way.
2. `"adapter": "c"` with `"harness": "./build/harness"` — same
   protocol, binary path instead of argv list.

## Rules for harness authors

- Never print anything except the one reply line per request to
  stdout (log to stderr).
- Validate hex exactly (even length, hex chars): garbage in must be
  `REJ` or `ERR`, never silently zero-padded.
- Only declare seeded key generation if the library truly pins it;
  otherwise `keygen -` must work and pqcheck will not claim pinned
  randomness for you.
- Stateless protocol: pqcheck may create a fresh harness process per
  algorithm run. Signing state that advances (XMSS/LMS/HSS) cannot
  be modelled and is refused by design.
