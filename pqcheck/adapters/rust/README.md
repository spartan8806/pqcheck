# Rust codec harness

`codec_harness.rs` implements the exact line protocol that
`pqcheck/adapters/codec_bridge.py` (`CodecTarget`) speaks, forwarding to
`falcon_rust::encoding::{compress, decompress}` with `N = 512` and
`SLEN = 625`. It proves the harness contract is language-independent:
any process that answers `info` / `encode` / `decode` honestly
(`REJ` = codec refused, `ERR` = harness declined) can be driven by
pqcheck, whatever language it is written in.

## Build (inside a crate that depends on falcon_rust)

```sh
rustc -O codec_harness.rs --extern falcon_rust=<path-to-libfalcon_rust.rlib>
# or add it as src/main.rs in a crate with falcon_rust as a dependency
```

Then point a `codec` manifest at the resulting binary. The harness was
not compiled in the pqcheck build environment (no Rust toolchain was
available there); see DEVIATIONS.md.
