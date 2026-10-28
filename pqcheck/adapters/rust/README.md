# Rust codec harness (pinned upstream Falcon codec)

`codec_harness.rs` is only the line-protocol shell that
`pqcheck/adapters/codec_bridge.py` (`CodecTarget`) speaks
(`info` / `encode` / `decode`; `REJ` = codec refused, `ERR` = harness
declined). The codec it runs is the **actual pinned upstream code**,
not a reimplementation.

## What is under test

- Upstream: `falcon-rust` **v0.3.0**, commit
  `8845fe573b2108a1a84eced6c438a4aeb6b3773c`
- File: `falcon-rust/src/encoding.rs` (`compress` / `decompress`),
  vendored byte-identical as `upstream_encoding.rs` here
- SHA-256 of that file:
  `a6eb5fd5e891c69627b76cd6ef249a54392730000624b5afa6aec78032eae02a`
  (pinned in `Cargo.toml` and enforced by
  `tests/test_audit_fixes.py::RustHarnessTests`)

Why a vendored copy instead of a crate dependency: at the pinned
revision upstream declares `pub(crate) mod encoding`, so an external
crate cannot import `falcon_rust::encoding::compress` (rustc
E0603), and its `compress` takes `(coefficients, byte_length)`.
Vendoring the unmodified file is the only way to compile and run
the pinned upstream functions themselves. The file's own imports
(`bit-vec`, `itertools`, `num`) are pinned in `Cargo.toml`;
`falcon-profiler`, upstream's path-only workspace member, is
supplied by the no-op proc-macro shim in `falcon-profiler/` (its
`profiling` attribute is instrumentation only).

An earlier revision of this harness replaced the upstream codec
with a locally written one. That was withdrawn: it tested pqcheck's
own code instead of the target, and its bit layout did not even
match Falcon's (it used 8 low bits and 1-terminated unary; the
format is 7 low bits and 0-runs terminated by 1). See
DEVIATIONS.md item 20.

## Build

```sh
cargo build --release   # in this directory
cp target/release/pqcheck_codec_harness ../pqcheck_codec_harness
```

Then point a `codec` manifest at `pqcheck/adapters/pqcheck_codec_harness`.
Do not run `cargo test` in this crate: the vendored file's own
`#[cfg(test)]` module references other upstream crate internals
that are not vendored.

## Cross-implementation vectors

`pqcheck/testing/falcon_vectors.json` pins encoding vectors from
three independent sides: Noble falcon512 signature encodings
(@noble/post-quantum 0.6.1), hand-computed Falcon-spec vectors, and
non-canonical negative vectors. pqcheck's independent spec codec
(`pqcheck/testing/falcon_codec.py`) must reproduce Noble's bytes
exactly, and `probes/verify_falcon_cross_vectors.py` drives this
harness's upstream `compress`/`decompress` against the same vectors
when the binary exists (it exits 77, an explicit skip, when it does
not).

The harness was not compiled in the pqcheck build environment (no
Rust toolchain there); the vendored-file hash, protocol shell, and
cross-implementation vectors above are what is verified. See
DEVIATIONS.md.
