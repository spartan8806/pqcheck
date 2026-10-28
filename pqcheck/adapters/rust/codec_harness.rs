//! pqcheck codec line protocol in Rust, forwarding to the pinned
//! upstream falcon-rust v0.3.0 compression codec.
//!
//! Protocol (identical to codec_bridge.py):
//!   info           -> OK kind=codec ncoef=512 sig=625 fixed=1
//!   encode <c0> <c1> ... (512 coefficients)
//!                  -> OK <hex> | REJ <why> | ERR <why>
//!   decode <hex|-> -> OK <int16 block hex> | REJ <why> | ERR <why>
//! Buffers are handled at exact lengths; REJ is the codec refusing an
//! input, ERR is this harness declining.
//!
//! This file is only the protocol shell. The codec itself is
//! upstream's `compress`/`decompress`, compiled from the
//! byte-identical vendored copy in upstream_encoding.rs
//! (falcon-rust v0.3.0, commit
//! 8845fe573b2108a1a84eced6c438a4aeb6b3773c, sha256
//! a6eb5fd5e891c69627b76cd6ef249a54392730000624b5afa6aec78032eae02a).
//! Upstream marks its encoding module `pub(crate)`, so the vendored
//! file is how the pinned upstream functions are linked unmodified;
//! see Cargo.toml and README.md in this directory. There is no
//! locally written codec in this harness.

use std::io::{self, BufRead, Write};

#[path = "upstream_encoding.rs"]
mod upstream_encoding;

use upstream_encoding::{compress, decompress};

const N: usize = 512;
const SLEN: usize = 625;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text == "-" {
        return Some(Vec::new());
    }
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn reply(stdout: &mut impl Write, text: &str) {
    let _ = writeln!(stdout, "{text}");
    let _ = stdout.flush();
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "info" => reply(&mut stdout, &format!("OK kind=codec ncoef={N} sig={SLEN} fixed=1")),
            "encode" => {
                if parts.len() != N + 1 {
                    reply(&mut stdout, &format!("ERR encode needs {N} coefficients"));
                    continue;
                }
                let mut coeffs = [0i16; N];
                let mut bad = false;
                for (slot, token) in coeffs.iter_mut().zip(&parts[1..]) {
                    match token.parse::<i16>() {
                        Ok(value) => *slot = value,
                        Err(_) => {
                            bad = true;
                            break;
                        }
                    }
                }
                if bad {
                    reply(&mut stdout, "ERR bad coefficient");
                    continue;
                }
                match compress(&coeffs, SLEN) {
                    Some(stream) => reply(&mut stdout, &format!("OK {}", hex_encode(&stream))),
                    None => reply(&mut stdout, "REJ encode refused"),
                }
            }
            "decode" => {
                let Some(arg) = parts.get(1) else {
                    reply(&mut stdout, "ERR decode needs hex");
                    continue;
                };
                let Some(input) = hex_decode(arg) else {
                    reply(&mut stdout, "ERR bad hex");
                    continue;
                };
                match decompress(&input, N) {
                    Some(coeffs) => {
                        let mut block = Vec::with_capacity(N * 2);
                        for c in coeffs.iter().take(N) {
                            block.extend_from_slice(&c.to_le_bytes());
                        }
                        reply(&mut stdout, &format!("OK {}", hex_encode(&block)));
                    }
                    None => reply(&mut stdout, "REJ decode refused"),
                }
            }
            _ => reply(&mut stdout, "ERR unknown command"),
        }
    }
}
