//! pqcheck line-protocol harness template for Rust.
//!
//! pqcheck launches this harness as an "exec" adapter target (or via
//! the C-bridge argv convention) and appends:  <kem|sig> <algorithm>
//! e.g.  rust_kem_sig_harness kem ML-KEM-768
//!
//! Protocol (one request per line on stdin, one reply per line):
//!   info                    -> OK kind=kem alg=ML-KEM-768 pk=.. sk=.. ct=.. ss=..
//!   keygen <seed|->         -> OK <pk-hex> <sk-hex>
//!   encaps <pk>             -> OK <ss-hex> <ct-hex>
//!   decaps <sk> <ct>        -> OK <ss-hex>
//!   sign <sk> <msg>         -> OK <sig-hex>
//!   verify <pk> <msg> <sig> -> OK | REJ <reason>
//!   guard <hex|->           -> OK
//! Bad hex or unknown verbs get ERR; over-long lines get ERR and are
//! discarded, never truncated into a valid request.
//!
//! This template uses only std. The `Library` stub below is a tiny
//! deterministic toy so the wire shape compiles and runs; replace the
//! ADAPT sections with your real crates (e.g. RustCrypto `ml-kem` /
//! `ml-dsa`) and their exact key/signature byte formats.

use std::io::{BufRead, Write};

const MAX_LINE: usize = 1_000_000;

// ---------- hex helpers ----------
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let nib = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("non-hex character".into()),
        }
    };
    for pair in bytes.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- toy digest (template plumbing only, NOT cryptography) ----------
fn digest(label: &[u8], parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    // FNV-1a style expand; replace with the real scheme's primitives.
    let mut state: u64 = 0xcbf29ce484222325;
    let mut mix = |bytes: &[u8], state: &mut u64| {
        for &b in bytes {
            *state ^= b as u64;
            *state = state.wrapping_mul(0x100000001b3);
        }
    };
    mix(label, &mut state);
    for p in parts {
        mix(&(p.len() as u64).to_be_bytes(), &mut state);
        mix(p, &mut state);
    }
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        mix(&state.to_be_bytes(), &mut state);
        out.extend_from_slice(&state.to_be_bytes());
    }
    out.truncate(out_len);
    out
}

// ---------- ADAPT: your library ----------
struct Library {
    kind: String,
    alg: String,
    last: Option<(Vec<u8>, Vec<u8>)>,
    ctr: u64,
}

impl Library {
    // sizes: pk, sk, ct (kem) or sig (sig), ss (kem)
    fn sizes(&self) -> (usize, usize, usize, usize) {
        match (self.kind.as_str(), self.alg.as_str()) {
            ("kem", "ML-KEM-512") => (800, 1632, 768, 32),
            ("kem", "ML-KEM-768") => (1184, 2400, 1088, 32),
            ("kem", "ML-KEM-1024") => (1568, 3168, 1568, 32),
            ("sig", "ML-DSA-44") => (1312, 2560, 2420, 0),
            ("sig", "ML-DSA-65") => (1952, 4032, 3309, 0),
            ("sig", "ML-DSA-87") => (2592, 4896, 4627, 0),
            _ => (32, 96, 32, 32),
        }
    }

    fn keygen(&mut self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // ADAPT: call the real key generation; note whether a seed
        // can be pinned (pqcheck only then declares PINNED_RANDOMNESS).
        let seed = if seed.is_empty() { b"default-seed" } else { seed };
        if self.kind == "kem" {
            let ek = digest(b"ek", &[seed], 32);
            let h = digest(b"H", &[&ek], 32);
            let z = digest(b"z", &[seed], 32);
            let mut dk = ek.clone();
            dk.extend_from_slice(&h);
            dk.extend_from_slice(&z);
            (ek, dk)
        } else {
            let sk = digest(b"sk", &[seed], 32);
            let pk = digest(b"pk", &[&sk], 32);
            (pk, sk)
        }
    }

    fn encaps(&mut self, ek: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.ctr += 1;
        let ct = digest(b"ct", &[ek, &self.ctr.to_be_bytes()], 32);
        let ss = digest(b"ss", &[ek, &ct], 32);
        self.last = Some((ct.clone(), ss.clone()));
        (ss, ct)
    }

    fn decaps(&mut self, dk: &[u8], ct: &[u8]) -> Vec<u8> {
        let ek = &dk[..32.min(dk.len())];
        digest(b"ss", &[ek, ct], 32)
    }

    fn sign(&mut self, sk: &[u8], msg: &[u8]) -> Vec<u8> {
        let pk = digest(b"pk", &[sk], 32);
        digest(b"sig", &[&pk, msg], 64)
    }

    fn verify(&mut self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        sig == digest(b"sig", &[pk, msg], 64)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if args.len() < 3 {
        writeln!(out, "ERR usage: rust_kem_sig_harness <kem|sig> <algorithm>").unwrap();
        return;
    }
    let mut lib = Library {
        kind: args[1].clone(),
        alg: args[2].clone(),
        last: None,
        ctr: 0,
    };
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.len() > MAX_LINE {
            writeln!(out, "ERR line exceeds this harness's input buffer").unwrap();
            out.flush().unwrap();
            continue;
        }
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.is_empty() {
            continue;
        }
        let reply: String = (|| -> Result<String, String> {
            match p[0] {
                "info" => {
                    let (pk, sk, x, ss) = lib.sizes();
                    if lib.kind == "kem" {
                        Ok(format!("OK kind=kem alg={} pk={pk} sk={sk} ct={x} ss={ss}", lib.alg))
                    } else {
                        Ok(format!("OK kind=sig alg={} pk={pk} sk={sk} sig={x}", lib.alg))
                    }
                }
                "keygen" => {
                    let seed = if p.len() > 1 { unhex(p[1])? } else { Vec::new() };
                    let (a, b) = lib.keygen(&seed);
                    Ok(format!("OK {} {}", hex(&a), hex(&b)))
                }
                "encaps" => {
                    let (ss, ct) = lib.encaps(&unhex(p[1])?);
                    Ok(format!("OK {} {}", hex(&ss), hex(&ct)))
                }
                "decaps" => Ok(format!("OK {}", hex(&lib.decaps(&unhex(p[1])?, &unhex(p[2])?)))),
                "sign" => Ok(format!("OK {}", hex(&lib.sign(&unhex(p[1])?, &unhex(p[2])?)))),
                "verify" => {
                    if lib.verify(&unhex(p[1])?, &unhex(p[2])?, &unhex(p[3])?) {
                        Ok("OK".to_string())
                    } else {
                        Ok("REJ signature mismatch".to_string())
                    }
                }
                "guard" => Ok("OK".to_string()),
                other => Err(format!("unknown verb {other}")),
            }
        })()
        .unwrap_or_else(|e| format!("ERR {e}"));
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
}
