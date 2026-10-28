//! pqcheck exec-protocol harness for the enc_rust ML-KEM-768
//! regression. This shim forwards REAL serialized keys and
//! ciphertexts into enc_rust's public API; it contains no
//! cryptography of its own and plants no defect. The defect (or its
//! fix) lives entirely in the pinned enc_rust revision the harness
//! is built against.
//!
//! Pinned revisions (see README.md in this directory):
//!   vulnerable parent: 121385c2c9bab5ab509104b3e7b13259fc8a4080
//!   fix commit:        572a37f395e3c3bcf60d89bea89885b4dc13c176
//! Upstream: https://github.com/supinie/enc_rust
//! Advisory: GHSA-3qxj-wq9g-37w6 (FO re-encryption check missing a
//! ciphertext comparison, so edited ciphertexts could decapsulate
//! to the honest secret).
//!
//! Protocol (one request per line; argv kind/algorithm appended by
//! pqcheck are accepted and ignored — info hardcodes ML-KEM-768):
//!   info                    -> OK kind=kem alg=ML-KEM-768 pk=1184 sk=2400 ct=1088 ss=32
//!   keygen <seed|->         -> OK <ek-hex> <dk-hex>
//!   encaps <ek-hex>         -> OK <ss-hex> <ct-hex>
//!   decaps <dk-hex> <ct>    -> OK <ss-hex>
//!   guard <hex|->           -> ERR (Rust shim cannot expose past-buffer guards)
//! Library refusals are REJ; harness misuse is ERR.
use enc_rust::kem::{generate_keypair_768, PrivateKey, PublicKey};
use std::io::{self, BufRead, Write};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" {
        return Ok(vec![]);
    }
    if s.len() % 2 != 0 {
        return Err("ERR odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "ERR hex".into()))
        .collect()
}

/// Build provenance: the exact enc_rust commit this binary was built
/// against, stamped at build time via ENC_RUST_REVISION (see README).
const REV: &str = match option_env!("ENC_RUST_REVISION") {
    Some(v) => v,
    None => "unknown",
};

fn call(p: &[&str]) -> Result<String, String> {
    match p.first().copied().unwrap_or("") {
        "info" => Ok(format!(
            "OK kind=kem alg=ML-KEM-768 pk=1184 sk=2400 ct=1088 ss=32 rev={REV}")),
        "keygen" => {
            let (pk, sk) = generate_keypair_768(None).map_err(|e| format!("REJ {e:?}"))?;
            let mut a = vec![0; 1184];
            let mut b = vec![0; 2400];
            pk.pack(&mut a).map_err(|e| format!("ERR {e:?}"))?;
            sk.pack(&mut b).map_err(|e| format!("ERR {e:?}"))?;
            Ok(format!("OK {} {}", hex(&a), hex(&b)))
        }
        "encaps" if p.len() == 2 => {
            let pk = PublicKey::unpack(&unhex(p[1])?).map_err(|e| format!("REJ {e:?}"))?;
            let (ct, ss) = pk.encapsulate(None, None).map_err(|e| format!("REJ {e:?}"))?;
            Ok(format!("OK {} {}", hex(&ss), hex(ct.as_bytes())))
        }
        "decaps" if p.len() == 3 => {
            let sk = PrivateKey::unpack(&unhex(p[1])?).map_err(|e| format!("REJ {e:?}"))?;
            let ss = sk.decapsulate(&unhex(p[2])?).map_err(|e| format!("REJ {e:?}"))?;
            Ok(format!("OK {}", hex(&ss)))
        }
        "guard" => Err("ERR Rust shim cannot expose past-buffer guards".into()),
        _ => Err("ERR arity or verb".into()),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.is_empty() {
            continue;
        }
        let reply = call(&p).unwrap_or_else(|e| e);
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
    }
}
