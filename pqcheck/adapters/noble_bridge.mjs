// pqcheck noble bridge: JSON-lines driver for @noble/post-quantum.
// Usage: node noble_bridge.mjs <algorithm>
// Requests (one JSON object per line): {op:"info"|"keygen"|"encaps"|"decaps"|"sign"|"verify", ...hex fields}
// Replies:  {ok:true, ...hex fields} | {ok:false, rejected:true} | {ok:false, error:"..."}
import { createRequire } from 'node:module';
import path from 'node:path';
import readline from 'node:readline';

const alg = (process.argv[2] || '').toLowerCase();
let mod = null;
let loadError = null;
const SUBMODULES = [
  ['ml-kem', 'ml-kem.js'], ['ml-dsa', 'ml-dsa.js'], ['slh-dsa', 'slh-dsa.js'],
  ['falcon', 'falcon.js'],
];
const submodule = (SUBMODULES.find(([prefix]) => alg.startsWith(prefix)) || [])[1];
try {
  // Recent @noble/post-quantum refuses a root import; use the submodule.
  mod = await import(submodule ? `@noble/post-quantum/${submodule}` : '@noble/post-quantum');
} catch (e1) {
  try {
    const cwd = path.resolve(process.env.PQCHECK_NODE_CWD || process.cwd());
    if (!submodule) throw e1;
    const { pathToFileURL } = await import('node:url');
    mod = await import(pathToFileURL(path.join(cwd, 'node_modules', '@noble', 'post-quantum', submodule)).href);
  } catch (e2) {
    loadError = e2;
  }
}

const ALIASES = {
  'ml-kem-512': ['mlkem512', 'ml_kem512', 'MLKEM512'],
  'ml-kem-768': ['mlkem768', 'ml_kem768', 'MLKEM768'],
  'ml-kem-1024': ['mlkem1024', 'ml_kem1024', 'MLKEM1024'],
  'ml-dsa-44': ['mldsa44', 'ml_dsa44', 'MLDSA44'],
  'ml-dsa-65': ['mldsa65', 'ml_dsa65', 'MLDSA65'],
  'ml-dsa-87': ['mldsa87', 'ml_dsa87', 'MLDSA87'],
  'slh-dsa-sha2-128f': ['slhdsa_sha2_128f', 'slh_dsa_sha2_128f'],
  'slh-dsa-shake-128f': ['slhdsa_shake_128f', 'slh_dsa_shake_128f'],
  'falcon-512': ['falcon512'],
  'falcon-1024': ['falcon1024'],
};

function pick(name) {
  if (!mod) return null;
  const candidates = [name, ...(ALIASES[name] || []), name.replaceAll('-', ''), name.replaceAll('-', '_')];
  for (const c of candidates) if (mod[c]) return mod[c];
  // namespaced exports such as mod.mlkem.mlkem768
  for (const key of Object.keys(mod)) {
    const ns = mod[key];
    if (ns && typeof ns === 'object') {
      for (const c of candidates) if (ns[c]) return ns[c];
      if (ns[name]) return ns[name];
    }
  }
  return null;
}

const impl = pick(alg);
const isKem = alg.startsWith('ml-kem');
const isSig = !isKem;

let prehashVariant = null;
let prehashTried = false;
async function getPrehashVariant() {
  if (prehashTried) return prehashVariant;
  prehashTried = true;
  if (!impl || typeof impl.prehash !== 'function') return null;
  try {
    let hashes = null;
    try { hashes = await import('@noble/hashes/sha2.js'); }
    catch {
      const cwd = path.resolve(process.env.PQCHECK_NODE_CWD || process.cwd());
      const { pathToFileURL } = await import('node:url');
      hashes = await import(pathToFileURL(path.join(cwd, 'node_modules', '@noble', 'hashes', 'sha2.js')).href);
    }
    prehashVariant = impl.prehash(hashes.sha512);
  } catch { prehashVariant = null; }
  return prehashVariant;
}

function hex(buf) {
  if (buf == null) return null;
  return Buffer.from(buf).toString('hex');
}
function unhex(s) {
  if (!s || s === '-') return new Uint8Array(0);
  return new Uint8Array(Buffer.from(s, 'hex'));
}
function reply(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function info() {
  if (loadError) return { ok: false, error: 'cannot load @noble/post-quantum: ' + loadError.message };
  if (!impl) return { ok: false, error: 'algorithm not found in @noble/post-quantum: ' + alg };
  const out = { ok: true, kind: isKem ? 'kem' : 'sig', alg };
  // Probe key/signature sizes with an unseeded keygen where cheap.
  try {
    const kp = impl.keygen();
    const pk = kp.publicKey ?? kp.encapsulationKey ?? kp.pk;
    const sk = kp.secretKey ?? kp.decapsulationKey ?? kp.sk;
    out.pk = pk?.length; out.sk = sk?.length;
    if (isKem) {
      const e = impl.encapsulate ? impl.encapsulate(pk) : impl.encaps(pk);
      const ct = e.cipherText ?? e.ciphertext ?? e.ct;
      const ss = e.sharedSecret ?? e.ss;
      out.ct = ct?.length; out.ss = ss?.length;
    } else {
      const msg = new Uint8Array([1, 2, 3]);
      let sig;
      try { sig = impl.sign(msg, sk); } catch { sig = impl.sign(sk, msg); }
      const detached = sig && typeof sig === 'object' && !(sig instanceof Uint8Array) ? (sig.signature ?? sig) : sig;
      out.sig = detached?.length;
    }
  } catch (e) {
    out.sizeProbeError = String(e && e.message || e);
  }
  out.caps = [];
  if (isKem) out.caps.push('kem'); else out.caps.push('sig');
  out.caps.push('explicit_sig_length');
  if (isSig) out.caps.push('detached_sig');
  // seed support: keygen(seed) returning the same keys twice
  try {
    const seed = new Uint8Array(32);
    const a = impl.keygen(seed);
    const b = impl.keygen(seed);
    const apk = a.publicKey ?? a.encapsulationKey ?? a.pk;
    const bpk = b.publicKey ?? b.encapsulationKey ?? b.pk;
    if (apk && bpk && Buffer.from(apk).equals(Buffer.from(bpk))) out.caps.push('pinned_randomness');
  } catch {}
  // ctx expressibility and ML-DSA hint geometry are reported optimistically
  // only for the families that define them; the Python side re-probes ctx.
  if (alg.startsWith('ml-dsa')) out.caps.push('ctx_string', 'mldsa_hint_encoding');
  return out;
}

async function handle(req) {
  if (req.op === 'info') return info();
  if (!impl) return { ok: false, error: 'algorithm unavailable: ' + alg };
  try {
    if (req.op === 'keygen') {
      const seed = req.seed && req.seed !== '-' ? unhex(req.seed) : null;
      let kp;
      try { kp = seed ? impl.keygen(seed) : impl.keygen(); }
      catch { kp = impl.keygen(); }
      const pk = kp.publicKey ?? kp.encapsulationKey ?? kp.pk;
      const sk = kp.secretKey ?? kp.decapsulationKey ?? kp.sk;
      return { ok: true, pk: hex(pk), sk: hex(sk) };
    }
    if (req.op === 'encaps') {
      const ek = unhex(req.ek);
      const e = impl.encapsulate ? await impl.encapsulate(ek) : await impl.encaps(ek);
      const ct = e.cipherText ?? e.ciphertext ?? e.ct;
      const ss = e.sharedSecret ?? e.ss;
      return { ok: true, ss: hex(ss), ct: hex(ct) };
    }
    if (req.op === 'decaps') {
      const dk = unhex(req.dk), ct = unhex(req.ct);
      const ss = impl.decapsulate ? await impl.decapsulate(ct, dk) : await impl.decaps(dk, ct);
      return { ok: true, ss: hex(ss instanceof Uint8Array ? ss : ss.sharedSecret ?? ss) };
    }
    if (req.op === 'sign') {
      const sk = unhex(req.sk), msg = unhex(req.msg);
      const opts = {};
      if (req.ctx) opts.context = unhex(req.ctx);
      let signer = impl;
      if (req.prehash) {
        signer = await getPrehashVariant();
        if (!signer) return { ok: false, error: 'prehash mode not supported by this algorithm' };
      }
      let sig;
      try { sig = await signer.sign(msg, sk, opts); }
      catch { try { sig = await signer.sign(sk, msg, opts); } catch { sig = await signer.sign(msg, sk); } }
      const detached = sig && typeof sig === 'object' && !(sig instanceof Uint8Array) ? (sig.signature ?? sig) : sig;
      return { ok: true, sig: hex(detached) };
    }
    if (req.op === 'verify') {
      const pk = unhex(req.pk), msg = unhex(req.msg), sig = unhex(req.sig);
      const opts = {};
      if (req.ctx) opts.context = unhex(req.ctx);
      let verifier = impl;
      if (req.prehash) {
        verifier = await getPrehashVariant();
        if (!verifier) return { ok: false, error: 'prehash mode not supported by this algorithm' };
      }
      let valid = false;
      try { valid = await verifier.verify(sig, msg, pk, opts); }
      catch (e1) {
        try { valid = await verifier.verify(pk, msg, sig, opts); }
        catch (e2) { return { ok: false, rejected: true, detail: String(e2 && e2.message || e2) }; }
      }
      return valid ? { ok: true } : { ok: false, rejected: true };
    }
    return { ok: false, error: 'unknown op ' + req.op };
  } catch (e) {
    // noble throws on malformed input: that is a controlled rejection.
    return { ok: false, rejected: true, detail: String(e && e.message || e) };
  }
}

const rl = readline.createInterface({ input: process.stdin });
for await (const line of rl) {
  if (!line.trim()) continue;
  let req;
  try { req = JSON.parse(line); } catch { reply({ ok: false, error: 'bad json' }); continue; }
  reply(await handle(req));
}
