"""NobleTarget: driver for the @noble/post-quantum JSON-lines bridge."""
from __future__ import annotations

import json
import os
from pathlib import Path

from pqcheck.adapters.cbridge import ProcessTarget, parse_hex_reply
from pqcheck.target import Capability, HarnessProtocolError, Outcome, Status

_CAP_MAP = {
    "kem": Capability.KEM, "sig": Capability.SIG,
    "pinned_randomness": Capability.PINNED_RANDOMNESS,
    "detached_sig": Capability.DETACHED_SIG,
    "ctx_string": Capability.CTX_STRING,
    "explicit_sig_length": Capability.EXPLICIT_SIG_LENGTH,
    "mldsa_hint_encoding": Capability.MLDSA_HINT_ENCODING,
}

MLKEM_PACKING = {
    "ml-kem-512": {"coeff_bits": 12, "q": 3329, "n": 256, "k": 2},
    "ml-kem-768": {"coeff_bits": 12, "q": 3329, "n": 256, "k": 3},
    "ml-kem-1024": {"coeff_bits": 12, "q": 3329, "n": 256, "k": 4},
}

MLDSA_GEOMETRY = {
    # FIPS 204: sig = ctilde || z || h, h = omega index bytes + k offsets
    "ml-dsa-44": {"ctilde": 32, "z": 2304, "omega": 80, "k": 4, "sig_len": 2420},
    "ml-dsa-65": {"ctilde": 48, "z": 3200, "omega": 55, "k": 6, "sig_len": 3309},
    "ml-dsa-87": {"ctilde": 64, "z": 4480, "omega": 75, "k": 8, "sig_len": 4627},
}


class NobleTarget(ProcessTarget):
    name = "NobleTarget"

    def __init__(self, node_cwd, algorithm, bridge=None, node="node", timeout=15.0):
        self.algorithm = algorithm.lower()
        self.node_cwd = str(Path(node_cwd).resolve())
        bridge_path = Path(bridge) if bridge else Path(__file__).with_name("noble_bridge.mjs")
        env = dict(os.environ)
        env["PQCHECK_NODE_CWD"] = self.node_cwd
        super().__init__([node, str(bridge_path), self.algorithm], timeout=timeout, cwd=self.node_cwd, env=env)
        self.oracle = "@noble/post-quantum (independent JS implementation)"
        info = self._request({"op": "info"})
        if not info.ok or not isinstance(info.value, dict):
            detail = info.detail if isinstance(info, Outcome) else "no info"
            self.close()
            raise HarnessProtocolError(f"noble bridge info failed: {detail}")
        meta = info.value
        self.meta = meta
        self.kind = meta.get("kind")
        caps = frozenset(_CAP_MAP[c] for c in meta.get("caps", []) if c in _CAP_MAP)
        self.caps = caps
        pk, sk = meta.get("pk"), meta.get("sk")
        if self.kind == "kem":
            self.sizes = {"pk": pk, "sk": sk, "ek": pk, "dk": sk, "ct": meta.get("ct"), "ss": meta.get("ss")}
            self.measured_sizes = [k for k in ("ek", "dk", "ct", "ss") if self.sizes.get(k)]
            self.fixed_sig_len = None
            self.sig_len_basis = ""
            if self.algorithm in MLKEM_PACKING:
                self.ek_packing = dict(MLKEM_PACKING[self.algorithm])
        else:
            self.sizes = {"pk": pk, "sk": sk, "sig": meta.get("sig")}
            self.measured_sizes = [k for k in ("pk", "sk", "sig") if self.sizes.get(k)]
            is_falcon_variable = self.algorithm.startswith("falcon") and not self.algorithm.endswith("padded")
            if is_falcon_variable:
                self.fixed_sig_len = False
                self.sig_len_basis = "Falcon signatures are variable length unless padded"
                self.measured_sizes = [k for k in self.measured_sizes if k != "sig"]
            else:
                self.fixed_sig_len = True if meta.get("sig") else None
                self.sig_len_basis = "noble bridge reported a fixed signature size" if meta.get("sig") else ""
            if self.algorithm in MLDSA_GEOMETRY:
                self.mldsa_hint = dict(MLDSA_GEOMETRY[self.algorithm])
                self.hint_layout = "fips204"
        self.supports_prehash = self.algorithm.startswith("ml-dsa")
        self.size_semantics = "exact"
        self.name = f"NobleTarget({self.algorithm})"
        self.randomness_basis = "bridge probed seeded keygen for determinism"

    def _request(self, req) -> Outcome:
        line = json.dumps(req)
        # The bridge must resolve @noble/post-quantum from node_cwd.
        self._ensure_cwd()
        reply = self._send_line(line)
        if isinstance(reply, Outcome):
            return reply
        try:
            data = json.loads(reply)
        except json.JSONDecodeError:
            return Outcome(Status.CRASHED, detail=f"malformed JSON from noble bridge: {reply[:200]}")
        if data.get("ok"):
            return Outcome(Status.OK, value=data)  # type: ignore[arg-type]
        if data.get("rejected"):
            return Outcome(Status.REJECTED, detail=str(data.get("detail", "rejected")))
        raise HarnessProtocolError(str(data.get("error", "noble bridge error")))

    def _ensure_cwd(self):
        # Node resolves modules relative to the bridge and PQCHECK_NODE_CWD;
        # the env var is set by the CLI/manifest layer before spawn. Here we
        # only record the intent for diagnostics.
        os.environ.setdefault("PQCHECK_NODE_CWD", self.node_cwd)

    @staticmethod
    def _bytes(data, key):
        value = data.get(key)
        if value is None:
            return None
        parsed = parse_hex_reply(value)
        return parsed

    def keygen(self, seed=None):
        out = self._request({"op": "keygen", "seed": seed.hex() if seed else "-"})
        if not out.ok:
            return out
        pk = self._bytes(out.value, "pk"); sk = self._bytes(out.value, "sk")
        if pk is None or sk is None:
            return Outcome(Status.CRASHED, detail="noble keygen reply missing keys")
        return Outcome(Status.OK, value=(pk, sk))

    def encaps(self, ek, m=None):
        out = self._request({"op": "encaps", "ek": bytes(ek).hex()})
        if not out.ok:
            return out
        ss = self._bytes(out.value, "ss"); ct = self._bytes(out.value, "ct")
        if ss is None or ct is None:
            return Outcome(Status.CRASHED, detail="noble encaps reply missing fields")
        return Outcome(Status.OK, value=(ss, ct))

    def decaps(self, dk, ct):
        out = self._request({"op": "decaps", "dk": bytes(dk).hex(), "ct": bytes(ct).hex()})
        if not out.ok:
            return out
        ss = self._bytes(out.value, "ss")
        return Outcome(Status.OK, value=ss) if ss is not None else Outcome(Status.CRASHED, detail="noble decaps reply missing ss")

    def sign(self, sk, msg, ctx=b"", prehash=False, **kw):
        req = {"op": "sign", "sk": bytes(sk).hex(), "msg": bytes(msg).hex()}
        if ctx:
            req["ctx"] = bytes(ctx).hex()
        if prehash:
            req["prehash"] = True
        # prehash mode switch: noble exposes it via sign options in recent versions
        out = self._request(req)
        if not out.ok:
            return out
        sig = self._bytes(out.value, "sig")
        return Outcome(Status.OK, value=sig) if sig is not None else Outcome(Status.CRASHED, detail="noble sign reply missing sig")

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, **kw):
        req = {"op": "verify", "pk": bytes(pk).hex(), "msg": bytes(msg).hex(), "sig": bytes(sig).hex()}
        if ctx:
            req["ctx"] = bytes(ctx).hex()
        if prehash:
            req["prehash"] = True
        return self._request(req)

    def guard(self, fill):
        self._guard = fill
        return Outcome(Status.OK, value=b"")
