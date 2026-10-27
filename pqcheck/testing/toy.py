"""In-process reference toys and planted mutants (not real cryptography).

Mutant keys are the canonical Appendix A names. Each mutant is a
behavioural defect shape that at least one relation must catch, and
selftest proves each is live (differs from clean) and caught.
"""
from __future__ import annotations

import hashlib

from pqcheck.target import Capability, Outcome, Status


def _h(label: bytes, *parts: bytes, out: int = 32) -> bytes:
    x = hashlib.shake_256()
    x.update(label)
    for p in parts:
        x.update(len(p).to_bytes(8, "big"))
        x.update(p)
    return x.digest(out)


def _ok(value=None):
    return Outcome(Status.OK, value=value)


def _rej(reason="rejected"):
    return Outcome(Status.REJECTED, detail=reason)


class ToyKem:
    """Hash-based toy KEM. dk = ek(32) || H(ek)(32) || z(32)."""

    name = "ToyKem"
    oracle = None
    size_semantics = "exact"

    def __init__(self, mutant: str | None = None):
        self.mutant = mutant
        self.caps = frozenset({
            Capability.KEM, Capability.PINNED_RANDOMNESS,
            Capability.EXPLICIT_SIG_LENGTH, Capability.GUARD_FILL,
        })
        self.ct_len = 32
        self.sizes = {"ek": 32, "dk": 96, "ct": 32, "ss": 32, "pk": 32, "sk": 96}
        self.measured_sizes = ["ek", "dk", "ct", "ss"]
        self.fixed_sig_len = None
        self._ctr = 0
        self._guard: bytes | None = None
        self._last: tuple[bytes, bytes] | None = None

    def alive(self):
        return True

    def guard(self, fill):
        self._guard = fill
        return _ok(b"")

    def keygen(self, seed=None):
        if seed is None:
            seed = b"toy-kem-default-seed"
        seed = bytes(seed)
        ek = _h(b"ek", seed)
        dk = ek + hashlib.sha3_256(ek).digest() + _h(b"z", seed)
        return _ok((ek, dk))

    def _canonical(self, ct: bytes) -> bytes:
        """Bytes the FO/decapsulation check actually binds (precision hooks)."""
        return ct

    def _wrap_ct(self, body: bytes) -> bytes:
        return body

    def _body_len(self) -> int:
        return self.ct_len

    def _ss(self, ek, ct):
        ct_eff = ct
        if self.mutant == "reject_ignores_ct":
            ct_eff = b""
        if self.mutant == "reject_binds_prefix_only":
            ct_eff = ct[:16]
        if self.mutant == "decaps_reads_past_ct" and self._guard is not None:
            ct_eff = ct + bytes(self._guard[:1])
        return _h(b"ss", ek, ct_eff)

    def encaps(self, ek, m=None):
        ek = bytes(ek)
        if len(ek) != 32:
            return _rej("bad ek length")
        if m is not None:
            body = bytes(m).ljust(self._body_len(), b"\x00")[:self._body_len()]
            ct = self._wrap_ct(body)
        else:
            self._ctr += 1
            body = _h(b"ct", ek, self._ctr.to_bytes(8, "big"), out=self._body_len())
            ct = self._wrap_ct(body)
        ss = self._ss(ek, self._canonical(ct))
        self._last = (ct, ss)
        return _ok((ss, ct))

    def decaps(self, dk, ct):
        dk, ct = bytes(dk), bytes(ct)
        if len(dk) != 96:
            return _rej("bad dk length")
        if self.mutant == "decaps_ignores_ct_length":
            ct = ct.ljust(self.ct_len, b"\x00")[:self.ct_len]
        elif len(ct) != self.ct_len:
            return _rej("bad ct length")
        ek, hh, z = dk[:32], dk[32:64], dk[64:96]
        canon = self._canonical(ct)
        if self.mutant == "reject_uninit_on_degenerate" and ct in (b"\x00" * len(ct), b"\xff" * len(ct)):
            return _ok(_h(b"degenerate"))
        if self.mutant == "no_reencryption_check" and self._last is not None:
            last_ct, last_ss = self._last
            if len(ct) == len(last_ct) and sum(bin(a ^ b).count("1") for a, b in zip(ct, last_ct)) <= 2:
                return _ok(last_ss)
        if self.mutant == "reject_ignores_z" and not (self._last is not None and ct == self._last[0]):
            return _ok(_h(b"rej-ct-only", canon))
        if hh != hashlib.sha3_256(ek).digest():
            if self.mutant == "reject_ignores_ct":
                ss = _h(b"rej", z)
            elif self.mutant == "reject_binds_prefix_only":
                ss = _h(b"rej", z, canon[:16])
            elif self.mutant == "reject_ignores_z":
                ss = _h(b"rej", canon)
            else:
                ss = _h(b"rej", z, canon)
        else:
            ss = self._ss(ek, canon)
        if self.mutant == "decaps_returns_wrong_secret":
            ss = _h(b"wrong", ct)
        if self.mutant == "reject_nondeterministic" and self._last is not None and ct != self._last[0]:
            self._ctr += 1
            ss = _h(b"ss-nondet", ss, self._ctr.to_bytes(8, "big"))
        if self.mutant == "decaps_reads_past_ct_dirty" and self._guard and any(self._guard):
            ss = _h(b"ss-past-ct", ss, bytes(self._guard))
        return _ok(ss)


class ToySig:
    """Hash-based toy signature. sig is 64 bytes, detached."""

    name = "ToySig"
    oracle = None
    size_semantics = "exact"

    def __init__(self, mutant: str | None = None):
        self.mutant = mutant
        self.caps = frozenset({
            Capability.SIG, Capability.PINNED_RANDOMNESS, Capability.DETACHED_SIG,
            Capability.CTX_STRING, Capability.EXPLICIT_SIG_LENGTH,
            Capability.DECLARED_LENGTH, Capability.GUARD_FILL,
        })
        self.sizes = {"pk": 32, "sk": 32, "sig": 64}
        self.measured_sizes = ["pk", "sk", "sig"]
        self.fixed_sig_len = True
        self.sig_len_basis = "toy fixed 64-byte signature"
        self._guard: bytes | None = None

    def alive(self):
        return True

    def guard(self, fill):
        self._guard = fill
        return _ok(b"")

    def keygen(self, seed=None):
        if seed is None:
            seed = b"toy-sig-default-seed"
        seed = bytes(seed)
        sk = _h(b"sk", seed)
        pk = _h(b"pk", sk)
        return _ok((pk, sk))

    def _expected(self, pk, msg, ctx, prehash):
        ctx_eff = b"" if self.mutant == "verify_ignores_ctx" else bytes(ctx)
        msg_eff = b"" if self.mutant == "msg_unbound" else bytes(msg)
        if self.mutant == "msg_prefix_only":
            msg_eff = msg_eff[:8]
        flag = b"" if self.mutant == "verify_ignores_prehash_domain" else (b"P" if prehash else b"H")
        if self.mutant == "no_ctx_length_prefix":
            x = hashlib.shake_256()
            x.update(b"sig")
            x.update(bytes(pk))
            x.update(ctx_eff + msg_eff)
            x.update(flag)
            return x.digest(64)
        return _h(b"sig", pk, msg_eff, ctx_eff, flag, out=64)

    def _declared_ok(self, msg, declared_len):
        if declared_len is None:
            return True
        if self.mutant == "msg_len_wraps_at_32bit":
            return declared_len % (1 << 32) == len(msg) % (1 << 32)
        return declared_len == len(msg)

    def sign(self, sk, msg, ctx=b"", prehash=False, declared_len=None):
        if self.mutant == "refuses_every_message":
            return _rej("every message refused")
        msg = bytes(msg)
        if not self._declared_ok(msg, declared_len):
            return _rej("declared length mismatch")
        pk = _h(b"pk", bytes(sk))
        sig = self._expected(pk, msg, ctx, prehash)
        if self.mutant == "sign_produces_unverifiable":
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        if self.mutant == "sig_overruns_declared_size":
            sig = sig + b"\x00"
        return _ok(sig)

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, declared_len=None):
        pk, msg, sig = bytes(pk), bytes(msg), bytes(sig)
        if not self._declared_ok(msg, declared_len):
            return _rej("declared length mismatch")
        if self.mutant == "verify_accepts_trailing":
            sig_eff = sig[:64].ljust(64, b"\x00")
        elif self.mutant == "sig_overruns_declared_size" and len(sig) == 65:
            sig_eff = sig[:64]
        else:
            if len(sig) != 64:
                return _rej("bad sig length")
            sig_eff = sig
        if self.mutant == "verify_reads_past_msg" and self._guard and self._guard[:1] == b"\xff":
            return _ok(None)
        if self.mutant == "verify_ignores_pk_arg":
            return _ok(None) if len(sig_eff) == 64 else _rej("bad sig length")
        if self.mutant == "verify_accepts_degenerate" and sig_eff == b"\x00" * 64:
            return _ok(None)
        msg_eff = msg
        if self.mutant == "verify_drops_byte_at_rate_multiple" and len(msg) >= 136 and len(msg) % 136 == 0:
            msg_eff = msg[:-1]
        expected = self._expected(pk, msg_eff, ctx, prehash)
        if self.mutant == "verify_ignores_slack":
            return _ok(None) if sig_eff[:63] == expected[:63] else _rej("mismatch")
        return _ok(None) if sig_eff == expected else _rej("mismatch")


def _factory(cls, mutant):
    return lambda: cls(mutant=mutant)


KEM_MUTANTS = {
    "reject_ignores_ct": _factory(ToyKem, "reject_ignores_ct"),
    "reject_binds_prefix_only": _factory(ToyKem, "reject_binds_prefix_only"),
    "reject_ignores_z": _factory(ToyKem, "reject_ignores_z"),
    "no_reencryption_check": _factory(ToyKem, "no_reencryption_check"),
    "reject_nondeterministic": _factory(ToyKem, "reject_nondeterministic"),
    "decaps_returns_wrong_secret": _factory(ToyKem, "decaps_returns_wrong_secret"),
    "reject_uninit_on_degenerate": _factory(ToyKem, "reject_uninit_on_degenerate"),
    "decaps_ignores_ct_length": _factory(ToyKem, "decaps_ignores_ct_length"),
    "decaps_reads_past_ct": _factory(ToyKem, "decaps_reads_past_ct"),
    "decaps_reads_past_ct_dirty": _factory(ToyKem, "decaps_reads_past_ct_dirty"),
}

SIG_MUTANTS = {
    "verify_ignores_ctx": _factory(ToySig, "verify_ignores_ctx"),
    "sign_produces_unverifiable": _factory(ToySig, "sign_produces_unverifiable"),
    "refuses_every_message": _factory(ToySig, "refuses_every_message"),
    "sig_overruns_declared_size": _factory(ToySig, "sig_overruns_declared_size"),
    "no_ctx_length_prefix": _factory(ToySig, "no_ctx_length_prefix"),
    "verify_accepts_degenerate": _factory(ToySig, "verify_accepts_degenerate"),
    "verify_ignores_prehash_domain": _factory(ToySig, "verify_ignores_prehash_domain"),
    "verify_ignores_pk_arg": _factory(ToySig, "verify_ignores_pk_arg"),
    "msg_unbound": _factory(ToySig, "msg_unbound"),
    "msg_prefix_only": _factory(ToySig, "msg_prefix_only"),
    "verify_accepts_trailing": _factory(ToySig, "verify_accepts_trailing"),
    "verify_drops_byte_at_rate_multiple": _factory(ToySig, "verify_drops_byte_at_rate_multiple"),
    "verify_ignores_slack": _factory(ToySig, "verify_ignores_slack"),
    "verify_reads_past_msg": _factory(ToySig, "verify_reads_past_msg"),
    "msg_len_wraps_at_32bit": _factory(ToySig, "msg_len_wraps_at_32bit"),
}

NEGATIVE_CONTROLS: frozenset[str] = frozenset()
