"""CTarget: driver for the pqcheck C line-protocol harness."""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile

from pqcheck.target import (
    DEADLINE_KILLED, Capability, HarnessProtocolError, Outcome, Status,
    classify_exit, post_mortem, readline_deadline,
)
from pqcheck.verdict import redact_target_output

STATEFUL_SIGS = ("LMS", "HSS", "XMSS", "XMSSMT")
_HEX_OK = re.compile(r"^[0-9a-fA-F]*$")


def _hex(data: bytes | None) -> str:
    if not data:
        return "-"
    return bytes(data).hex()


def parse_hex_reply(text: str) -> bytes | None:
    text = text.strip()
    if not _HEX_OK.match(text) or len(text) % 2:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


class ProcessTarget:
    """Shared subprocess plumbing: stderr to a temp file, deadline reads."""

    def __init__(self, command, timeout=10.0, cwd=None, env=None):
        self.command = [str(c) for c in command]
        self.timeout = timeout
        self._stderr = tempfile.TemporaryFile(mode="w+b")
        self.proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self._stderr, text=True, bufsize=1, cwd=cwd, env=env,
        )
        self.oracle = None
        self._guard: bytes | None = None

    def alive(self):
        return self.proc.poll() is None

    def stderr_text(self) -> str:
        try:
            self._stderr.flush()
            pos = self._stderr.tell()
            self._stderr.seek(0)
            data = self._stderr.read().decode("utf-8", errors="replace")
            self._stderr.seek(pos)
            return data[-4000:]
        except Exception:
            return ""

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.stdin.close()
                self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            self._stderr.close()
        except Exception:
            pass
        for stream in (getattr(self.proc, "stdout", None), getattr(self.proc, "stdin", None)):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass

    def _send_line(self, line: str) -> str | Outcome:
        if self.proc.poll() is not None:
            return post_mortem(self.proc, self.stderr_text())
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return post_mortem(self.proc, self.stderr_text())
        reply = readline_deadline(self.proc, self.timeout)
        if reply == "":
            if getattr(self.proc, "_pqcheck_deadline_killed", False):
                return Outcome(Status.TIMEOUT, detail=f"no reply within {self.timeout}s; {DEADLINE_KILLED}")
            if self.proc.poll() is not None:
                return post_mortem(self.proc, self.stderr_text())
            return Outcome(Status.CRASHED, detail="empty reply from harness")
        return reply.strip()


class CTarget(ProcessTarget):
    name = "CTarget"

    def __init__(self, harness, kind, algorithm, wsl=False, timeout=10.0):
        if any(tok in algorithm.upper() for tok in STATEFUL_SIGS):
            raise HarnessProtocolError(
                f"refusing stateful hash-based scheme {algorithm!r}: the stateless "
                "line protocol cannot persist advancing secret-key state"
            )
        self.kind = kind
        self.algorithm = algorithm
        self.randomness_basis = (
            "pqc_kem_keygen/pqc_sig_keygen take no seed in the C harness; "
            "pinned randomness is not declared"
        )
        cmd = [harness, kind, algorithm]
        if isinstance(harness, str) and harness.endswith(".py"):
            cmd = [sys.executable, harness, kind, algorithm]
        if wsl:
            cmd = ["wsl.exe", harness, kind, algorithm]
        if isinstance(harness, (list, tuple)):
            cmd = list(harness) + [kind, algorithm]
        super().__init__(cmd, timeout=timeout)
        info = self._call("info")
        if not info.ok or not isinstance(info.value, dict):
            self.close()
            raise HarnessProtocolError(f"harness info failed: {info.detail}")
        meta = info.value
        if meta.get("kind", "").lower() != kind.lower() or meta.get("alg", "").lower() != algorithm.lower():
            self.close()
            raise HarnessProtocolError(f"harness info mismatch: {meta.get('kind')}/{meta.get('alg')} vs {kind}/{algorithm}")
        self.meta = meta
        pk, sk = int(meta["pk"]), int(meta["sk"])
        if kind == "kem":
            ct, ss = int(meta["ct"]), int(meta["ss"])
            self.sizes = {"pk": pk, "sk": sk, "ek": pk, "dk": sk, "ct": ct, "ss": ss}
            self.measured_sizes = ["ek", "dk", "ct", "ss"]
            # EXPLICIT_SIG_LENGTH is declared only when the harness's
            # info line asserts the underlying library API receives an
            # explicit ciphertext length (ctlen=explicit). Pointer-only
            # C KEM APIs (PQClean/OQS crypto_kem_dec style) take no
            # length argument, so off-length ciphertext probes cannot
            # be observed by the library and the length-exact relation
            # must decline (NOT_ANSWERABLE), never accuse it.
            caps = {Capability.KEM, Capability.GUARD_FILL}
            if meta.get("ctlen") == "explicit":
                caps.add(Capability.EXPLICIT_SIG_LENGTH)
            self.caps = frozenset(caps)
            self.fixed_sig_len = None
            self.sig_len_basis = ""
        else:
            sig = int(meta["sig"])
            self.sizes = {"pk": pk, "sk": sk, "sig": sig}
            self.measured_sizes = ["pk", "sk", "sig"]
            self.caps = frozenset({Capability.SIG, Capability.GUARD_FILL, Capability.EXPLICIT_SIG_LENGTH, Capability.DETACHED_SIG})
            self.fixed_sig_len, self.sig_len_basis = self._infer_fixed_sig_len(sig)
        self.name = f"CTarget({algorithm})"
        self.size_semantics = "exact"
        # Build provenance reported by the harness itself (rev= token
        # in the info line), or None when the harness reports none.
        self.reported_revision = meta.get("rev")
        # The line protocol has no prehash verb: this adapter cannot
        # express a prehash mode, so mode-separation relations must
        # decline (NOT_ANSWERABLE) instead of testing direct signing
        # twice and accusing the library.
        self.supports_prehash = False

    def _infer_fixed_sig_len(self, declared):
        lengths = []
        kg = self.keygen()
        if not kg.ok:
            return None, "keygen failed during fixed-length inference"
        _pk, sk = kg.value
        for n in (0, 1, 31, 32, 100, 513):
            out = self.sign(sk, bytes(n))
            if not out.ok:
                return None, "signing failed during fixed-length inference"
            lengths.append(len(out.value))
        fixed = all(n == declared for n in lengths)
        return fixed, f"signatures over 6 message lengths were {lengths}; declared sig={declared}"

    def _call(self, line: str) -> Outcome:
        reply = self._send_line(line)
        if isinstance(reply, Outcome):
            return reply
        if reply.startswith("OK"):
            rest = reply[2:].strip()
            if "=" in rest and not re.fullmatch(r"[0-9a-fA-F ]+", rest):
                meta = dict(p.split("=", 1) for p in rest.split() if "=" in p)
                return Outcome(Status.OK, value=meta)  # type: ignore[arg-type]
            parts = rest.split() if rest else []
            values = []
            for p in parts:
                parsed = parse_hex_reply(p)
                if parsed is None:
                    return Outcome(Status.CRASHED, detail=f"unparseable hex in harness reply: {redact_target_output(reply)[:200]}")
                values.append(parsed)
            if not values:
                return Outcome(Status.OK, value=None)
            return Outcome(Status.OK, value=values[0] if len(values) == 1 else tuple(values))
        if reply.startswith("REJ"):
            return Outcome(Status.REJECTED, detail=reply[3:].strip())
        if reply.startswith("ERR"):
            raise HarnessProtocolError(reply[3:].strip() or "harness error")
        return Outcome(Status.CRASHED, detail=f"malformed harness reply: {redact_target_output(reply)[:200]} ({classify_exit(self.proc.poll(), self.stderr_text())})")

    # -- target API ------------------------------------------------------------
    def guard(self, fill):
        self._guard = fill
        out = self._call("guard " + ("-" if fill is None else bytes(fill).hex()))
        return out

    def keygen(self, seed=None):
        out = self._call("keygen " + _hex(seed))
        return out

    def encaps(self, ek, m=None):
        return self._call("encaps " + _hex(ek))

    def decaps(self, dk, ct):
        return self._call("decaps " + _hex(dk) + " " + _hex(ct))

    def sign(self, sk, msg, ctx=b"", prehash=False, **kw):
        if ctx:
            return Outcome(Status.REJECTED, detail="C harness protocol cannot express a context string")
        if prehash:
            return Outcome(Status.REJECTED, detail="C harness protocol cannot express a prehash mode")
        return self._call("sign " + _hex(sk) + " " + _hex(msg))

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, **kw):
        if ctx:
            return Outcome(Status.REJECTED, detail="C harness protocol cannot express a context string")
        if prehash:
            return Outcome(Status.REJECTED, detail="C harness protocol cannot express a prehash mode")
        return self._call("verify " + _hex(pk) + " " + _hex(msg) + " " + _hex(sig))
