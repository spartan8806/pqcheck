"""CodecTarget and HintTarget drivers for raw codec / hint harnesses."""
from __future__ import annotations

from pqcheck.adapters.cbridge import ProcessTarget, _hex, parse_hex_reply
from pqcheck.target import Capability, HarnessProtocolError, Outcome, Status


class _LineTarget(ProcessTarget):
    def _call(self, line: str) -> Outcome:
        reply = self._send_line(line)
        if isinstance(reply, Outcome):
            return reply
        if reply.startswith("OK"):
            rest = reply[2:].strip()
            if "=" in rest and " " in rest:
                return Outcome(Status.OK, value=dict(p.split("=", 1) for p in rest.split() if "=" in p))  # type: ignore[arg-type]
            if "=" in rest and re_match_kv(rest):
                return Outcome(Status.OK, value=dict(p.split("=", 1) for p in rest.split() if "=" in p))  # type: ignore[arg-type]
            if not rest:
                return Outcome(Status.OK, value=None)
            parsed = parse_hex_reply(rest)
            if parsed is None:
                return Outcome(Status.CRASHED, detail=f"unparseable hex in reply: {reply[:200]}")
            return Outcome(Status.OK, value=parsed)
        if reply.startswith("REJ"):
            return Outcome(Status.REJECTED, detail=reply[3:].strip())
        if reply.startswith("ERR"):
            raise HarnessProtocolError(reply[3:].strip() or "harness error")
        return Outcome(Status.CRASHED, detail=f"malformed reply: {reply[:200]}")


def re_match_kv(rest: str) -> bool:
    return all("=" in p for p in rest.split())


class CodecTarget(_LineTarget):
    name = "CodecTarget"

    def __init__(self, harness, oracle="external codec harness (comp_encode/comp_decode)", timeout=10.0):
        cmd = list(harness) if isinstance(harness, (list, tuple)) else [harness]
        super().__init__(cmd, timeout=timeout)
        self.oracle = oracle
        info = self._call("info")
        if not info.ok or not isinstance(info.value, dict):
            self.close()
            raise HarnessProtocolError(f"codec harness info failed: {info.detail}")
        self.meta = info.value
        self.ncoef = int(info.value.get("ncoef", 8))
        self.sizes = {"sig": int(info.value.get("sig", 2 * self.ncoef))}
        self.measured_sizes = ["sig"]
        self.fixed_sig_len = info.value.get("fixed", "1") == "1"
        self.sig_len_basis = "codec harness declared fixed block length" if self.fixed_sig_len else "variable"
        self.codec_kind = "fixed_int16"
        self.omega = 8
        self.krows = 4
        self.caps = frozenset({Capability.RAW_DECODE})
        self.size_semantics = "exact"
        self.name = f"CodecTarget({oracle})"

    def encode(self, coeffs):
        return self._call("encode " + " ".join(str(int(c)) for c in coeffs))

    def decode(self, data):
        return self._call("decode " + _hex(data))


class HintTarget(_LineTarget):
    name = "HintTarget"

    def __init__(self, harness, oracle="external hint harness (unpack_sig)", timeout=10.0):
        cmd = list(harness) if isinstance(harness, (list, tuple)) else [harness]
        super().__init__(cmd, timeout=timeout)
        self.oracle = oracle
        info = self._call("info")
        if not info.ok or not isinstance(info.value, dict):
            self.close()
            raise HarnessProtocolError(f"hint harness info failed: {info.detail}")
        self.meta = info.value
        self.omega = int(info.value.get("omega", 8))
        self.krows = int(info.value.get("k", 4))
        self.ncoef = 8
        self.sizes = {"sig": 16}
        self.measured_sizes = ["sig"]
        self.fixed_sig_len = True
        self.sig_len_basis = "hint harness codec block"
        self.codec_kind = "fixed_int16"
        self.caps = frozenset({Capability.RAW_DECODE})
        self.size_semantics = "exact"
        self.name = f"HintTarget({oracle})"

    def encode(self, coeffs):
        # Hint harnesses do not expose a coefficient codec; route through the
        # hint-shaped block so generic codec relations fail closed upstream.
        return Outcome(Status.REJECTED, detail="hint harness has no coefficient encode")

    def decode(self, data):
        return Outcome(Status.REJECTED, detail="hint harness has no coefficient decode")

    def encode_hints(self, rows):
        return self._call("encode_hints " + ";".join(",".join(str(int(x)) for x in row) for row in rows))

    def decode_hints(self, data):
        return self._call("decode_hints " + _hex(data))
