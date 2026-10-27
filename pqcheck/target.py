"""Target seam: outcomes, capabilities, and process-death attribution."""
from __future__ import annotations

import queue
import re
import threading
from dataclasses import dataclass
from enum import Enum

from pqcheck.verdict import redact_target_output

__all__ = [
    "Status",
    "Outcome",
    "Capability",
    "HarnessProtocolError",
    "POST_MORTEM",
    "NOT_ATTRIBUTABLE",
    "DEADLINE_KILLED",
    "classify_exit",
    "post_mortem",
    "readline_deadline",
]


class Status(str, Enum):
    OK = "OK"
    REJECTED = "REJECTED"
    CRASHED = "CRASHED"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class Outcome:
    status: Status
    value: bytes | tuple[bytes, ...] | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is Status.OK

    @property
    def is_finding(self) -> bool:
        return self.status in (Status.CRASHED, Status.TIMEOUT)


class Capability(str, Enum):
    KEM = "kem"
    SIG = "sig"
    PINNED_RANDOMNESS = "pinned_randomness"
    DETACHED_SIG = "detached_sig"
    EXTERNAL_MU = "external_mu"
    CTX_STRING = "ctx_string"
    EXPLICIT_SIG_LENGTH = "explicit_sig_length"
    RAW_DECODE = "raw_decode"
    MLDSA_HINT_ENCODING = "mldsa_hint_encoding"
    DECLARED_LENGTH = "declared_length"
    GUARD_FILL = "guard_fill"


class HarnessProtocolError(RuntimeError):
    """The adapter/harness could not marshal or execute a request."""


POST_MORTEM = "[post-mortem]"
NOT_ATTRIBUTABLE = "NOT attributable to the target"
DEADLINE_KILLED = "killed by pqcheck's own deadline"

_EXTERNAL_SIGNALS = {1: "SIGHUP", 2: "SIGINT", 9: "SIGKILL", 13: "SIGPIPE", 15: "SIGTERM"}
_FAULT_SIGNALS = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV"}


def classify_exit(rc: int | None, stderr_text: str = "") -> str:
    """Describe a child exit without blaming the target for external kills."""
    if rc is None:
        return "process exit status unknown"
    extra = ""
    if stderr_text:
        extra = ": " + redact_target_output(stderr_text).strip()[:300]
    sig = -rc if isinstance(rc, int) and rc < 0 else None
    if sig in _EXTERNAL_SIGNALS:
        return f"process died from {_EXTERNAL_SIGNALS[sig]} (signal {sig}); {NOT_ATTRIBUTABLE}{extra}"
    if sig in _FAULT_SIGNALS:
        return f"process died from {_FAULT_SIGNALS[sig]} (signal {sig}){extra}"
    if rc == 1 and stderr_text and "wsl" in stderr_text.lower():
        return f"process exited 1 under WSL; {NOT_ATTRIBUTABLE}{extra}"
    if sig is not None:
        return f"process died from signal {sig}{extra}"
    if rc != 0:
        return f"process exited with status {rc}{extra}"
    return "process exited cleanly"


def post_mortem(proc, stderr_text: str = "") -> Outcome:
    """Outcome for a call attempted after the child already died."""
    rc = None
    try:
        rc = proc.poll()
    except Exception:
        pass
    detail = f"{POST_MORTEM} child already dead (exit {rc})"
    if getattr(proc, "_pqcheck_deadline_killed", False):
        detail += f"; {DEADLINE_KILLED}"
    elif rc is not None:
        detail += "; " + classify_exit(rc, stderr_text)
    elif stderr_text:
        detail += ": " + redact_target_output(stderr_text).strip()[:300]
    return Outcome(Status.CRASHED, detail=detail)


def readline_deadline(proc, timeout_s: float) -> str:
    """Read one stdout line; on timeout kill the child and mark why."""
    stream = getattr(proc, "stdout", None)
    if stream is None:
        raise HarnessProtocolError("child process has no stdout pipe")
    result: queue.Queue = queue.Queue(maxsize=1)

    def _read() -> None:
        try:
            result.put(stream.readline())
        except Exception as exc:  # pragma: no cover - defensive
            result.put(exc)

    thread = threading.Thread(target=_read, daemon=True)
    thread.start()
    try:
        item = result.get(timeout=max(timeout_s, 0.001))
    except queue.Empty:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc._pqcheck_deadline_killed = True
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        return ""
    if isinstance(item, Exception):
        raise HarnessProtocolError(str(item)) from item
    return item if isinstance(item, str) else ""
