#!/usr/bin/env python3
"""Report emission survives legacy cp437/cp1252 consoles."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_pq_here = Path(__file__).resolve()
_pq_root = (_pq_here.parents[3] if _pq_here.parents[2].name == "pqcheck" else _pq_here.parents[1])
sys.path.insert(0, str(_pq_root))
from pqcheck.assets.probes.probe_lib import check, passed  # noqa: E402

from pqcheck.verdict import Report  # noqa: E402


class LegacyStream:
    encoding = "cp1252"

    def __init__(self):
        self.buffer = _Buffer()
        self.text = ""

    def write(self, data):
        data.encode(self.encoding)  # raises like a real legacy console
        self.text += data

    def flush(self):
        pass


class _Buffer:
    def __init__(self):
        self.data = b""

    def write(self, payload):
        self.data += payload

    def flush(self):
        pass


stream = LegacyStream()
text = "NO WITNESS FOUND \u2014 ESTABLISHES NOTHING \u2713\n"
try:
    Report.emit(text, stream)
except UnicodeEncodeError:
    check(False, "emit raised UnicodeEncodeError on a cp1252 stream")
check(stream.buffer.data == text.encode("utf-8"), "emit did not fall back to UTF-8 bytes")
print("emit fell back to UTF-8 bytes on a cp1252 console without raising")
passed("report encoding")
