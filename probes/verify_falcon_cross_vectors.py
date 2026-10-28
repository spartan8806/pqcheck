#!/usr/bin/env python3
"""Cross-implementation Falcon encoding vectors.

Three independent sides must agree on the compressed encoding:
  1. the shipped vectors (Noble falcon512 signature encodings,
     decoded once and stored in pqcheck/testing/falcon_vectors.json),
  2. pqcheck's independent spec codec (pqcheck.testing.falcon_codec),
  3. the pinned upstream falcon-rust codec, when its harness binary
     has been built (pqcheck/adapters/pqcheck_codec_harness) -- the
     harness compiles upstream's own compress/decompress, so this
     drives actual upstream code, not a reimplementation.
Side 3 exits 77 when the binary is absent (e.g. no Rust toolchain).
"""
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_lib import ROOT, check, passed  # noqa: E402

from pqcheck.testing.falcon_codec import compress, decompress  # noqa: E402

VECTORS = json.loads(
    (ROOT / "pqcheck" / "testing" / "falcon_vectors.json").read_text())


def check_python_side():
    for entry in VECTORS["noble_signatures"]:
        comp = bytes.fromhex(entry["compressed_hex"])
        coeffs = decompress(comp, 512)
        check(coeffs == tuple(entry["coeffs"]),
              "python codec disagrees with stored Noble coefficients")
        check(compress(coeffs, len(comp)) == comp,
              "python re-encode differs from Noble's encoding bytes")
    for vec in VECTORS["hand_vectors"]:
        got = compress(vec["coeffs"], vec["byte_length"])
        check(got is not None and got.hex() == vec["hex"],
              f"hand vector mismatch for {vec['coeffs']}")
        check(decompress(got, len(vec["coeffs"])) == tuple(vec["coeffs"]),
              f"hand vector round-trip failed for {vec['coeffs']}")
    for vec in VECTORS["negative_vectors"]:
        check(decompress(bytes.fromhex(vec["hex"]), vec["n"]) is None,
              f"negative vector accepted: {vec['why']}")
    print("python spec codec agrees with Noble vectors, hand vectors, "
          "and rejects the negative vectors")


check_python_side()

BINARY = ROOT / "pqcheck" / "adapters" / "pqcheck_codec_harness"
if not BINARY.exists():
    print("SKIP: upstream falcon-rust harness binary is not present "
          "on disk (pqcheck/adapters/pqcheck_codec_harness); build it "
          "with cargo in pqcheck/adapters/rust to enable side 3")
    raise SystemExit(77)

try:
    proc = subprocess.Popen([str(BINARY)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
except OSError as exc:  # e.g. an ELF built under WSL, seen from Windows
    print(f"SKIP: upstream harness binary is not executable on this platform ({exc})")
    raise SystemExit(77)


def call(line):
    proc.stdin.write(line + "\n")
    proc.stdin.flush()
    return proc.stdout.readline().strip()


try:
    check(call("info").startswith("OK kind=codec ncoef=512 sig=625"),
          "upstream harness info line wrong")
    for entry in VECTORS["noble_signatures"]:
        coeffs = entry["coeffs"]
        reply = call("encode " + " ".join(str(c) for c in coeffs))
        check(reply.startswith("OK "), f"upstream encode refused: {reply[:80]}")
        stream = bytes.fromhex(reply[3:])
        noble_bytes = bytes.fromhex(entry["compressed_hex"])
        check(stream[:len(noble_bytes)] == noble_bytes
              and not any(stream[len(noble_bytes):]),
              "upstream compress output differs from Noble encoding")
        reply = call("decode " + entry["compressed_hex"])
        check(reply.startswith("OK "), f"upstream decode refused: {reply[:80]}")
        block = bytes.fromhex(reply[3:])
        got = struct.unpack("<512h", block[:1024])
        check(list(got) == coeffs,
              "upstream decompress coefficients differ from Noble vector")
    print("pinned upstream falcon-rust codec agrees with Noble vectors")
finally:
    proc.stdin.close()
    proc.wait(timeout=10)
passed("falcon cross-implementation vectors")
