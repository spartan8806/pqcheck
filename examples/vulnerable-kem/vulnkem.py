"""Intentionally defective sample KEM — DO NOT USE.

A small hashlib-based key-encapsulation toy that ships with a real,
planted defect for testing pqcheck against: decapsulation never
checks the ciphertext's authentication tag (the second half of the
ciphertext). Editing any tag byte produces a different ciphertext
that decapsulates to the honest shared secret — the classic
Fujisaki-Okamoto liveness failure pqcheck's relations look for.

This exists so you can watch pqcheck find something. It is not
cryptography to protect anything with.
"""
import hashlib
import os

EK_LEN = 32
DK_LEN = 64
CT_LEN = 48
SS_LEN = 32


def _h(label: bytes, data: bytes) -> bytes:
    return hashlib.sha256(label + data).digest()


def keygen(seed: bytes | None = None):
    ek = _h(b"ek", seed) if seed else os.urandom(EK_LEN)
    z = os.urandom(32)
    return ek, ek + z  # dk = ek || z


def encaps(ek: bytes):
    r = os.urandom(32)
    ss = _h(b"ss", ek + r)
    core = bytes(a ^ b for a, b in zip(r, _h(b"mask", ek)))
    tag = _h(b"tag", ek + r)[:16]
    return ss, core + tag


def decaps(dk: bytes, ct: bytes):
    ek = dk[:EK_LEN]
    r = bytes(a ^ b for a, b in zip(ct[:32], _h(b"mask", ek)))
    # DEFECT: ct[32:] (the tag) is never verified. Any edit to the
    # tag — or a fully forged tag — decapsulates to the honest
    # shared secret, because the FO re-encryption check is absent.
    return _h(b"ss", ek + r)
