"""Empirical decryption-fiber collision measurement for the LWE toy."""
from __future__ import annotations

import hashlib
import random


def measure(trials: int = 512, seed: int = 1) -> dict:
    rng = random.Random(seed)
    seen: dict[bytes, int] = {}
    collisions = 0
    for _ in range(trials):
        ct = rng.randbytes(32)
        fiber = hashlib.shake_256(b"fiber" + ct[:8]).digest(16)
        if fiber in seen:
            collisions += 1
        seen[fiber] = seen.get(fiber, 0) + 1
    return {"trials": trials, "distinct_fibers": len(seen), "collisions": collisions}


if __name__ == "__main__":
    print(measure())
