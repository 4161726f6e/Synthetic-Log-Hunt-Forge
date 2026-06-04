from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


@dataclass(frozen=True)
class DeterministicRng:
    seed: int

    def derive(self, label: str) -> random.Random:
        """
        Return a seeded Random instance derived from this seed and a label.

        Using the full 32-byte SHA-256 digest (256 bits) rather than just
        the first 8 bytes (64 bits) gives better seed distribution across
        the Mersenne Twister's large state space, reducing the chance of
        two differently-labelled streams producing correlated sequences.
        """
        h = hashlib.sha256(f"{self.seed}:{label}".encode("utf-8")).digest()
        return random.Random(int.from_bytes(h, "big"))
