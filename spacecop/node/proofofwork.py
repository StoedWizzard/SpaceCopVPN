"""Hashcash-style proof of work for node registration (anti-Sybil).

To *join* the overlay a node must "mine" a small proof: find a nonce so that
``SHA256(challenge || nonce)`` begins with a required number of zero bits.
This makes spinning up thousands of fake identities costly, which is the same
economic idea behind cryptocurrency mining — spend work to earn standing.  The
difficulty is a tunable number of leading zero bits.

This is intentionally lightweight; it is a spam/Sybil speed bump, not a
consensus mechanism.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        # Count leading zeros within this byte.
        for shift in range(7, -1, -1):
            if (byte >> shift) & 1:
                return bits
            bits += 1
        break
    return bits


def meets_difficulty(challenge: bytes, nonce: bytes, difficulty: int) -> bool:
    """True if ``SHA256(challenge || nonce)`` has >= ``difficulty`` leading zero bits."""
    digest = hashlib.sha256(challenge + nonce).digest()
    return _leading_zero_bits(digest) >= difficulty


@dataclass
class ProofOfWork:
    challenge: bytes
    nonce: bytes
    difficulty: int

    def verify(self) -> bool:
        return meets_difficulty(self.challenge, self.nonce, self.difficulty)


def mine(challenge: bytes, difficulty: int, max_iterations: int = 1 << 32) -> ProofOfWork:
    """Search for a nonce satisfying ``difficulty`` (blocking)."""
    counter = 0
    while counter < max_iterations:
        nonce = struct.pack("!Q", counter) + os.urandom(4)
        if meets_difficulty(challenge, nonce, difficulty):
            return ProofOfWork(challenge, nonce, difficulty)
        counter += 1
    raise RuntimeError("proof of work not found within iteration budget")
