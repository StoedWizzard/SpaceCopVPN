"""ChaCha20 stream cipher, implemented from scratch per RFC 8439.

This is a clean-room implementation of the ChaCha20 cipher using only the
Python standard library.  It is written for clarity and correctness and is
validated against the official RFC 8439 test vectors (see tests/).

ChaCha20 is a well-studied, peer-reviewed stream cipher designed by Daniel J.
Bernstein.  We deliberately re-implement a *standard* algorithm rather than
invent a novel one: inventing new cryptography is unsafe, while a faithful
re-implementation of a documented standard can be checked against known
answers.

Security note: a from-scratch implementation like this should be audited and,
for production, ideally replaced by a constant-time native implementation.
It is provided so the whole VPN stack can be understood end to end.
"""

from __future__ import annotations

import struct
from typing import List

_MASK32 = 0xFFFFFFFF

# The ChaCha state is initialised with four constant words spelling
# "expand 32-byte k" in little-endian ASCII.
_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(value: int, count: int) -> int:
    value &= _MASK32
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """The ChaCha quarter-round operating in place on four state words."""
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)

    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)

    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)

    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate one 64-byte ChaCha20 keystream block."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    key_words = struct.unpack("<8L", key)
    nonce_words = struct.unpack("<3L", nonce)

    state = [
        _CONSTANTS[0], _CONSTANTS[1], _CONSTANTS[2], _CONSTANTS[3],
        key_words[0], key_words[1], key_words[2], key_words[3],
        key_words[4], key_words[5], key_words[6], key_words[7],
        counter & _MASK32, nonce_words[0], nonce_words[1], nonce_words[2],
    ]

    working = list(state)
    for _ in range(10):  # 20 rounds = 10 iterations of (column + diagonal)
        # Column rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    out_words = [(working[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16L", *out_words)


def chacha20_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    """Produce ``length`` bytes of ChaCha20 keystream."""
    blocks = bytearray()
    generated = 0
    while generated < length:
        block = _chacha20_block(key, counter, nonce)
        blocks.extend(block)
        generated += 64
        counter = (counter + 1) & _MASK32
    return bytes(blocks[:length])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt ``data`` (the operation is symmetric)."""
    keystream = chacha20_keystream(key, counter, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


# Backwards-friendly aliases
encrypt = chacha20_xor
decrypt = chacha20_xor
