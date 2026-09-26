"""Poly1305 one-time message authentication code (RFC 8439), from scratch.

Poly1305 evaluates a polynomial modulo the prime 2**130 - 5 and adds a secret
value ``s`` modulo 2**128 to produce a 16-byte tag.  It is used as the
authenticator half of the ChaCha20-Poly1305 AEAD.

Validated against the RFC 8439 test vectors in tests/.
"""

from __future__ import annotations

_P = (1 << 130) - 5  # the Poly1305 prime
_MASK128 = (1 << 128) - 1


def _clamp(r: int) -> int:
    """Clamp ``r`` as specified: certain bits are forced to zero."""
    return r & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    """Compute the 16-byte Poly1305 tag for ``message`` under 32-byte ``key``."""
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r = _clamp(int.from_bytes(key[:16], "little"))
    s = int.from_bytes(key[16:32], "little")

    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset:offset + 16]
        # Append a 1 bit beyond the highest byte of the block.
        n = int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))
        accumulator = (accumulator + n) % _P
        accumulator = (accumulator * r) % _P

    accumulator = (accumulator + s) & _MASK128
    return accumulator.to_bytes(16, "little")


def verify(message: bytes, key: bytes, tag: bytes) -> bool:
    """Constant-time comparison of the computed tag with ``tag``."""
    import hmac

    expected = poly1305_mac(message, key)
    return hmac.compare_digest(expected, tag)
