"""HKDF (RFC 5869) built on HMAC-SHA256, from scratch.

HKDF turns a raw Diffie-Hellman shared secret into any number of independent,
uniformly-random session keys.  The VPN uses it to split one X25519 shared
secret into separate send and receive keys so the two directions never reuse
key material.

Only ``hashlib``/``hmac`` from the standard library are used (SHA-256 and the
HMAC construction are primitives, not a VPN library).
"""

from __future__ import annotations

import hashlib
import hmac

_HASH_LEN = 32  # SHA-256 output length


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def extract(salt: bytes, input_key_material: bytes) -> bytes:
    """HKDF-Extract: compress the input keying material into a pseudo-random key."""
    if not salt:
        salt = b"\x00" * _HASH_LEN
    return _hmac(salt, input_key_material)


def expand(pseudo_random_key: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: stretch the PRK into ``length`` bytes of output."""
    if length > 255 * _HASH_LEN:
        raise ValueError("cannot expand to more than 255*HashLen bytes")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = _hmac(pseudo_random_key, previous + info + bytes([counter]))
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def derive(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Convenience: full extract-then-expand in one call."""
    prk = extract(salt, input_key_material)
    return expand(prk, info, length)
