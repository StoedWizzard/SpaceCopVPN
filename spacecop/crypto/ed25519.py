"""Ed25519 digital signatures (RFC 8032), from scratch.

Ed25519 gives each node a stable cryptographic identity.  Nodes sign the
proof-of-relay receipts they collect; anyone can verify those signatures
against the node's public key, which is what makes the decentralised scoring
ledger tamper-evident without a trusted central authority.

Implemented over the twisted Edwards curve edwards25519 and validated against
the RFC 8032 test vectors in tests/.
"""

from __future__ import annotations

import hashlib
import os

_P = (1 << 255) - 19
# Group order of the base point.
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p

KEY_SIZE = 32
SIGNATURE_SIZE = 64


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little")


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx % _P, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


# Base point B
_BY = (4 * _inv(5)) % _P
_BX = _x_recover(_BY)
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)  # extended coordinates (X, Y, Z, T)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    x3 = (e * f) % _P
    y3 = (g * h) % _P
    t3 = (e * h) % _P
    z3 = (f * g) % _P
    return (x3, y3, z3, t3)


def _scalar_mult(p, e: int):
    result = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            result = _edwards_add(result, p)
        p = _edwards_add(p, p)
        e >>= 1
    return result


def _encode_point(p) -> bytes:
    x, y, z, _t = p
    zi = _inv(z)
    x = (x * zi) % _P
    y = (y * zi) % _P
    encoded = bytearray((y % _P).to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _decode_point(data: bytes):
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = (data[31] >> 7) & 1
    x = _x_recover(y)
    if (x & 1) != sign:
        x = _P - x
    p = (x % _P, y % _P, 1, (x * y) % _P)
    if not _on_curve(p):
        raise ValueError("decoded point is not on the curve")
    return p


def _on_curve(p) -> bool:
    x, y, z, _t = p
    x = (x * _inv(z)) % _P
    y = (y * _inv(z)) % _P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("private key must be 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def public_key_from_private(secret: bytes) -> bytes:
    a, _prefix = _secret_expand(secret)
    return _encode_point(_scalar_mult(_B, a))


def generate_keypair():
    """Return ``(private_key, public_key)`` for a new node identity."""
    secret = os.urandom(32)
    return secret, public_key_from_private(secret)


def sign(secret: bytes, message: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over ``message``."""
    a, prefix = _secret_expand(secret)
    public = _encode_point(_scalar_mult(_B, a))
    r = _sha512_int(prefix + message) % _L
    rr = _encode_point(_scalar_mult(_B, r))
    h = _sha512_int(rr + public + message) % _L
    s = (r + h * a) % _L
    return rr + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature; returns True only if it is valid."""
    if len(signature) != 64 or len(public) != 32:
        return False
    try:
        rr = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        a_point = _decode_point(public)
        r_point = _decode_point(rr)
        h = _sha512_int(rr + public + message) % _L
        # Check [s]B == R + [h]A
        left = _scalar_mult(_B, s)
        right = _edwards_add(r_point, _scalar_mult(a_point, h))
        return _encode_point(left) == _encode_point(right)
    except (ValueError, IndexError):
        return False
