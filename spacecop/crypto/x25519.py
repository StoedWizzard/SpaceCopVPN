"""X25519 Elliptic-Curve Diffie-Hellman (RFC 7748), from scratch.

X25519 is the ECDH function over Curve25519.  Two parties each generate a
private scalar and a public point; exchanging public points lets both derive
the same shared secret without an eavesdropper being able to compute it.  This
is how the VPN establishes session keys without ever transmitting them.

Implemented with the constant-loop Montgomery ladder from RFC 7748 and
validated against its test vectors in tests/.
"""

from __future__ import annotations

import os

_P = (1 << 255) - 19  # the Curve25519 field prime
_A24 = 121665  # (486662 - 2) / 4, the curve constant used by the ladder
_BITS = 255

# Standard base point: u-coordinate 9.
BASE_POINT = (9).to_bytes(32, "little")

KEY_SIZE = 32


def _decode_scalar(scalar: bytes) -> int:
    """Decode and clamp a 32-byte scalar per RFC 7748."""
    if len(scalar) != 32:
        raise ValueError("scalar must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _decode_u(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("u-coordinate must be 32 bytes")
    u = bytearray(u)
    u[31] &= 127  # mask off the unused top bit
    return int.from_bytes(u, "little") % _P


def _encode_u(u: int) -> bytes:
    return (u % _P).to_bytes(32, "little")


def _cswap(swap: int, a: int, b: int):
    """Conditionally swap ``a`` and ``b`` when ``swap`` is 1."""
    dummy = (-swap) & ((1 << 256) - 1)
    dummy &= (a ^ b)
    return a ^ dummy, b ^ dummy


def _x25519(scalar: int, u: int) -> int:
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for t in range(_BITS - 1, -1, -1):
        k_t = (scalar >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + (_A24 * e)) % _P)) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)

    # Return x2 * z2^(p-2) mod p  (division via Fermat's little theorem)
    return (x2 * pow(z2, _P - 2, _P)) % _P


def scalar_mult(scalar: bytes, u: bytes) -> bytes:
    """Compute the X25519 function: scalar * point(u)."""
    k = _decode_scalar(scalar)
    u_int = _decode_u(u)
    return _encode_u(_x25519(k, u_int))


def scalar_base_mult(scalar: bytes) -> bytes:
    """Compute the public key for a private scalar (scalar * base point)."""
    return scalar_mult(scalar, BASE_POINT)


def generate_private_key() -> bytes:
    """Generate a fresh 32-byte private scalar from the OS CSPRNG."""
    return os.urandom(32)


def generate_keypair():
    """Return ``(private_key, public_key)``."""
    private = generate_private_key()
    public = scalar_base_mult(private)
    return private, public
