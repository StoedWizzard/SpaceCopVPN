"""Cryptographic primitives for SpaceCopVPN, implemented from scratch.

Everything here uses only the Python standard library.  The algorithms are
standard, peer-reviewed constructions (ChaCha20, Poly1305, X25519, Ed25519,
HKDF) re-implemented from their RFCs and checked against published test
vectors.  We do not invent new cryptography; we re-implement documented
standards so the entire VPN can be read and audited in one place.
"""

from . import aead, chacha20, ed25519, hkdf, poly1305, x25519
from .aead import AuthenticationError

__all__ = [
    "aead",
    "chacha20",
    "ed25519",
    "hkdf",
    "poly1305",
    "x25519",
    "AuthenticationError",
]
