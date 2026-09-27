"""ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8), from scratch.

Authenticated Encryption with Associated Data: encrypts a plaintext, and
produces a tag that authenticates both the ciphertext and an unencrypted
"associated data" header.  Decryption fails loudly if the tag does not match,
which is what protects the VPN against tampering and forgery.

Validated against the RFC 8439 test vectors in tests/.
"""

from __future__ import annotations

import struct

from . import chacha20, native, poly1305


class AuthenticationError(Exception):
    """Raised when an AEAD tag fails to verify (tampering or wrong key)."""


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Derive the one-time Poly1305 key from the ChaCha20 block at counter 0."""
    block = chacha20.chacha20_keystream(key, 0, nonce, 64)
    return block[:32]


def _pad16(data: bytes) -> bytes:
    """Zero-pad to the next 16-byte boundary (empty pad if already aligned)."""
    remainder = len(data) % 16
    if remainder == 0:
        return b""
    return b"\x00" * (16 - remainder)


def _build_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    mac_data = bytearray()
    mac_data.extend(aad)
    mac_data.extend(_pad16(aad))
    mac_data.extend(ciphertext)
    mac_data.extend(_pad16(ciphertext))
    mac_data.extend(struct.pack("<Q", len(aad)))
    mac_data.extend(struct.pack("<Q", len(ciphertext)))
    return bytes(mac_data)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD-encrypt ``plaintext``; returns ``ciphertext || tag`` (tag is 16 bytes).

    Uses the native library when one is loaded (see :mod:`.native`), else the
    pure-Python reference below; both produce identical output."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if native.available():
        return native.aead_encrypt(key, nonce, bytes(plaintext), bytes(aad))
    return _encrypt_pure(key, nonce, plaintext, aad)


def _encrypt_pure(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    otk = _poly1305_key_gen(key, nonce)
    # Data encryption starts at counter 1; counter 0 produced the Poly1305 key.
    ciphertext = chacha20.chacha20_xor(key, 1, nonce, plaintext)
    tag = poly1305.poly1305_mac(_build_mac_data(aad, ciphertext), otk)
    return ciphertext + tag


def decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    """AEAD-decrypt; verifies the tag first and raises on failure."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if len(ciphertext_and_tag) < 16:
        raise AuthenticationError("ciphertext too short to contain a tag")
    if native.available():
        out = native.aead_decrypt(key, nonce, bytes(ciphertext_and_tag), bytes(aad))
        if out is None:
            raise AuthenticationError("AEAD tag verification failed")
        return out
    return _decrypt_pure(key, nonce, ciphertext_and_tag, aad)


def _decrypt_pure(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    ciphertext = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]

    otk = _poly1305_key_gen(key, nonce)
    if not poly1305.verify(_build_mac_data(aad, ciphertext), otk, tag):
        raise AuthenticationError("AEAD tag verification failed")

    return chacha20.chacha20_xor(key, 1, nonce, ciphertext)


TAG_SIZE = 16


def backend() -> str:
    """'native (<path>)' or 'python' — shown in diagnostics and the GUI log."""
    return f"native ({native.path()})" if native.available() else "python"
