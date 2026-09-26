"""Encrypted session state: directional keys, nonces, and replay protection.

After the handshake both peers hold two 32-byte keys — one for each direction —
so the two traffic directions never share key material.  Each direction uses a
monotonically increasing 64-bit counter as its ChaCha20-Poly1305 nonce, which
guarantees no (key, nonce) pair is ever reused.  Incoming counters are checked
against a sliding window so replayed packets are dropped.
"""

from __future__ import annotations

import struct
import threading

from ..crypto import aead
from . import constants as c


class ReplayError(Exception):
    """Raised when a packet's counter has already been seen (a replay)."""


def _nonce_from_counter(counter: int) -> bytes:
    """Encode a 64-bit counter into a 12-byte nonce (4 zero bytes + counter)."""
    return b"\x00\x00\x00\x00" + struct.pack("!Q", counter)


class Session:
    """One end of an encrypted session with a peer.

    Parameters
    ----------
    send_key, recv_key:
        Directional 32-byte AEAD keys derived by the handshake.
    session_id:
        A short identifier echoed in the clear so the peer can locate the
        matching session without trial-decryption.
    """

    def __init__(self, send_key: bytes, recv_key: bytes, session_id: bytes,
                 peer_identity: bytes = b""):
        if len(send_key) != c.KEY_SIZE or len(recv_key) != c.KEY_SIZE:
            raise ValueError("session keys must be 32 bytes")
        self.send_key = send_key
        self.recv_key = recv_key
        self.session_id = session_id
        self.peer_identity = peer_identity  # peer's Ed25519 public key, if known

        self._send_counter = 0
        self._recv_high = 0            # highest counter accepted so far
        self._recv_window = 0          # bitmask of recently seen counters
        # seal() may be called from several threads (e.g. concurrent SOCKS
        # connections).  The counter must be reserved atomically, otherwise two
        # records could share a nonce, which would be catastrophic for AEAD.
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()

    # -- outbound -----------------------------------------------------------
    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt ``plaintext``; returns ``counter(8) || ciphertext || tag``."""
        with self._send_lock:
            counter = self._send_counter
            self._send_counter += 1
        nonce = _nonce_from_counter(counter)
        # Bind the counter into the associated data so it cannot be moved.
        full_aad = aad + struct.pack("!Q", counter)
        ct = aead.encrypt(self.send_key, nonce, plaintext, full_aad)
        return struct.pack("!Q", counter) + ct

    # -- inbound ------------------------------------------------------------
    def open(self, framed: bytes, aad: bytes = b"") -> bytes:
        """Decrypt ``counter || ciphertext || tag`` with replay checking."""
        if len(framed) < 8 + c.TAG_SIZE:
            raise aead.AuthenticationError("sealed record too short")
        (counter,) = struct.unpack("!Q", framed[:8])
        with self._recv_lock:
            self._check_replay(counter)
        nonce = _nonce_from_counter(counter)
        full_aad = aad + struct.pack("!Q", counter)
        plaintext = aead.decrypt(self.recv_key, nonce, framed[8:], full_aad)
        # Only mark the counter as seen after successful authentication.
        with self._recv_lock:
            self._check_replay(counter)  # re-check: another thread may have accepted it
            self._accept(counter)
        return plaintext

    # -- sliding-window replay protection -----------------------------------
    def _check_replay(self, counter: int) -> None:
        if counter > self._recv_high:
            return  # newer than anything seen -> always fine
        offset = self._recv_high - counter
        if offset >= c.REPLAY_WINDOW:
            raise ReplayError("counter too old (outside replay window)")
        if (self._recv_window >> offset) & 1:
            raise ReplayError("counter already seen (replay)")

    def _accept(self, counter: int) -> None:
        if counter > self._recv_high:
            shift = counter - self._recv_high
            self._recv_window = ((self._recv_window << shift) | 1) & ((1 << c.REPLAY_WINDOW) - 1)
            self._recv_high = counter
        else:
            offset = self._recv_high - counter
            self._recv_window |= (1 << offset)
