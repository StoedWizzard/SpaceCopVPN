"""Authenticated, forward-secret handshake (a custom Noise-like pattern).

Design goals:

* **Forward secrecy** — each session uses fresh ephemeral X25519 keys, so
  compromising a node's long-term key later does not decrypt past traffic.
* **Node authentication** — the client already knows the node's static X25519
  key (published and signed by the node's Ed25519 identity), and the static
  Diffie-Hellman step proves the node holds the matching private key.
* **Identity binding** — the node signs the handshake transcript with its
  Ed25519 identity key, tying the key exchange to the identity used for the
  scoring ledger.
* **Client anonymity** — the client presents no long-term identity, which is
  the right default for a privacy tool.

Message flow::

    client                                   node
      | --- INIT: sid, e_c_pub, timestamp --> |
      | <-- RESP: sid, e_n_pub, sealed{...} -- |
      (both derive c->n, n->c, and confirm keys)

The transcript hashed by both sides is::

    SHA256( MAGIC || VERSION || sid || e_c_pub || e_n_pub || node_static_pub )
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass

from ..crypto import aead, ed25519, hkdf, x25519
from . import constants as c
from . import framing
from .session import Session

SESSION_ID_SIZE = 8
_EPH_PUB = c.KEY_SIZE
_TS = 8
_CONFIRM_NONCE = b"\x00" * c.NONCE_SIZE


class HandshakeError(Exception):
    """Raised when a handshake message is malformed or fails verification."""


@dataclass
class NodeIdentity:
    """A node's long-term identity: an Ed25519 signing key and X25519 DH key."""

    ed_private: bytes
    ed_public: bytes
    x_private: bytes
    x_public: bytes

    @classmethod
    def generate(cls) -> "NodeIdentity":
        ed_priv, ed_pub = ed25519.generate_keypair()
        x_priv, x_pub = x25519.generate_keypair()
        return cls(ed_priv, ed_pub, x_priv, x_pub)

    def public_bundle(self) -> bytes:
        """Serialise the public identity (Ed25519 pub || X25519 pub)."""
        return self.ed_public + self.x_public

    @staticmethod
    def parse_bundle(data: bytes):
        if len(data) != c.ED25519_PUB_SIZE + c.KEY_SIZE:
            raise HandshakeError("bad identity bundle length")
        return data[:c.ED25519_PUB_SIZE], data[c.ED25519_PUB_SIZE:]


def _transcript_hash(sid: bytes, e_c_pub: bytes, e_n_pub: bytes, node_static_pub: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(c.MAGIC)
    h.update(bytes([c.VERSION]))
    h.update(sid)
    h.update(e_c_pub)
    h.update(e_n_pub)
    h.update(node_static_pub)
    return h.digest()


def _derive_keys(ss_static: bytes, ss_eph: bytes, transcript: bytes):
    """Return (k_client_to_node, k_node_to_client, k_confirm)."""
    prk = hkdf.extract(transcript, ss_static + ss_eph)
    okm = hkdf.expand(prk, c.HKDF_INFO_SESSION, 3 * c.SESSION_KEY_SIZE)
    return (
        okm[0:32],
        okm[32:64],
        okm[64:96],
    )


# ---------------------------------------------------------------------------
# Client side
# ---------------------------------------------------------------------------
class ClientHandshake:
    """Drives the client half of the handshake."""

    def __init__(self, node_static_pub: bytes, expected_node_ed_pub: bytes = b""):
        if len(node_static_pub) != c.KEY_SIZE:
            raise HandshakeError("node static public key must be 32 bytes")
        self.node_static_pub = node_static_pub
        self.expected_node_ed_pub = expected_node_ed_pub
        self._eph_priv, self._eph_pub = x25519.generate_keypair()
        self.session_id = os.urandom(SESSION_ID_SIZE)

    def build_init(self) -> bytes:
        """Return a full INIT frame ready to put on the wire."""
        body = self.session_id + self._eph_pub + struct.pack("!Q", int(time.time()))
        return framing.encode_frame(c.MSG_HANDSHAKE_INIT, body)

    def consume_response(self, body: bytes) -> Session:
        """Process the node's RESP body and return the established Session."""
        min_len = SESSION_ID_SIZE + _EPH_PUB
        if len(body) < min_len:
            raise HandshakeError("RESP too short")
        sid = body[:SESSION_ID_SIZE]
        if sid != self.session_id:
            raise HandshakeError("session id mismatch")
        offset = SESSION_ID_SIZE
        e_n_pub = body[offset:offset + _EPH_PUB]
        offset += _EPH_PUB
        sealed = body[offset:]

        ss_static = x25519.scalar_mult(self._eph_priv, self.node_static_pub)
        ss_eph = x25519.scalar_mult(self._eph_priv, e_n_pub)
        transcript = _transcript_hash(sid, self._eph_pub, e_n_pub, self.node_static_pub)
        k_c2n, k_n2c, k_confirm = _derive_keys(ss_static, ss_eph, transcript)

        try:
            confirm = aead.decrypt(k_confirm, _CONFIRM_NONCE, sealed, transcript)
        except aead.AuthenticationError as exc:
            raise HandshakeError("could not authenticate node response") from exc

        if len(confirm) != c.ED25519_PUB_SIZE + c.ED25519_SIG_SIZE:
            raise HandshakeError("bad confirmation payload")
        node_ed_pub = confirm[:c.ED25519_PUB_SIZE]
        sig = confirm[c.ED25519_PUB_SIZE:]
        if not ed25519.verify(node_ed_pub, transcript, sig):
            raise HandshakeError("node identity signature invalid")
        if self.expected_node_ed_pub and node_ed_pub != self.expected_node_ed_pub:
            raise HandshakeError("node identity does not match expected key")

        return Session(send_key=k_c2n, recv_key=k_n2c,
                       session_id=sid, peer_identity=node_ed_pub)


# ---------------------------------------------------------------------------
# Node side
# ---------------------------------------------------------------------------
class NodeHandshake:
    """Drives the node half of the handshake."""

    def __init__(self, identity: NodeIdentity):
        self.identity = identity

    def handle_init(self, body: bytes):
        """Process an INIT body; return ``(resp_frame, Session)``."""
        if len(body) != SESSION_ID_SIZE + _EPH_PUB + _TS:
            raise HandshakeError("INIT wrong length")
        sid = body[:SESSION_ID_SIZE]
        offset = SESSION_ID_SIZE
        e_c_pub = body[offset:offset + _EPH_PUB]
        offset += _EPH_PUB
        (timestamp,) = struct.unpack("!Q", body[offset:offset + _TS])

        skew = abs(int(time.time()) - timestamp)
        if skew > c.MAX_CLOCK_SKEW_SECONDS:
            raise HandshakeError(f"handshake timestamp skew too large ({skew}s)")

        eph_priv, eph_pub = x25519.generate_keypair()
        ss_static = x25519.scalar_mult(self.identity.x_private, e_c_pub)
        ss_eph = x25519.scalar_mult(eph_priv, e_c_pub)
        transcript = _transcript_hash(sid, e_c_pub, eph_pub, self.identity.x_public)
        k_c2n, k_n2c, k_confirm = _derive_keys(ss_static, ss_eph, transcript)

        sig = ed25519.sign(self.identity.ed_private, transcript)
        confirm_plain = self.identity.ed_public + sig
        sealed = aead.encrypt(k_confirm, _CONFIRM_NONCE, confirm_plain, transcript)

        resp_body = sid + eph_pub + sealed
        resp_frame = framing.encode_frame(c.MSG_HANDSHAKE_RESP, resp_body)

        # Node sends with k_n2c and receives with k_c2n.
        session = Session(send_key=k_n2c, recv_key=k_c2n,
                          session_id=sid, peer_identity=b"")
        return resp_frame, session
