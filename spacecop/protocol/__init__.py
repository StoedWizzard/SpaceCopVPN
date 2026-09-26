"""The custom SpaceCopVPN wire protocol.

Layers:
* :mod:`constants` — magic bytes, versions, message-type codes, sizes.
* :mod:`framing` — the 4-byte header and primitive field codecs.
* :mod:`messages` — typed bodies for every message.
* :mod:`session` — directional AEAD keys, nonces, replay protection.
* :mod:`handshake` — the authenticated, forward-secret key exchange.
"""

from . import constants, framing, handshake, messages, session
from .framing import ProtocolError, decode_frame, encode_frame
from .handshake import ClientHandshake, HandshakeError, NodeHandshake, NodeIdentity
from .session import ReplayError, Session

__all__ = [
    "constants",
    "framing",
    "handshake",
    "messages",
    "session",
    "ProtocolError",
    "encode_frame",
    "decode_frame",
    "ClientHandshake",
    "NodeHandshake",
    "NodeIdentity",
    "HandshakeError",
    "Session",
    "ReplayError",
]
