"""Typed message bodies for the control and data planes.

Each message has a ``dataclass`` plus ``encode()``/``decode()`` helpers that
serialise to and from the wire body (the part after the 4-byte header).  The
header itself is added/removed by :mod:`spacecop.protocol.framing`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Tuple

from ..crypto import ed25519
from . import constants as c
from . import framing
from .framing import ProtocolError


# ---------------------------------------------------------------------------
# Data plane
# ---------------------------------------------------------------------------
@dataclass
class DataMessage:
    """A sealed session record carrying one fragment.

    ``sealed`` is exactly what :meth:`Session.seal` produced (counter || ct ||
    tag); ``session_id`` lets the receiver pick the right session key without
    trial decryption.
    """

    session_id: bytes
    sealed: bytes

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.session_id)
        buf.extend(self.sealed)
        return framing.encode_frame(c.MSG_DATA, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "DataMessage":
        if len(body) < 8:
            raise ProtocolError("DATA missing session id")
        return DataMessage(session_id=body[:8], sealed=body[8:])


@dataclass
class AckMessage:
    """Acknowledge a set of fragment indices within a message group."""

    session_id: bytes
    group_id: int
    indices: List[int] = field(default_factory=list)

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.session_id)
        framing.write_u32(buf, self.group_id)
        framing.write_u16(buf, len(self.indices))
        for idx in self.indices:
            framing.write_u16(buf, idx)
        return framing.encode_frame(c.MSG_ACK, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "AckMessage":
        if len(body) < 8:
            raise ProtocolError("ACK too short")
        session_id = body[:8]
        offset = 8
        group_id, offset = framing.read_u32(body, offset)
        count, offset = framing.read_u16(body, offset)
        indices = []
        for _ in range(count):
            idx, offset = framing.read_u16(body, offset)
            indices.append(idx)
        return AckMessage(session_id, group_id, indices)


# ---------------------------------------------------------------------------
# Control plane: discovery / gossip
# ---------------------------------------------------------------------------
@dataclass
class NodeAnnounce:
    """A node advertising itself to the overlay, self-signed for authenticity."""

    ed_public: bytes
    x_public: bytes
    host: str
    port: int
    score: int
    timestamp: int
    signature: bytes = b""

    def _signed_content(self) -> bytes:
        buf = bytearray()
        buf.extend(self.ed_public)
        buf.extend(self.x_public)
        framing.write_bytes(buf, self.host.encode("utf-8"))
        framing.write_u16(buf, self.port)
        framing.write_u64(buf, self.score)
        framing.write_u64(buf, self.timestamp)
        return bytes(buf)

    def sign(self, ed_private: bytes) -> "NodeAnnounce":
        self.signature = ed25519.sign(ed_private, self._signed_content())
        return self

    def verify(self) -> bool:
        return ed25519.verify(self.ed_public, self._signed_content(), self.signature)

    def encode(self) -> bytes:
        buf = bytearray(self._signed_content())
        framing.write_bytes(buf, self.signature)
        return framing.encode_frame(c.MSG_NODE_ANNOUNCE, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "NodeAnnounce":
        if len(body) < c.ED25519_PUB_SIZE + c.KEY_SIZE:
            raise ProtocolError("ANNOUNCE too short")
        ed_public = body[:c.ED25519_PUB_SIZE]
        offset = c.ED25519_PUB_SIZE
        x_public = body[offset:offset + c.KEY_SIZE]
        offset += c.KEY_SIZE
        host_bytes, offset = framing.read_bytes(body, offset)
        port, offset = framing.read_u16(body, offset)
        score, offset = framing.read_u64(body, offset)
        timestamp, offset = framing.read_u64(body, offset)
        signature, offset = framing.read_bytes(body, offset)
        return NodeAnnounce(ed_public, x_public, host_bytes.decode("utf-8"),
                            port, score, timestamp, signature)


@dataclass
class PeerRequest:
    max_peers: int = 32

    def encode(self) -> bytes:
        buf = bytearray()
        framing.write_u16(buf, self.max_peers)
        return framing.encode_frame(c.MSG_PEER_REQUEST, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "PeerRequest":
        max_peers, _ = framing.read_u16(body, 0) if body else (32, 0)
        return PeerRequest(max_peers)


@dataclass
class PeerEntry:
    ed_public: bytes
    x_public: bytes
    host: str
    port: int


@dataclass
class PeerList:
    peers: List[PeerEntry] = field(default_factory=list)

    def encode(self) -> bytes:
        buf = bytearray()
        framing.write_u16(buf, len(self.peers))
        for p in self.peers:
            buf.extend(p.ed_public)
            buf.extend(p.x_public)
            framing.write_bytes(buf, p.host.encode("utf-8"))
            framing.write_u16(buf, p.port)
        return framing.encode_frame(c.MSG_PEER_LIST, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "PeerList":
        count, offset = framing.read_u16(body, 0)
        peers = []
        for _ in range(count):
            ed_public = body[offset:offset + c.ED25519_PUB_SIZE]
            offset += c.ED25519_PUB_SIZE
            x_public = body[offset:offset + c.KEY_SIZE]
            offset += c.KEY_SIZE
            host_bytes, offset = framing.read_bytes(body, offset)
            port, offset = framing.read_u16(body, offset)
            peers.append(PeerEntry(ed_public, x_public, host_bytes.decode("utf-8"), port))
        return PeerList(peers)


# ---------------------------------------------------------------------------
# Control plane: relaying + scoring
# ---------------------------------------------------------------------------
@dataclass
class RelayRequest:
    """Ask a node to forward an opaque, already-encrypted blob to a next hop.

    The relay never sees plaintext: ``blob`` is ciphertext addressed to the
    final destination.  ``request_id`` correlates the eventual reply.
    """

    request_id: bytes
    dest_host: str
    dest_port: int
    blob: bytes

    def encode(self) -> bytes:
        buf = bytearray()
        framing.write_bytes(buf, self.request_id)
        framing.write_bytes(buf, self.dest_host.encode("utf-8"))
        framing.write_u16(buf, self.dest_port)
        framing.write_bytes32(buf, self.blob)  # blob can be a whole payload
        return framing.encode_frame(c.MSG_RELAY_REQUEST, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "RelayRequest":
        request_id, offset = framing.read_bytes(body, 0)
        dest_host, offset = framing.read_bytes(body, offset)
        dest_port, offset = framing.read_u16(body, offset)
        blob, offset = framing.read_bytes32(body, offset)
        return RelayRequest(request_id, dest_host.decode("utf-8"), dest_port, blob)


@dataclass
class RelayResponse:
    """A node's reply to a :class:`RelayRequest`, carrying the destination's data."""

    request_id: bytes
    status: int          # 0 = ok, non-zero = relay error code
    blob: bytes

    def encode(self) -> bytes:
        buf = bytearray()
        framing.write_bytes(buf, self.request_id)
        framing.write_u8(buf, self.status)
        framing.write_bytes32(buf, self.blob)  # blob can be a whole payload
        return framing.encode_frame(c.MSG_RELAY_RESPONSE, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "RelayResponse":
        request_id, offset = framing.read_bytes(body, 0)
        status, offset = framing.read_u8(body, offset)
        blob, offset = framing.read_bytes32(body, offset)
        return RelayResponse(request_id, status, blob)


@dataclass
class Receipt:
    """A client-signed proof that ``node_ed_public`` relayed ``byte_count`` bytes.

    Nodes accumulate these; the client's Ed25519 signature makes them
    verifiable by anyone, and the ``(client_ed_public, seq)`` pair lets a ledger
    reject duplicates.  See docs/SCORING.md for the trust model.
    """

    client_ed_public: bytes
    node_ed_public: bytes
    seq: int
    byte_count: int
    timestamp: int
    signature: bytes = b""

    def _signed_content(self) -> bytes:
        buf = bytearray()
        buf.extend(self.client_ed_public)
        buf.extend(self.node_ed_public)
        framing.write_u64(buf, self.seq)
        framing.write_u64(buf, self.byte_count)
        framing.write_u64(buf, self.timestamp)
        return bytes(buf)

    def sign(self, client_ed_private: bytes) -> "Receipt":
        self.signature = ed25519.sign(client_ed_private, self._signed_content())
        return self

    def verify(self) -> bool:
        return ed25519.verify(self.client_ed_public, self._signed_content(), self.signature)

    def encode(self) -> bytes:
        buf = bytearray(self._signed_content())
        framing.write_bytes(buf, self.signature)
        return framing.encode_frame(c.MSG_RECEIPT, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "Receipt":
        client_ed = body[:c.ED25519_PUB_SIZE]
        offset = c.ED25519_PUB_SIZE
        node_ed = body[offset:offset + c.ED25519_PUB_SIZE]
        offset += c.ED25519_PUB_SIZE
        seq, offset = framing.read_u64(body, offset)
        byte_count, offset = framing.read_u64(body, offset)
        timestamp, offset = framing.read_u64(body, offset)
        signature, offset = framing.read_bytes(body, offset)
        return Receipt(client_ed, node_ed, seq, byte_count, timestamp, signature)


# ---------------------------------------------------------------------------
# Streaming relay
# ---------------------------------------------------------------------------
@dataclass
class StreamOpen:
    stream_id: bytes
    dest_host: str
    dest_port: int

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.stream_id)
        framing.write_bytes(buf, self.dest_host.encode("utf-8"))
        framing.write_u16(buf, self.dest_port)
        return framing.encode_frame(c.MSG_STREAM_OPEN, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "StreamOpen":
        stream_id = body[:8]
        host, offset = framing.read_bytes(body, 8)
        port, offset = framing.read_u16(body, offset)
        return StreamOpen(stream_id, host.decode("utf-8"), port)


@dataclass
class StreamOpened:
    stream_id: bytes
    status: int          # 0 = connected, non-zero = failed
    text: bytes = b""

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.stream_id)
        framing.write_u8(buf, self.status)
        framing.write_bytes(buf, self.text)
        return framing.encode_frame(c.MSG_STREAM_OPENED, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "StreamOpened":
        stream_id = body[:8]
        status, offset = framing.read_u8(body, 8)
        text, offset = framing.read_bytes(body, offset)
        return StreamOpened(stream_id, status, text)


@dataclass
class StreamData:
    stream_id: bytes
    seq: int
    fin: bool
    data: bytes

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.stream_id)
        framing.write_u32(buf, self.seq)
        framing.write_u8(buf, 1 if self.fin else 0)
        framing.write_bytes(buf, self.data)
        return framing.encode_frame(c.MSG_STREAM_DATA, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "StreamData":
        stream_id = body[:8]
        seq, offset = framing.read_u32(body, 8)
        fin, offset = framing.read_u8(body, offset)
        data, offset = framing.read_bytes(body, offset)
        return StreamData(stream_id, seq, bool(fin), data)


@dataclass
class StreamAck:
    stream_id: bytes
    ack: int                                   # next expected seq (cumulative)
    sacks: List[int] = field(default_factory=list)  # received out-of-order seqs

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.stream_id)
        framing.write_u32(buf, self.ack)
        framing.write_u16(buf, len(self.sacks))
        for s in self.sacks:
            framing.write_u32(buf, s)
        return framing.encode_frame(c.MSG_STREAM_ACK, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "StreamAck":
        stream_id = body[:8]
        ack, offset = framing.read_u32(body, 8)
        n, offset = framing.read_u16(body, offset)
        sacks = []
        for _ in range(n):
            s, offset = framing.read_u32(body, offset)
            sacks.append(s)
        return StreamAck(stream_id, ack, sacks)


@dataclass
class StreamClose:
    stream_id: bytes
    reason: int = 0      # 0 = normal, 1 = error/abort

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.stream_id)
        framing.write_u8(buf, self.reason)
        return framing.encode_frame(c.MSG_STREAM_CLOSE, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "StreamClose":
        reason, _ = framing.read_u8(body, 8)
        return StreamClose(body[:8], reason)


@dataclass
class ScoreReport:
    ed_public: bytes
    score: int
    receipts_count: int

    def encode(self) -> bytes:
        buf = bytearray()
        buf.extend(self.ed_public)
        framing.write_u64(buf, self.score)
        framing.write_u64(buf, self.receipts_count)
        return framing.encode_frame(c.MSG_SCORE_REPORT, bytes(buf))

    @staticmethod
    def decode(body: bytes) -> "ScoreReport":
        ed_public = body[:c.ED25519_PUB_SIZE]
        offset = c.ED25519_PUB_SIZE
        score, offset = framing.read_u64(body, offset)
        receipts_count, offset = framing.read_u64(body, offset)
        return ScoreReport(ed_public, score, receipts_count)
