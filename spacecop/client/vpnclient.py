"""The VPN client: connects to several competing nodes and relays through them.

The client holds a pseudonymous Ed25519 identity used only to sign
proof-of-relay receipts.  It maintains encrypted sessions to multiple nodes at
once, and for each request it picks a node (see :mod:`.multipath`) — nodes
compete to serve traffic, and the client rewards the one that does the work
with a signed receipt.  Requests are fragmented into 20 KB pieces, shuffled,
and encrypted before they hit the wire; replies are reassembled locally.
"""

from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..crypto import ed25519
from ..fragmentation import Fragmenter, Reassembler
from ..protocol import ClientHandshake, HandshakeError, Session, constants as c, framing
from ..protocol.messages import (
    DataMessage,
    PeerList,
    Receipt,
    RelayRequest,
    RelayResponse,
)
from ..transport import Address, UDPTransport
from .multipath import NodeConnection, NodeSelector


class RelayTimeout(Exception):
    pass


@dataclass
class _PendingHandshake:
    handshake: ClientHandshake
    addr: Address
    event: threading.Event = field(default_factory=threading.Event)
    session: Optional[Session] = None
    error: str = ""  # reason reported by the node (MSG_ERROR) or verification failure


@dataclass
class _PendingPing:
    event: threading.Event = field(default_factory=threading.Event)
    rtt: float = 0.0


@dataclass
class _PendingRequest:
    event: threading.Event = field(default_factory=threading.Event)
    response: Optional[RelayResponse] = None


class VPNClient:
    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 0):
        self.ed_private, self.ed_public = ed25519.generate_keypair()
        self.transport = UDPTransport(bind_host, bind_port)
        self.transport.set_handler(self._on_datagram)
        self.fragmenter = Fragmenter()

        self._connections: Dict[bytes, NodeConnection] = {}  # session_id -> conn
        self._reassemblers: Dict[bytes, Reassembler] = {}
        self._pending_handshakes: Dict[bytes, _PendingHandshake] = {}
        self._pending_requests: Dict[bytes, _PendingRequest] = {}
        self._pending_pings: Dict[bytes, _PendingPing] = {}
        self._selector = NodeSelector()
        self._lock = threading.Lock()
        self._receipt_seq = 0

    def start(self) -> None:
        self.transport.start()

    def stop(self) -> None:
        self.transport.stop()

    # -- connection establishment ------------------------------------------
    def connect(self, node_x_public: bytes, addr: Address,
                expected_node_ed: bytes = b"", timeout: float = 5.0) -> NodeConnection:
        """Perform a handshake with a node and register the resulting session."""
        handshake = ClientHandshake(node_x_public, expected_node_ed_pub=expected_node_ed)
        pending = _PendingHandshake(handshake=handshake, addr=addr)
        with self._lock:
            self._pending_handshakes[handshake.session_id] = pending

        # Re-send the INIT every second until we get an answer: a single lost
        # UDP datagram must not turn into a "node unreachable" verdict.  The
        # INIT carries a timestamp, so each copy is rebuilt fresh.
        deadline = time.monotonic() + timeout
        answered = False
        while time.monotonic() < deadline:
            self.transport.send(handshake.build_init(), addr)
            if pending.event.wait(min(1.0, max(0.05, deadline - time.monotonic()))):
                answered = True
                break

        if not answered:
            with self._lock:
                self._pending_handshakes.pop(handshake.session_id, None)
            raise RelayTimeout(
                "handshake timed out: no reply from the node "
                "(node not running, UDP port blocked by a firewall/provider, or wrong host:port)")

        session = pending.session
        if session is None:
            raise HandshakeError(
                pending.error or "node response failed verification "
                                 "(wrong key, wrong identity, or tampering)")
        conn = NodeConnection(session=session, addr=addr,
                              node_ed_public=session.peer_identity)
        with self._lock:
            self._connections[session.session_id] = conn
            self._reassemblers[session.session_id] = Reassembler()
            self._selector.add(conn)
        return conn

    # -- relaying -----------------------------------------------------------
    def relay(self, dest_host: str, dest_port: int, blob: bytes,
              via: Optional[NodeConnection] = None, timeout: float = 10.0,
              issue_receipt: bool = True, retries: int = 2,
              retry_interval: float = 2.0) -> bytes:
        """Send ``blob`` to (dest_host, dest_port) through a node; return the reply.

        If ``via`` is None the selector picks a node — and keeps picking the
        *same* node for the same site, so a web site sees one stable IP for
        the whole session.  On success the client signs and sends a
        proof-of-relay receipt to that node.

        Lost datagrams are recovered by re-sending the identical sealed
        fragments (``retries`` times, every ``retry_interval`` seconds).  This
        is safe: the receiver's replay window rejects copies it already saw,
        the reassembler ignores duplicate fragments, and the node replays a
        cached response instead of contacting the destination twice.
        """
        conn = via or self._selector.choose(dest_host)
        if conn is None:
            raise RelayTimeout("no node connections available")

        request_id = os.urandom(8)
        pending = _PendingRequest()
        with self._lock:
            self._pending_requests[request_id] = pending

        req = RelayRequest(request_id, dest_host, dest_port, blob).encode()
        started = time.monotonic()
        datagrams = self._send_app_message(conn, req)

        deadline = started + timeout
        attempt = 0
        got = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wait_for = min(remaining, retry_interval) if attempt < retries else remaining
            if pending.event.wait(wait_for):
                got = True
                break
            if attempt >= retries:
                break
            attempt += 1
            self._resend(conn, datagrams)

        if not got:
            with self._lock:
                self._pending_requests.pop(request_id, None)
            self._selector.record_failure(conn, dest_host)
            raise RelayTimeout("relay request timed out")

        elapsed = time.monotonic() - started
        resp = pending.response
        with self._lock:
            self._pending_requests.pop(request_id, None)

        if resp.status != 0:
            # The node answered but could not reach the destination.  Do not
            # reward it for work it did not complete, and unpin the site so the
            # next attempt may try another node.
            self._selector.record_failure(conn, dest_host)
            raise RelayTimeout(f"relay failed with status {resp.status}: {resp.blob!r}")

        relayed = len(blob) + len(resp.blob)
        self._selector.record_success(conn, elapsed, relayed)
        if issue_receipt and conn.node_ed_public:
            self._send_receipt(conn, relayed)
        return resp.blob

    def _send_receipt(self, conn: NodeConnection, byte_count: int) -> None:
        with self._lock:
            self._receipt_seq += 1
            seq = self._receipt_seq
        receipt = Receipt(
            client_ed_public=self.ed_public,
            node_ed_public=conn.node_ed_public,
            seq=seq,
            byte_count=byte_count,
            timestamp=int(time.time()),
        ).sign(self.ed_private)
        try:
            self.transport.send(receipt.encode(), conn.addr)
        except OSError:
            pass

    def _send_app_message(self, conn: NodeConnection, inner_frame: bytes) -> List[bytes]:
        """Fragment, shuffle, seal and send; return the datagrams for retransmission."""
        datagrams = []
        for raw in self.fragmenter.fragment_encoded(inner_frame, shuffle=True):
            sealed = conn.session.seal(raw)
            datagram = DataMessage(conn.session.session_id, sealed).encode()
            datagrams.append(datagram)
            self.transport.send(datagram, conn.addr)
        return datagrams

    def _resend(self, conn: NodeConnection, datagrams: List[bytes]) -> None:
        """Re-send identical sealed fragments in a fresh random order."""
        order = list(datagrams)
        random.SystemRandom().shuffle(order)
        for datagram in order:
            try:
                self.transport.send(datagram, conn.addr)
            except OSError:
                break

    # -- receive path -------------------------------------------------------
    def _on_datagram(self, data: bytes, addr: Address) -> None:
        try:
            msg_type, body = framing.decode_frame(data)
        except framing.ProtocolError:
            return
        if msg_type == c.MSG_HANDSHAKE_RESP:
            self._handle_handshake_resp(body)
        elif msg_type == c.MSG_DATA:
            self._handle_data(body)
        elif msg_type == c.MSG_PEER_LIST:
            self._handle_peer_list(body)
        elif msg_type == c.MSG_ERROR:
            self._handle_error(body)
        elif msg_type == c.MSG_PONG:
            self._handle_pong(body)

    # -- diagnostics --------------------------------------------------------
    def ping(self, addr: Address, timeout: float = 3.0, attempts: int = 3) -> Optional[float]:
        """Reachability probe: return the round-trip time in seconds, or None.

        Uses the protocol PING, which a node answers without any cryptography
        or clock check — so "no PONG" means the node is down or the UDP port
        is not reachable, and "PONG but handshake fails" points at keys/clock.
        """
        token = os.urandom(8)
        pending = _PendingPing()
        with self._lock:
            self._pending_pings[token] = pending
        try:
            per_try = max(0.2, timeout / max(1, attempts))
            for _ in range(attempts):
                started = time.monotonic()
                self.transport.send(framing.encode_frame(c.MSG_PING, token), addr)
                if pending.event.wait(per_try):
                    return time.monotonic() - started
            return None
        finally:
            with self._lock:
                self._pending_pings.pop(token, None)

    def _handle_pong(self, body: bytes) -> None:
        with self._lock:
            pending = self._pending_pings.get(body[:8])
        if pending is not None:
            pending.event.set()

    def _handle_error(self, body: bytes) -> None:
        if len(body) < 8:
            return
        session_id, reason = body[:8], body[8:].decode("utf-8", "replace")
        with self._lock:
            pending = self._pending_handshakes.pop(session_id, None)
        if pending is not None:
            pending.error = f"node rejected the handshake: {reason}"
            pending.session = None
            pending.event.set()

    def _handle_handshake_resp(self, body: bytes) -> None:
        if len(body) < 8:
            return
        session_id = body[:8]
        with self._lock:
            pending = self._pending_handshakes.pop(session_id, None)
        if pending is None:
            return
        try:
            pending.session = pending.handshake.consume_response(body)
        except Exception:
            pending.session = None
        pending.event.set()

    def _handle_data(self, body: bytes) -> None:
        try:
            dm = DataMessage.decode(body)
        except framing.ProtocolError:
            return
        with self._lock:
            conn = self._connections.get(dm.session_id)
            reasm = self._reassemblers.get(dm.session_id)
        if conn is None or reasm is None:
            return
        try:
            fragment_bytes = conn.session.open(dm.sealed)
            completed = reasm.add_bytes(fragment_bytes)
        except Exception:
            return
        if completed is not None:
            self._handle_app_message(completed)

    def _handle_app_message(self, plaintext: bytes) -> None:
        try:
            msg_type, inner = framing.decode_frame(plaintext)
        except framing.ProtocolError:
            return
        if msg_type == c.MSG_RELAY_RESPONSE:
            try:
                resp = RelayResponse.decode(inner)
            except framing.ProtocolError:
                return
            with self._lock:
                pending = self._pending_requests.get(resp.request_id)
            if pending is not None:
                pending.response = resp
                pending.event.set()

    def _handle_peer_list(self, body: bytes) -> None:
        try:
            PeerList.decode(body)
        except framing.ProtocolError:
            return

    # -- introspection ------------------------------------------------------
    def connections(self) -> List[NodeConnection]:
        with self._lock:
            return list(self._connections.values())
