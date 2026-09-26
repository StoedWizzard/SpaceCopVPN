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
    StreamAck,
    StreamClose,
    StreamData,
    StreamOpen,
    StreamOpened,
)
from ..protocol.stream import StreamEndpoint, StreamError
from ..transport import Address, UDPTransport
from .multipath import NodeConnection, NodeSelector
import queue as _queue


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
    version: str = ""  # node software version from the PONG ("" = old node)


@dataclass
class _PendingRequest:
    event: threading.Event = field(default_factory=threading.Event)
    response: Optional[RelayResponse] = None


@dataclass
class _PendingOpen:
    event: threading.Event = field(default_factory=threading.Event)
    status: int = -1
    text: bytes = b""


class ClientStream:
    """A TCP connection to ``dest`` carried through a node, with a socket-like API.

    ``send(data)`` blocks while the send window is full; ``recv()`` blocks until
    bytes arrive and returns ``b""`` at EOF; ``close()`` tears the stream down
    and, if any bytes were carried, hands the node a signed receipt.
    """

    def __init__(self, client: "VPNClient", conn: NodeConnection, stream_id: bytes,
                 dest_host: str, dest_port: int):
        self._client = client
        self.conn = conn
        self.stream_id = stream_id
        self.dest = (dest_host, dest_port)
        self._inbox: "_queue.Queue" = _queue.Queue()
        self._closed = False
        self.error: str = ""
        self.endpoint = StreamEndpoint(
            stream_id,
            send_msg=lambda frame: client._send_app_message(conn, frame),
            on_deliver=self._inbox.put,
            on_eof=lambda: self._inbox.put(None),
            on_error=self._on_error,
        )

    def _on_error(self, why: str) -> None:
        self.error = why
        self._inbox.put(None)

    def send(self, data: bytes) -> None:
        self.endpoint.send(data)

    def send_eof(self) -> None:
        self.endpoint.send_fin()

    def recv(self, timeout: Optional[float] = None) -> bytes:
        """Next chunk of received bytes, or b"" at EOF / after close."""
        if self._closed and self._inbox.empty():
            return b""
        try:
            item = self._inbox.get(timeout=timeout)
        except _queue.Empty:
            raise TimeoutError("no data")
        if item is None:
            self._inbox.put(None)  # keep EOF sticky for subsequent recv() calls
            return b""
        return item

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._client._close_client_stream(self, notify_peer=True)

    @property
    def closed(self) -> bool:
        return self._closed or self.endpoint.closed


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
        self._streams: Dict[bytes, ClientStream] = {}
        self._pending_opens: Dict[bytes, _PendingOpen] = {}
        self._selector = NodeSelector()
        self._lock = threading.Lock()
        self._receipt_seq = 0
        self._running = threading.Event()
        self._ticker_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.transport.start()
        self._running.set()
        self._ticker_thread = threading.Thread(target=self._stream_ticker, daemon=True,
                                               name="spacecop-client-tick")
        self._ticker_thread.start()

    def stop(self) -> None:
        self._running.clear()
        with self._lock:
            streams = list(self._streams.values())
        for s in streams:
            s.close()
        if self._ticker_thread is not None:
            self._ticker_thread.join(timeout=1.0)
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

    # -- streaming (full TCP connections through a node) --------------------
    def open_stream(self, dest_host: str, dest_port: int,
                    via: Optional[NodeConnection] = None, timeout: float = 15.0) -> ClientStream:
        """Open a TCP connection to ``dest`` through a node and return a stream.

        The node is chosen with the same per-site pinning as :meth:`relay`,
        so every connection to a site leaves through the same exit IP.
        """
        conn = via or self._selector.choose(dest_host)
        if conn is None:
            raise RelayTimeout("no node connections available")
        stream_id = os.urandom(8)
        stream = ClientStream(self, conn, stream_id, dest_host, dest_port)
        pending = _PendingOpen()
        with self._lock:
            self._streams[stream_id] = stream
            self._pending_opens[stream_id] = pending

        open_frame = StreamOpen(stream_id, dest_host, dest_port).encode()
        deadline = time.monotonic() + timeout
        answered = False
        while time.monotonic() < deadline:
            self._send_app_message(conn, open_frame)  # re-sent until acknowledged
            if pending.event.wait(min(1.0, max(0.05, deadline - time.monotonic()))):
                answered = True
                break
        with self._lock:
            self._pending_opens.pop(stream_id, None)
        if not answered or pending.status != 0:
            with self._lock:
                self._streams.pop(stream_id, None)
            self._selector.record_failure(conn, dest_host)
            why = ("no answer from node (an outdated node build ignores stream messages; "
                   "update the server: deploy/update_server.sh)"
                   if not answered else pending.text.decode("utf-8", "replace"))
            raise RelayTimeout(f"stream open to {dest_host}:{dest_port} failed: {why}")
        self._selector.record_success(conn, 0.0, 0)
        return stream

    def _close_client_stream(self, stream: ClientStream, notify_peer: bool) -> None:
        with self._lock:
            self._streams.pop(stream.stream_id, None)
        if notify_peer:
            stream.endpoint.close()
        else:
            stream.endpoint.on_close()
        carried = stream.endpoint.bytes_sent + stream.endpoint.bytes_received
        if carried > 0 and stream.conn.node_ed_public:
            self._selector.record_success(stream.conn, 0.0, carried)
            self._send_receipt(stream.conn, carried)

    def _stream_ticker(self) -> None:
        while self._running.is_set():
            time.sleep(0.1)
            now = time.monotonic()
            with self._lock:
                streams = list(self._streams.values())
            for s in streams:
                try:
                    s.endpoint.tick(now)
                    if s.endpoint.closed and not s._closed:
                        s._closed = True
                        self._close_client_stream(s, notify_peer=False)
                except Exception:
                    pass

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
        rtt, _version = self.probe(addr, timeout=timeout, attempts=attempts)
        return rtt

    def probe(self, addr: Address, timeout: float = 3.0, attempts: int = 3):
        """Like :meth:`ping` but also return the node's software version.

        Returns ``(rtt_seconds_or_None, version_string)``.  An empty version
        with a successful PONG means the node runs an old build (before
        0.2.0) that does not support streams and must be updated.
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
                    return time.monotonic() - started, pending.version
            return None, ""
        finally:
            with self._lock:
                self._pending_pings.pop(token, None)

    def _handle_pong(self, body: bytes) -> None:
        with self._lock:
            pending = self._pending_pings.get(body[:8])
        if pending is not None:
            marker = b"|spacecop/"
            if marker in body:
                pending.version = body.split(marker, 1)[1][:32].decode("ascii", "replace")
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
        elif msg_type == c.MSG_STREAM_OPENED:
            try:
                msg = StreamOpened.decode(inner)
            except framing.ProtocolError:
                return
            with self._lock:
                pending = self._pending_opens.get(msg.stream_id)
            if pending is not None:
                pending.status, pending.text = msg.status, msg.text
                pending.event.set()
        elif msg_type in (c.MSG_STREAM_DATA, c.MSG_STREAM_ACK, c.MSG_STREAM_CLOSE):
            try:
                if msg_type == c.MSG_STREAM_DATA:
                    msg = StreamData.decode(inner)
                elif msg_type == c.MSG_STREAM_ACK:
                    msg = StreamAck.decode(inner)
                else:
                    msg = StreamClose.decode(inner)
            except framing.ProtocolError:
                return
            with self._lock:
                stream = self._streams.get(msg.stream_id)
            if stream is None:
                return
            if msg_type == c.MSG_STREAM_DATA:
                stream.endpoint.on_data(msg)
            elif msg_type == c.MSG_STREAM_ACK:
                stream.endpoint.on_ack(msg)
            else:
                stream._closed = True
                self._close_client_stream(stream, notify_peer=False)
                stream.endpoint.on_close(msg.reason)

    def _handle_peer_list(self, body: bytes) -> None:
        try:
            PeerList.decode(body)
        except framing.ProtocolError:
            return

    # -- introspection ------------------------------------------------------
    def connections(self) -> List[NodeConnection]:
        with self._lock:
            return list(self._connections.values())
