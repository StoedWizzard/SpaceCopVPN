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


# Automatic discovery: how often to pull peer lists from connected nodes, and
# how long to leave a node alone after a failed connection attempt.
DISCOVERY_INTERVAL = 60.0
DISCOVERY_RETRY_COOLDOWN = 300.0
DEFAULT_MAX_AUTO_NODES = 8


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
    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 0,
                 discovery_enabled: bool = True,
                 max_auto_nodes: int = DEFAULT_MAX_AUTO_NODES,
                 on_event=None):
        """
        ``discovery_enabled`` — after connecting to any node, ask it for the
        peers it knows and connect to them too (the client side of the
        gossip), so one connection URI is enough to reach the whole overlay.
        ``max_auto_nodes`` caps the total number of connections.
        ``on_event`` — optional callback receiving human-readable log lines.
        """
        self.discovery_enabled = discovery_enabled
        self.max_auto_nodes = max_auto_nodes
        self.on_event = on_event
        self._discovering: set = set()
        self._discovery_failed: Dict[bytes, float] = {}
        self._discovery_thread: Optional[threading.Thread] = None
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
        self._discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True,
                                                  name="spacecop-discovery")
        self._discovery_thread.start()

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
                              node_ed_public=session.peer_identity,
                              x_public=node_x_public)
        with self._lock:
            self._connections[session.session_id] = conn
            self._reassemblers[session.session_id] = Reassembler()
            self._selector.add(conn)
        if self.discovery_enabled:
            # Pull this node's peer list right away so the rest of the overlay
            # is reached within seconds of the first connection.
            from ..protocol.messages import PeerRequest
            try:
                self.transport.send(PeerRequest(max_peers=32).encode(), addr)
            except OSError:
                pass
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
        # Failover: if the chosen node cannot reach the destination (its network
        # blocks that site, its exit is disabled, or it does not answer), try
        # the other nodes before giving up.  A site that one node cannot serve
        # thereby migrates to a node that can — and stays pinned there.
        tried: set = set()
        errors = []
        attempts = 1 if via is not None else max(1, self._selector.node_count())
        for _ in range(attempts):
            conn = via or self._selector.choose(dest_host, exclude=tried)
            if conn is None:
                break
            tried.add(conn)
            stream, why = self._try_open_stream(conn, dest_host, dest_port, timeout)
            if stream is not None:
                return stream
            errors.append(f"{conn.node_id_hex()}: {why}")
        if not tried:
            raise RelayTimeout("no node connections available")
        raise RelayTimeout(f"stream open to {dest_host}:{dest_port} failed on "
                           f"{len(tried)} node(s): " + "; ".join(errors))

    def _try_open_stream(self, conn: NodeConnection, dest_host: str, dest_port: int,
                         timeout: float):
        """One attempt on one node; returns (stream, None) or (None, reason)."""
        stream_id = os.urandom(8)
        stream = ClientStream(self, conn, stream_id, dest_host, dest_port)
        pending = _PendingOpen()
        with self._lock:
            self._streams[stream_id] = stream
            self._pending_opens[stream_id] = pending

        open_frame = StreamOpen(stream_id, dest_host, dest_port).encode()
        started = time.monotonic()
        deadline = started + timeout
        answered = False
        while time.monotonic() < deadline:
            self._send_app_message(conn, open_frame)  # re-sent until acknowledged
            if pending.event.wait(min(1.0, max(0.05, deadline - time.monotonic()))):
                answered = True
                break
        open_latency = time.monotonic() - started
        with self._lock:
            self._pending_opens.pop(stream_id, None)
        if not answered or pending.status != 0:
            with self._lock:
                self._streams.pop(stream_id, None)
            self._selector.record_failure(conn, dest_host)
            why = ("no answer from node (an outdated node build ignores stream messages; "
                   "update the server: deploy/update_server.sh)"
                   if not answered else
                   "node could not connect to the destination: "
                   + pending.text.decode("utf-8", "replace"))
            return None, why
        # Time-to-OPENED is a real round trip through the node (plus its TCP
        # connect to the destination): a fair latency sample for node ranking.
        self._selector.record_success(conn, open_latency, 0)
        return stream, None

    def _close_client_stream(self, stream: ClientStream, notify_peer: bool) -> None:
        with self._lock:
            self._streams.pop(stream.stream_id, None)
        if notify_peer:
            stream.endpoint.close()
        else:
            stream.endpoint.on_close()
        carried = stream.endpoint.bytes_sent + stream.endpoint.bytes_received
        if carried > 0 and stream.conn.node_ed_public:
            # No timing here (a stream's lifetime is not a latency): latency=None.
            self._selector.record_success(stream.conn, None, carried)
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

    # -- automatic node discovery (client side of the gossip) ---------------
    def _handle_peer_list(self, body: bytes) -> None:
        try:
            peer_list = PeerList.decode(body)
        except framing.ProtocolError:
            return
        if not self.discovery_enabled:
            return
        with self._lock:
            known = {c.node_ed_public for c in self._connections.values()}
            fresh = []
            for entry in peer_list.peers:
                if (entry.ed_public in known or entry.ed_public in self._discovering
                        or entry.x_public == b"\x00" * 32):
                    continue
                cooldown_until = self._discovery_failed.get(entry.ed_public, 0.0)
                if time.monotonic() < cooldown_until:
                    continue
                if len(known) + len(self._discovering) >= self.max_auto_nodes:
                    break
                self._discovering.add(entry.ed_public)
                fresh.append(entry)
        for entry in fresh:
            threading.Thread(target=self._discover_connect, args=(entry,), daemon=True).start()

    def _discover_connect(self, entry) -> None:
        addr = (entry.host, entry.port)
        try:
            self._emit(f"discovered node {entry.ed_public.hex()[:16]} at {entry.host}:{entry.port}, connecting")
            self.connect(entry.x_public, addr, expected_node_ed=entry.ed_public, timeout=6.0)
            self._emit(f"connected to discovered node {entry.ed_public.hex()[:16]}")
        except Exception as exc:
            with self._lock:
                self._discovery_failed[entry.ed_public] = time.monotonic() + DISCOVERY_RETRY_COOLDOWN
            self._emit(f"could not connect to discovered node {entry.host}:{entry.port}: {exc}")
        finally:
            with self._lock:
                self._discovering.discard(entry.ed_public)

    def request_peers(self) -> None:
        """Ask every connected node for the peers it knows (gossip pull)."""
        from ..protocol.messages import PeerRequest

        frame = PeerRequest(max_peers=32).encode()
        for conn in self.connections():
            try:
                self.transport.send(frame, conn.addr)
            except OSError:
                pass

    def _discovery_loop(self) -> None:
        # First pull soon after start-up, then periodically to pick up new nodes.
        next_at = time.monotonic() + 1.0
        while self._running.is_set():
            time.sleep(0.5)
            if not self.discovery_enabled or time.monotonic() < next_at:
                continue
            next_at = time.monotonic() + DISCOVERY_INTERVAL
            self.request_peers()

    def _emit(self, text: str) -> None:
        if self.on_event is not None:
            try:
                self.on_event(text)
            except Exception:
                pass

    # -- introspection ------------------------------------------------------
    def connections(self) -> List[NodeConnection]:
        with self._lock:
            return list(self._connections.values())
