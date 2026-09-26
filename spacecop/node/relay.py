"""The relay node: a competing server in the decentralised VPN overlay.

A node does three jobs at once:

1. **Session endpoint** — it completes handshakes with clients and holds the
   per-session encrypted state.
2. **Relay/exit** — it reassembles a client's fragmented, encrypted request,
   forwards the opaque payload to the requested destination, and fragments the
   reply back.  Doing this work is what earns points.
3. **Overlay member** — it announces itself, answers peer requests, gossips the
   directory, and records signed proof-of-relay receipts in its ledger.

Everything is driven by one UDP socket and a couple of background threads.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from ..fragmentation import Fragmenter, Reassembler
from ..protocol import (
    NodeHandshake,
    NodeIdentity,
    Session,
    constants as c,
    framing,
)
from ..protocol.messages import (
    DataMessage,
    NodeAnnounce,
    PeerList,
    PeerRequest,
    Receipt,
    RelayRequest,
    RelayResponse,
    ScoreReport,
    StreamAck,
    StreamClose,
    StreamData,
    StreamOpen,
    StreamOpened,
)
from ..protocol.stream import StreamEndpoint
from ..transport import Address, UDPTransport
import queue as _queue
from .directory import PeerDirectory
from .scoring import Ledger

# Relay safety caps.
RELAY_CONNECT_TIMEOUT = 5.0
RELAY_READ_TIMEOUT = 5.0
RELAY_MAX_RESPONSE = 4 * 1024 * 1024  # cap a single relayed reply at 4 MB
# Sessions with no traffic for this long are dropped so memory stays bounded.
SESSION_IDLE_TIMEOUT = 15 * 60.0
# Relays run on a worker pool so one slow destination never blocks the UDP
# receive loop or other clients.  Web pages issue many requests at once.
RELAY_WORKERS = 64
# Completed responses are remembered briefly so a retransmitted request (the
# client re-sends fragments when it suspects loss) is answered from cache
# instead of contacting the destination a second time.
RESPONSE_CACHE_TTL = 60.0


@dataclass
class _SessionState:
    session: Session
    addr: Address
    reassembler: Reassembler = field(default_factory=Reassembler)
    last_active: float = field(default_factory=time.monotonic)
    streams: Dict[bytes, "_NodeStream"] = field(default_factory=dict)


@dataclass
class _NodeStream:
    """One relayed TCP connection: endpoint + socket + writer queue."""

    endpoint: StreamEndpoint
    sock: Optional[socket.socket] = None
    outbox: "_queue.Queue" = field(default_factory=_queue.Queue)
    opened: float = field(default_factory=time.monotonic)
    done: bool = False


STREAM_CONNECT_TIMEOUT = 10.0
STREAM_IDLE_TIMEOUT = 10 * 60.0


class RelayNode:
    def __init__(self, identity: Optional[NodeIdentity] = None,
                 bind_host: str = "0.0.0.0", bind_port: int = 0,
                 advertised_host: str = "127.0.0.1",
                 exit_enabled: bool = True):
        self.identity = identity or NodeIdentity.generate()
        self.transport = UDPTransport(bind_host, bind_port)
        self.transport.set_handler(self._on_datagram)
        self.advertised_host = advertised_host
        self.exit_enabled = exit_enabled

        self.directory = PeerDirectory()
        self.ledger = Ledger()
        self.fragmenter = Fragmenter()
        self._handshaker = NodeHandshake(self.identity)

        self._sessions: Dict[bytes, _SessionState] = {}
        self._lock = threading.Lock()
        self._gossip_thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=RELAY_WORKERS,
                                            thread_name_prefix="spacecop-relay")
        # (session_id, request_id) -> (encoded RelayResponse frame, timestamp)
        self._response_cache: Dict[Tuple[bytes, bytes], Tuple[bytes, float]] = {}
        # Requests currently being relayed, to coalesce retransmits in flight.
        self._in_flight: set = set()

        # Counters for observability / the score analogy.
        self.relayed_bytes = 0
        self.relayed_requests = 0

    # -- lifecycle ----------------------------------------------------------
    @property
    def address(self) -> Address:
        host, port = self.transport.local_addr
        return self.advertised_host, port

    @property
    def node_id_hex(self) -> str:
        return self.identity.ed_public.hex()[:16]

    def start(self, bootstrap=None) -> None:
        self.transport.start()
        if bootstrap:
            for host, port in bootstrap:
                self.directory.add_bootstrap(host, port)
        self._running.set()
        self._gossip_thread = threading.Thread(target=self._gossip_loop, daemon=True,
                                               name="spacecop-gossip")
        self._gossip_thread.start()
        self._ticker_thread = threading.Thread(target=self._stream_ticker, daemon=True,
                                               name="spacecop-stream-tick")
        self._ticker_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._gossip_thread is not None:
            self._gossip_thread.join(timeout=2.0)
        with self._lock:
            states = list(self._sessions.values())
        for st in states:
            for ns in list(st.streams.values()):
                self._close_node_stream(st, ns, notify_peer=False)
        self._executor.shutdown(wait=False)
        self.transport.stop()

    # -- self-announcement --------------------------------------------------
    def build_announce(self) -> NodeAnnounce:
        _host, port = self.transport.local_addr
        return NodeAnnounce(
            ed_public=self.identity.ed_public,
            x_public=self.identity.x_public,
            host=self.advertised_host,
            port=port,
            score=self.ledger.score(self.identity.ed_public),
            timestamp=int(time.time()),
        ).sign(self.identity.ed_private)

    def _gossip_loop(self) -> None:
        while self._running.is_set():
            try:
                announce = self.build_announce().encode()
                for peer in self.directory.sample(8):
                    self.transport.send(announce, peer.address())
                    self.transport.send(PeerRequest().encode(), peer.address())
                self._expire_idle_sessions()
                self._purge_response_cache()
            except Exception:
                pass
            # Sleep in small increments so stop() is responsive.
            for _ in range(20):
                if not self._running.is_set():
                    break
                time.sleep(0.25)

    # -- datagram dispatch --------------------------------------------------
    def _on_datagram(self, data: bytes, addr: Address) -> None:
        try:
            msg_type, body = framing.decode_frame(data)
        except framing.ProtocolError:
            return

        if msg_type == c.MSG_HANDSHAKE_INIT:
            self._handle_handshake(body, addr)
        elif msg_type == c.MSG_DATA:
            self._handle_data(body, addr)
        elif msg_type == c.MSG_NODE_ANNOUNCE:
            self._handle_announce(body, addr)
        elif msg_type == c.MSG_PEER_REQUEST:
            self._handle_peer_request(body, addr)
        elif msg_type == c.MSG_PEER_LIST:
            self._handle_peer_list(body, addr)
        elif msg_type == c.MSG_RECEIPT:
            self._handle_receipt(body)
        elif msg_type == c.MSG_SCORE_QUERY:
            self._handle_score_query(addr)
        elif msg_type == c.MSG_PING:
            self.transport.send(framing.encode_frame(c.MSG_PONG, body), addr)

    def _handle_handshake(self, body: bytes, addr: Address) -> None:
        try:
            resp_frame, session = self._handshaker.handle_init(body)
        except Exception as exc:
            # Tell the client *why* (in the clear, no secrets): a silent drop
            # is indistinguishable from an unreachable node.  Echo the session
            # id so the client can match it to its pending handshake.
            sid = body[:8] if len(body) >= 8 else b"\x00" * 8
            reason = str(exc).encode("utf-8", "replace")[:200]
            try:
                self.transport.send(framing.encode_frame(c.MSG_ERROR, sid + reason), addr)
            except OSError:
                pass
            return
        with self._lock:
            self._sessions[session.session_id] = _SessionState(session=session, addr=addr)
        self.transport.send(resp_frame, addr)

    def _handle_data(self, body: bytes, addr: Address) -> None:
        try:
            dm = DataMessage.decode(body)
        except framing.ProtocolError:
            return
        with self._lock:
            state = self._sessions.get(dm.session_id)
        if state is None:
            return
        try:
            fragment_bytes = state.session.open(dm.sealed)
        except Exception:
            return
        state.last_active = time.monotonic()
        state.addr = addr  # track roaming clients
        try:
            completed = state.reassembler.add_bytes(fragment_bytes)
        except Exception:
            return
        if completed is not None:
            self._handle_app_message(state, completed)

    def _handle_app_message(self, state: _SessionState, plaintext: bytes) -> None:
        try:
            msg_type, inner = framing.decode_frame(plaintext)
        except framing.ProtocolError:
            return
        if msg_type == c.MSG_RELAY_REQUEST:
            self._handle_relay_request(state, inner)
        elif msg_type == c.MSG_STREAM_OPEN:
            self._handle_stream_open(state, inner)
        elif msg_type == c.MSG_STREAM_DATA:
            self._route_stream(state, inner, StreamData, lambda ns, m: ns.endpoint.on_data(m))
        elif msg_type == c.MSG_STREAM_ACK:
            self._route_stream(state, inner, StreamAck, lambda ns, m: ns.endpoint.on_ack(m))
        elif msg_type == c.MSG_STREAM_CLOSE:
            self._route_stream(state, inner, StreamClose,
                               lambda ns, m: self._close_node_stream(state, ns, notify_peer=False,
                                                                     peer_reason=m.reason))

    # -- streaming relay (full TCP connections, e.g. HTTPS) ------------------
    def _route_stream(self, state: _SessionState, inner: bytes, cls, action) -> None:
        try:
            msg = cls.decode(inner)
        except framing.ProtocolError:
            return
        with self._lock:
            ns = state.streams.get(msg.stream_id)
        if ns is not None:
            action(ns, msg)

    def _handle_stream_open(self, state: _SessionState, inner: bytes) -> None:
        try:
            req = StreamOpen.decode(inner)
        except framing.ProtocolError:
            return
        with self._lock:
            if req.stream_id in state.streams:
                return  # retransmitted OPEN for a stream we already have
            if not self.exit_enabled:
                self._send_app_message(state, StreamOpened(req.stream_id, 1, b"exit disabled").encode())
                return
            ns = _NodeStream(endpoint=self._make_endpoint(state, req.stream_id))
            state.streams[req.stream_id] = ns
        self._executor.submit(self._stream_connect, state, ns, req)

    def _make_endpoint(self, state: _SessionState, stream_id: bytes) -> StreamEndpoint:
        holder: Dict[str, _NodeStream] = {}

        def deliver(data: bytes) -> None:
            ns = holder.get("ns") or state.streams.get(stream_id)
            if ns is not None:
                ns.outbox.put(data)

        def eof() -> None:
            ns = state.streams.get(stream_id)
            if ns is not None:
                ns.outbox.put(None)  # writer thread half-closes the socket

        def error(_why: str) -> None:
            ns = state.streams.get(stream_id)
            if ns is not None:
                self._close_node_stream(state, ns, notify_peer=False)

        return StreamEndpoint(stream_id, lambda frame: self._send_app_message(state, frame),
                              deliver, eof, error)

    def _stream_connect(self, state: _SessionState, ns: _NodeStream, req: StreamOpen) -> None:
        try:
            sock = socket.create_connection((req.dest_host, req.dest_port),
                                            timeout=STREAM_CONNECT_TIMEOUT)
        except OSError as exc:
            self._send_app_message(state, StreamOpened(req.stream_id, 2,
                                                       str(exc).encode()[:120]).encode())
            with self._lock:
                state.streams.pop(req.stream_id, None)
            return
        sock.settimeout(None)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        ns.sock = sock
        with self._lock:
            self.relayed_requests += 1
        self._send_app_message(state, StreamOpened(req.stream_id, 0).encode())
        threading.Thread(target=self._stream_reader, args=(state, ns), daemon=True).start()
        threading.Thread(target=self._stream_writer, args=(state, ns), daemon=True).start()

    def _stream_reader(self, state: _SessionState, ns: _NodeStream) -> None:
        """destination -> overlay"""
        try:
            while not ns.endpoint.closed:
                chunk = ns.sock.recv(c.STREAM_CHUNK_SIZE * 8)
                if not chunk:
                    ns.endpoint.send_fin()
                    break
                with self._lock:
                    self.relayed_bytes += len(chunk)
                ns.endpoint.send(chunk)
        except Exception:
            pass
        self._maybe_finish(state, ns)

    def _stream_writer(self, state: _SessionState, ns: _NodeStream) -> None:
        """overlay -> destination"""
        try:
            while True:
                item = ns.outbox.get()
                if item is None:
                    try:
                        ns.sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    break
                with self._lock:
                    self.relayed_bytes += len(item)
                ns.sock.sendall(item)
        except Exception:
            self._close_node_stream(state, ns, notify_peer=True)
        self._maybe_finish(state, ns)

    def _maybe_finish(self, state: _SessionState, ns: _NodeStream) -> None:
        if ns.endpoint.closed or ns.endpoint.both_directions_done:
            self._close_node_stream(state, ns, notify_peer=not ns.endpoint.closed)

    def _close_node_stream(self, state: _SessionState, ns: _NodeStream,
                           notify_peer: bool, peer_reason: int = 0) -> None:
        with self._lock:
            if ns.done:
                return
            ns.done = True
            state.streams.pop(ns.endpoint.stream_id, None)
        if notify_peer:
            ns.endpoint.close()
        else:
            ns.endpoint.on_close(peer_reason)
        ns.outbox.put(None)
        if ns.sock is not None:
            try:
                ns.sock.close()
            except OSError:
                pass

    def _stream_ticker(self) -> None:
        while self._running.is_set():
            time.sleep(0.1)
            now = time.monotonic()
            with self._lock:
                items = [(st, ns) for st in self._sessions.values()
                         for ns in list(st.streams.values())]
            for st, ns in items:
                try:
                    ns.endpoint.tick(now)
                    if ns.endpoint.closed:
                        self._close_node_stream(st, ns, notify_peer=False)
                    elif ns.endpoint.both_directions_done:
                        self._close_node_stream(st, ns, notify_peer=True)
                except Exception:
                    pass

    # -- relaying (the work that earns points) ------------------------------
    def _handle_relay_request(self, state: _SessionState, inner: bytes) -> None:
        try:
            req = RelayRequest.decode(inner)
        except framing.ProtocolError:
            return
        if not self.exit_enabled:
            self._send_app_message(state, RelayResponse(req.request_id, 1, b"exit disabled").encode())
            return

        key = (state.session.session_id, req.request_id)
        with self._lock:
            cached = self._response_cache.get(key)
            if cached is not None:
                response = cached[0]
            elif key in self._in_flight:
                return  # retransmit of a request we are already relaying
            else:
                self._in_flight.add(key)
                response = None
        if response is not None:
            # Retransmitted request: replay the answer, do not hit the destination again.
            self._send_app_message(state, response)
            return
        # Hand the blocking network work to the pool; the UDP loop stays free.
        self._executor.submit(self._relay_worker, state, req, key)

    def _relay_worker(self, state: _SessionState, req: RelayRequest, key) -> None:
        try:
            status, blob = self._perform_tcp_relay(req.dest_host, req.dest_port, req.blob)
            response = RelayResponse(req.request_id, status, blob).encode()
            with self._lock:
                self.relayed_requests += 1
                self.relayed_bytes += len(blob)
                self._response_cache[key] = (response, time.monotonic())
                self._in_flight.discard(key)
            self._send_app_message(state, response)
        except Exception:
            with self._lock:
                self._in_flight.discard(key)

    def _purge_response_cache(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [k for k, (_, ts) in self._response_cache.items()
                     if now - ts > RESPONSE_CACHE_TTL]
            for k in stale:
                del self._response_cache[k]

    def _perform_tcp_relay(self, host: str, port: int, blob: bytes) -> Tuple[int, bytes]:
        """Forward ``blob`` to (host, port) over TCP and return the reply."""
        try:
            with socket.create_connection((host, port), timeout=RELAY_CONNECT_TIMEOUT) as sock:
                sock.settimeout(RELAY_READ_TIMEOUT)
                sock.sendall(blob)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                chunks = []
                total = 0
                while total < RELAY_MAX_RESPONSE:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                return 0, b"".join(chunks)
        except OSError as exc:
            return 2, f"relay error: {exc}".encode()[:256]

    # -- sending helper -----------------------------------------------------
    def _send_app_message(self, state: _SessionState, inner_frame: bytes) -> None:
        """Fragment, encrypt, and send an application message back to the client."""
        for raw in self.fragmenter.fragment_encoded(inner_frame, shuffle=True):
            sealed = state.session.seal(raw)
            datagram = DataMessage(state.session.session_id, sealed).encode()
            try:
                self.transport.send(datagram, state.addr)
            except OSError:
                break

    # -- control plane ------------------------------------------------------
    def _handle_announce(self, body: bytes, addr: Address) -> None:
        try:
            announce = NodeAnnounce.decode(body)
        except framing.ProtocolError:
            return
        self.directory.add_announce(announce, observed_host=addr[0])

    def _handle_peer_request(self, body: bytes, addr: Address) -> None:
        try:
            req = PeerRequest.decode(body)
        except framing.ProtocolError:
            req = PeerRequest()
        peer_list = self.directory.to_peer_list(req.max_peers)
        self.transport.send(peer_list.encode(), addr)
        # Also introduce ourselves, so a peer that only knew our address as a
        # bootstrap seed learns our real identity and the gossip converges.
        self.transport.send(self.build_announce().encode(), addr)

    def _handle_peer_list(self, body: bytes, addr: Address) -> None:
        try:
            peer_list = PeerList.decode(body)
        except framing.ProtocolError:
            return
        for entry in peer_list.peers:
            self.directory.add_peer_entry(entry)

    def _handle_receipt(self, body: bytes) -> None:
        try:
            receipt = Receipt.decode(body)
        except framing.ProtocolError:
            return
        self.ledger.record(receipt)

    def _handle_score_query(self, addr: Address) -> None:
        standing = self.ledger.standing(self.identity.ed_public)
        report = ScoreReport(self.identity.ed_public, standing.points, standing.receipts)
        self.transport.send(report.encode(), addr)

    # -- introspection ------------------------------------------------------
    def score(self) -> int:
        return self.ledger.score(self.identity.ed_public)

    def active_sessions(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _expire_idle_sessions(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [sid for sid, st in self._sessions.items()
                     if now - st.last_active > SESSION_IDLE_TIMEOUT]
            for sid in stale:
                del self._sessions[sid]
