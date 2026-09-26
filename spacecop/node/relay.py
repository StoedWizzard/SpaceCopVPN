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

import os
import socket
import struct
import threading
import time
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
)
from ..transport import Address, UDPTransport
from .directory import PeerDirectory
from .scoring import Ledger

# Relay safety caps.
RELAY_CONNECT_TIMEOUT = 5.0
RELAY_READ_TIMEOUT = 5.0
RELAY_MAX_RESPONSE = 4 * 1024 * 1024  # cap a single relayed reply at 4 MB


@dataclass
class _SessionState:
    session: Session
    addr: Address
    reassembler: Reassembler = field(default_factory=Reassembler)
    last_active: float = field(default_factory=time.monotonic)


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

    def stop(self) -> None:
        self._running.clear()
        if self._gossip_thread is not None:
            self._gossip_thread.join(timeout=2.0)
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
        except Exception:
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

    # -- relaying (the work that earns points) ------------------------------
    def _handle_relay_request(self, state: _SessionState, inner: bytes) -> None:
        try:
            req = RelayRequest.decode(inner)
        except framing.ProtocolError:
            return
        if not self.exit_enabled:
            self._send_app_message(state, RelayResponse(req.request_id, 1, b"exit disabled").encode())
            return

        status, blob = self._perform_tcp_relay(req.dest_host, req.dest_port, req.blob)
        self.relayed_requests += 1
        self.relayed_bytes += len(blob)
        response = RelayResponse(req.request_id, status, blob).encode()
        self._send_app_message(state, response)

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
