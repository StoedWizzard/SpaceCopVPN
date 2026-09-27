"""A minimal threaded UDP transport built directly on the standard socket API.

Datagrams are the natural unit for this protocol: each fragment and each
control message is one self-contained, independently-encrypted datagram, and
UDP's unordered/lossy delivery is exactly what the fragmentation and replay
layers are designed to tolerate.  This uses only :mod:`socket` and
:mod:`threading`, so it runs unchanged on Windows, Linux, and Android.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable, Optional, Tuple

Address = Tuple[str, int]
DatagramHandler = Callable[[bytes, Address], None]

# Safe UDP payload well under typical path MTU considerations for localhost and
# most networks; the fragment size (20 KB) exceeds this, so at the IP layer a
# fragment datagram may itself be IP-fragmented.  For LAN/loopback and testing
# this is fine; see docs/ARCHITECTURE.md for the production note on MTU.
MAX_DATAGRAM = 65535

# Called with the new socket's file descriptor right after creation.  Android's
# VpnService uses it to protect() the tunnel's own UDP socket so its packets to
# the nodes are not routed back into the tunnel.
socket_created_hook: Optional[Callable[[int], None]] = None


class UDPTransport:
    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 0):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if socket_created_hook is not None:
            try:
                socket_created_hook(self._sock.fileno())
            except Exception:
                pass
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        except OSError:
            pass
        self._sock.bind((bind_host, bind_port))
        self._handler: Optional[DatagramHandler] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    @property
    def local_addr(self) -> Address:
        host, port = self._sock.getsockname()
        return host, port

    def set_handler(self, handler: DatagramHandler) -> None:
        self._handler = handler

    def start(self) -> None:
        if self._thread is not None:
            return
        self._running.set()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True,
                                        name="spacecop-udp-recv")
        self._thread.start()

    def _recv_loop(self) -> None:
        self._sock.settimeout(0.5)
        while self._running.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            if self._handler is not None and data:
                try:
                    self._handler(data, addr)
                except Exception:
                    # A malformed datagram must never take the node down.
                    continue

    def send(self, data: bytes, addr: Address) -> None:
        if len(data) > MAX_DATAGRAM:
            raise ValueError("datagram exceeds maximum size")
        self._sock.sendto(data, addr)

    def stop(self) -> None:
        self._running.clear()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        try:
            self._sock.close()
        except OSError:
            pass
