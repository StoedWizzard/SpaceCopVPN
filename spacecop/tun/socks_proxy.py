"""A userspace SOCKS5 proxy that tunnels connections through the VPN overlay.

This is the driver-free, no-root path that works identically on Windows, Linux,
Android (Termux), and macOS: point an application (or the whole system) at
``socks5://127.0.0.1:1080`` and each CONNECT is carried, fragmented and
encrypted, through a competing relay node to its destination.

It implements just enough of SOCKS5 (RFC 1928, no authentication, CONNECT
command) to be useful.  Payloads flow through :meth:`VPNClient.relay`, so they
are split into 20 KB fragments, shuffled, and encrypted exactly like every
other message in the system.  The relay is request/response oriented, which
covers the common "send request, read reply" pattern (HTTP, DNS-over-TCP, many
APIs); a fully streaming tunnel is described in docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

from ..client import VPNClient

_SOCKS_VERSION = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04
_REP_SUCCESS = 0x00
_REP_GENERAL_FAILURE = 0x01
_REP_CMD_NOT_SUPPORTED = 0x07


class Socks5Proxy:
    def __init__(self, client: VPNClient, listen_host: str = "127.0.0.1",
                 listen_port: int = 1080, gather_timeout: float = 0.4):
        self.client = client
        self.listen_host = listen_host
        self.listen_port = listen_port
        # How long to accumulate the client's request bytes before relaying.
        self.gather_timeout = gather_timeout
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else (self.listen_host, self.listen_port)

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.listen(128)
        self._running.set()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name="spacecop-socks")
        self._thread.start()

    def _accept_loop(self) -> None:
        self._sock.settimeout(0.5)
        while self._running.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                if not self._negotiate(conn):
                    return
                dest_host, dest_port = self._read_connect_request(conn)
                if dest_host is None:
                    self._reply(conn, _REP_CMD_NOT_SUPPORTED)
                    return
                self._reply(conn, _REP_SUCCESS)
                self._pump(conn, dest_host, dest_port)
            except (OSError, struct.error, UnicodeError):
                return
            except Exception:
                # Never let a single malformed SOCKS client take down the proxy.
                return

    def _negotiate(self, conn: socket.socket) -> bool:
        header = self._recv_exact(conn, 2)
        if not header or header[0] != _SOCKS_VERSION:
            return False
        n_methods = header[1]
        self._recv_exact(conn, n_methods)  # discard offered methods
        conn.sendall(bytes([_SOCKS_VERSION, 0x00]))  # choose "no authentication"
        return True

    def _read_connect_request(self, conn: socket.socket):
        header = self._recv_exact(conn, 4)
        if not header or header[0] != _SOCKS_VERSION:
            return None, None
        cmd, _rsv, atyp = header[1], header[2], header[3]
        if cmd != _CMD_CONNECT:
            return None, None
        if atyp == _ATYP_IPV4:
            addr = self._recv_exact(conn, 4)
            host = socket.inet_ntoa(addr)
        elif atyp == _ATYP_DOMAIN:
            length = self._recv_exact(conn, 1)[0]
            host = self._recv_exact(conn, length).decode("utf-8", "replace")
        elif atyp == _ATYP_IPV6:
            addr = self._recv_exact(conn, 16)
            host = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            return None, None
        port = struct.unpack("!H", self._recv_exact(conn, 2))[0]
        return host, port

    def _reply(self, conn: socket.socket, rep: int) -> None:
        # BND.ADDR/PORT are unused by clients for CONNECT; send zeros.
        conn.sendall(bytes([_SOCKS_VERSION, rep, 0x00, _ATYP_IPV4]) + b"\x00\x00\x00\x00\x00\x00")

    def _pump(self, conn: socket.socket, dest_host: str, dest_port: int) -> None:
        # Gather the initial request bytes from the local application.
        conn.settimeout(self.gather_timeout)
        request = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                request += chunk
        except socket.timeout:
            pass
        try:
            response = self.client.relay(dest_host, dest_port, request, timeout=20)
        except Exception:
            return
        if response:
            try:
                conn.sendall(response)
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def stop(self) -> None:
        self._running.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
