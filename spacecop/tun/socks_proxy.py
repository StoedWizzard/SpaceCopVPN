"""A userspace SOCKS5 proxy that tunnels TCP connections through the overlay.

This is the driver-free, no-root path that works identically on Windows, Linux,
Android (Termux), and macOS: point an application (or the whole system) at
``socks5://127.0.0.1:1080`` and every CONNECT becomes a **stream** through a
competing relay node — a real, bidirectional TCP connection, so HTTPS (TLS
handshakes), HTTP keep-alive, WebSockets, SSH and anything else that needs
several round trips inside one connection all work.

It implements SOCKS5 (RFC 1928) with no authentication and the CONNECT
command.  Each connection is carried by :meth:`VPNClient.open_stream`, whose
chunks are individually encrypted, sent in random order within the window,
acknowledged, and retransmitted on loss (see spacecop.protocol.stream).  All
connections to the same site leave through the same node (stable IP).
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
_REP_HOST_UNREACHABLE = 0x04
_REP_CMD_NOT_SUPPORTED = 0x07

_LOCAL_READ = 16 * 1024


class Socks5Proxy:
    def __init__(self, client: VPNClient, listen_host: str = "127.0.0.1",
                 listen_port: int = 1080):
        self.client = client
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self.active = 0
        self._active_lock = threading.Lock()

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else (self.listen_host, self.listen_port)

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self._sock.listen(512)
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

    # -- one client connection ----------------------------------------------
    def _handle(self, conn: socket.socket) -> None:
        stream = None
        with self._active_lock:
            self.active += 1
        try:
            conn.settimeout(10.0)
            if not self._negotiate(conn):
                return
            dest_host, dest_port = self._read_connect_request(conn)
            if dest_host is None:
                self._reply(conn, _REP_CMD_NOT_SUPPORTED)
                return
            try:
                stream = self.client.open_stream(dest_host, dest_port)
            except Exception:
                self._reply(conn, _REP_HOST_UNREACHABLE)
                return
            self._reply(conn, _REP_SUCCESS)
            conn.settimeout(None)
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self._pump(conn, stream)
        except (OSError, struct.error, UnicodeError):
            return
        except Exception:
            return
        finally:
            with self._active_lock:
                self.active -= 1
            if stream is not None:
                stream.close()
            try:
                conn.close()
            except OSError:
                pass

    def _pump(self, conn: socket.socket, stream) -> None:
        """Bidirectional copy until both directions are finished."""
        done = threading.Event()

        def local_to_overlay():
            try:
                while True:
                    chunk = conn.recv(_LOCAL_READ)
                    if not chunk:
                        stream.send_eof()
                        break
                    stream.send(chunk)
            except Exception:
                pass
            finally:
                # If the overlay side is already finished, we are done.
                if stream.closed:
                    done.set()

        def overlay_to_local():
            try:
                while True:
                    chunk = stream.recv()
                    if not chunk:
                        try:
                            conn.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        break
                    conn.sendall(chunk)
            except Exception:
                pass
            finally:
                done.set()

        t1 = threading.Thread(target=local_to_overlay, daemon=True)
        t2 = threading.Thread(target=overlay_to_local, daemon=True)
        t1.start()
        t2.start()
        done.wait()
        # Give the other direction a moment to flush, then tear down.
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)

    # -- SOCKS5 wire ----------------------------------------------------------
    def _negotiate(self, conn: socket.socket) -> bool:
        header = self._recv_exact(conn, 2)
        if len(header) < 2 or header[0] != _SOCKS_VERSION:
            return False
        n_methods = header[1]
        self._recv_exact(conn, n_methods)  # discard offered methods
        conn.sendall(bytes([_SOCKS_VERSION, 0x00]))  # "no authentication"
        return True

    def _read_connect_request(self, conn: socket.socket):
        header = self._recv_exact(conn, 4)
        if len(header) < 4 or header[0] != _SOCKS_VERSION:
            return None, None
        cmd, _rsv, atyp = header[1], header[2], header[3]
        if cmd != _CMD_CONNECT:
            return None, None
        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(self._recv_exact(conn, 4))
        elif atyp == _ATYP_DOMAIN:
            length = self._recv_exact(conn, 1)[0]
            host = self._recv_exact(conn, length).decode("utf-8", "replace")
        elif atyp == _ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, self._recv_exact(conn, 16))
        else:
            return None, None
        port = struct.unpack("!H", self._recv_exact(conn, 2))[0]
        return host, port

    def _reply(self, conn: socket.socket, rep: int) -> None:
        conn.sendall(bytes([_SOCKS_VERSION, rep, 0x00, _ATYP_IPV4]) + b"\x00" * 6)

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
