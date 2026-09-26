"""Android TUN backend: wrap the file descriptor handed over by ``VpnService``.

On Android an app cannot open ``/dev/net/tun`` directly.  Instead a small
Java/Kotlin component extends ``android.net.VpnService``, calls
``Builder.establish()`` to obtain a ``ParcelFileDescriptor``, and passes the
integer file descriptor to this Python engine (for example via Chaquopy, or
over a local UNIX socket).  This backend simply reads and writes that fd, so
all of the protocol/fragmentation/crypto code runs unchanged on Android.

Reference Kotlin sketch (lives in the Android app, not in this repo)::

    class SpaceCopVpn : VpnService() {
        override fun onStartCommand(i: Intent?, f: Int, id: Int): Int {
            val tun = Builder()
                .addAddress("10.8.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .setMtu(1400)
                .establish()
            // hand tun.fd to the Python engine (Chaquopy):
            Python.getInstance().getModule("spacecop.tun.android")
                  .callAttr("run_engine", tun.fd, /* client config */)
            return START_STICKY
        }
    }
"""

from __future__ import annotations

import os

from .base import TunInterface


class FileDescriptorTun(TunInterface):
    """A TUN interface backed by an already-open file descriptor.

    Used on Android (the fd from ``VpnService``), but also handy for tests and
    for any platform that can hand us a packet fd.
    """

    def __init__(self, fd: int, mtu: int = 1400, name: str = "spacecop-android",
                 close_fd: bool = True):
        self._fd = fd
        self.mtu = mtu
        self.name = name
        self._close_fd = close_fd

    def fileno(self) -> int:
        return self._fd

    def read_packet(self) -> bytes:
        return os.read(self._fd, self.mtu + 4)

    def write_packet(self, packet: bytes) -> None:
        os.write(self._fd, packet)

    def close(self) -> None:
        if self._close_fd:
            try:
                os.close(self._fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Entry point called from the Android app (Chaquopy)
# ---------------------------------------------------------------------------
_active = {}


def set_socket_protector(protector) -> None:
    """Register the VpnService's protect(fd) so the tunnel's own UDP socket
    bypasses the tunnel.  ``protector`` is any object with ``protectFd(int)``."""
    from .. import transport
    from ..transport import udp as _udp

    def hook(fd: int) -> None:
        try:
            protector.protectFd(fd)
        except Exception:
            pass
    _udp.socket_created_hook = hook


def run_engine(fd: int, uris: list, dns: str = "1.1.1.1:53", discover: bool = True,
               log=None) -> dict:
    """Start the VPN on the file descriptor from ``VpnService`` (non-blocking).

    ``uris`` — connection strings ``spacecop://…``.  Returns a dict with a
    ``stop()`` callable and a ``status()`` callable.  Log lines go to ``log``
    (a Java/Kotlin callback or Python callable) if given.
    """
    from ..client import VPNClient
    from ..protocol.uri import parse_uri
    from .engine import PacketEngine

    def emit(text):
        if log is not None:
            try:
                log(text)
            except Exception:
                pass

    client = VPNClient(discovery_enabled=discover, on_event=emit)
    client.start()
    ok = 0
    for text in uris:
        try:
            t = parse_uri(text)
            client.connect(t.x_public, t.address, expected_node_ed=t.ed_public, timeout=8.0)
            ok += 1
            emit(f"connected to node {t.host}:{t.port}")
        except Exception as exc:
            emit(f"node {text[:40]}…: {exc}")
    if ok == 0:
        client.stop()
        raise RuntimeError("no node answered")

    host, _, port = dns.rpartition(":")
    tun = FileDescriptorTun(fd, mtu=1400, close_fd=False)
    engine = PacketEngine(tun, client, gateway_ip="10.77.0.1",
                          dns_server=(host or "1.1.1.1", int(port or 53)), on_event=emit)
    engine.start()
    emit("packet engine running")

    def stop():
        engine.stop()
        client.stop()
        _active.pop(fd, None)

    def status():
        return {
            "nodes": len(client.connections()),
            "connections": engine.active_connections(),
            "opened": engine.tcp_opened,
            "failed": engine.tcp_failed,
            "dns": engine.dns_queries,
            "up": engine.bytes_up,
            "down": engine.bytes_down,
        }

    handle = {"stop": stop, "status": status}
    _active[fd] = handle
    return handle


def stop_engine(fd: int) -> None:
    handle = _active.get(fd)
    if handle:
        handle["stop"]()
