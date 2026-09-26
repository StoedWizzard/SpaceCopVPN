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
LOG_KEEP = 300


def _call_log(log, text: str) -> None:
    """Deliver a log line to ``log``: a Python callable, or a Java/Kotlin object
    with a ``log(String)`` method (Chaquopy proxies are not callable)."""
    if log is None:
        return
    try:
        method = getattr(log, "log", None)
        if callable(method):
            method(text)
        elif callable(log):
            log(text)
    except Exception:
        pass


def set_socket_protector(protector) -> None:
    """Register the VpnService's protect(fd) so the tunnel's own UDP socket
    bypasses the tunnel.  ``protector`` is any object with ``protectFd(int)``."""
    from ..transport import udp as _udp

    def hook(fd: int) -> None:
        try:
            protector.protectFd(fd)
        except Exception:
            pass
    _udp.socket_created_hook = hook


def node_table(client) -> list:
    """Per-node competition stats (same shape as SystemVPN.node_table())."""
    rows = []
    for conn in client._selector.ranking():
        rows.append({
            "id": conn.node_id_hex(),
            "addr": f"{conn.addr[0]}:{conn.addr[1]}",
            "requests": conn.requests,
            "failures": conn.failures,
            "latency_ms": round(conn.ewma_latency * 1000) if conn.ewma_latency else None,
            "health": round(conn.health_score(), 1),
            "bytes": conn.bytes_served,
        })
    return rows


def run_engine(fd: int, uris: list, dns: str = "1.1.1.1:53", discover: bool = True,
               log=None) -> dict:
    """Start the VPN on the file descriptor from ``VpnService`` (non-blocking).

    ``uris`` — connection strings ``spacecop://…``.  Returns a dict with
    ``stop()``, ``status()`` (dict), ``status_json()`` (JSON string incl. the
    node table) and ``log_text()`` (last lines).  Log lines also go to ``log``
    (a Java/Kotlin object with ``log(String)``, or a Python callable).
    """
    import collections
    import json
    import threading
    import time

    from ..client import VPNClient
    from ..protocol.uri import parse_uri
    from .engine import PacketEngine

    lines = collections.deque(maxlen=LOG_KEEP)
    lock = threading.Lock()

    def emit(text):
        stamp = time.strftime("%H:%M:%S")
        with lock:
            lines.append(f"{stamp} {text}")
        _call_log(log, text)

    client = VPNClient(discovery_enabled=discover, on_event=emit)
    client.start()
    ok = 0
    uris = [str(u).strip() for u in uris if str(u).strip()]
    emit(f"connecting to {len(uris)} node(s)…")
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
        raise RuntimeError("ни один узел не ответил (проверьте строку подключения и интернет)")

    host, _, port = dns.rpartition(":")
    tun = FileDescriptorTun(fd, mtu=1400, close_fd=False)
    engine = PacketEngine(tun, client, gateway_ip="10.77.0.1",
                          dns_server=(host or "1.1.1.1", int(port or 53)), on_event=emit)
    engine.start()
    emit("packet engine running — весь трафик идёт через VPN")

    def stop():
        try:
            engine.stop()
        finally:
            client.stop()
        _active.pop(fd, None)
        emit("stopped")

    def status():
        return {
            "nodes": len(client.connections()),
            "connections": engine.active_connections(),
            "opened": engine.tcp_opened,
            "failed": engine.tcp_failed,
            "dns": engine.dns_queries,
            "up": engine.bytes_up,
            "down": engine.bytes_down,
            "table": node_table(client),
        }

    def status_json():
        try:
            return json.dumps(status())
        except Exception as exc:  # never let the UI poller die
            return json.dumps({"error": str(exc)})

    def log_text():
        with lock:
            return "\n".join(lines)

    handle = {"stop": stop, "status": status, "status_json": status_json,
              "log_text": log_text}
    _active[fd] = handle
    return handle


def stop_engine(fd: int) -> None:
    handle = _active.get(fd)
    if handle:
        handle["stop"]()
