"""Full-system VPN on Linux: a TUN interface plus routing, no per-app proxy.

Everything the machine sends goes into ``spacecop0``; the packet engine
terminates TCP and carries it through the overlay; DNS is intercepted and
resolved through the tunnel.  Requires root (``CAP_NET_ADMIN``) — the GUI runs
this through ``pkexec``.  No external tools are needed: interface and routes
are configured through ioctls (:mod:`.netconfig`).

What ``SystemVPN.start()`` does, and ``stop()`` undoes:

1. create ``spacecop0`` (10.77.0.2/24, MTU 1400) and bring it up;
2. add a host route to every node via the *original* default gateway, so the
   tunnel's own UDP packets never loop into the tunnel;
3. steal the default route with the classic ``0.0.0.0/1`` + ``128.0.0.0/1``
   pair (more specific than ``0.0.0.0/0``, so the original default survives
   and comes back untouched when we leave);
4. point DNS at the tunnel gateway (``resolvectl`` when systemd-resolved runs,
   otherwise a backed-up ``/etc/resolv.conf``);
5. run the packet engine; newly discovered nodes get their host route added
   automatically.

Control: the process reads its stdin — a line ``stop`` shuts it down cleanly
(that is how the unprivileged GUI stops a ``pkexec``'d instance, since it
cannot signal a root process).
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Callable, Optional, Tuple

from . import netconfig
from .engine import PacketEngine
from .linux import LinuxTun

TUN_NAME = "spacecop0"
TUN_ADDR = "10.77.0.2"
TUN_GATEWAY = "10.77.0.1"
TUN_MTU = 1400
RESOLV_CONF = "/etc/resolv.conf"
RESOLV_BACKUP = "/etc/resolv.conf.spacecop-backup"


class SystemVPN:
    def __init__(self, client, dns_server: Tuple[str, int] = ("1.1.1.1", 53),
                 on_event: Optional[Callable[[str], None]] = None):
        self.client = client
        self.dns_server = dns_server
        self.on_event = on_event
        self.tun: Optional[LinuxTun] = None
        self.engine: Optional[PacketEngine] = None
        self._gw: Optional[str] = None
        self._dev: Optional[str] = None
        self._node_routes: set = set()
        self._default_stolen = False
        self._dns_mode: Optional[str] = None
        self._running = threading.Event()

    def _emit(self, text: str) -> None:
        if self.on_event:
            self.on_event(text)

    # -- start / stop --------------------------------------------------------
    def start(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("full-system mode needs root (CAP_NET_ADMIN); run via sudo/pkexec")
        self._gw, self._dev = netconfig.default_route()
        if self._dev is None:
            raise RuntimeError("no IPv4 default route found; is the network up?")

        self.tun = LinuxTun(name=TUN_NAME, mtu=TUN_MTU)
        netconfig.set_address(TUN_NAME, TUN_ADDR, 24)
        netconfig.set_mtu(TUN_NAME, TUN_MTU)
        netconfig.set_up(TUN_NAME)
        self._emit(f"interface {TUN_NAME} up ({TUN_ADDR}/24), default via {self._gw} dev {self._dev}")

        for conn in self.client.connections():
            self.add_node_route(conn.addr[0])

        netconfig.replace_route("0.0.0.0", 1, dev=TUN_NAME)
        netconfig.replace_route("128.0.0.0", 1, dev=TUN_NAME)
        self._default_stolen = True
        self._emit("default route now goes through the tunnel")

        self._set_dns()

        self.engine = PacketEngine(self.tun, self.client, gateway_ip=TUN_GATEWAY,
                                   dns_server=self.dns_server, on_event=self.on_event)
        self.engine.start()
        self._running.set()
        threading.Thread(target=self._route_watch, daemon=True).start()
        self._emit("packet engine running: all TCP and DNS now travel through the overlay")

    def stop(self) -> None:
        self._running.clear()
        if self.engine is not None:
            self.engine.stop()
            self.engine = None
        if self._default_stolen:
            netconfig.del_route("0.0.0.0", 1, dev=TUN_NAME)
            netconfig.del_route("128.0.0.0", 1, dev=TUN_NAME)
            self._default_stolen = False
        for host in list(self._node_routes):
            netconfig.del_route(host, 32, gateway=self._gw, dev=self._dev)
        self._node_routes.clear()
        self._restore_dns()
        if self.tun is not None:
            try:
                self.tun.close()   # removes the interface and its routes
            except Exception:
                pass
            self.tun = None
        self._emit("tunnel removed; routes and DNS restored")

    # -- routes ---------------------------------------------------------------
    def add_node_route(self, host: str) -> None:
        """Send traffic to a node via the real gateway, bypassing the tunnel."""
        if host in self._node_routes or self._dev is None:
            return
        if host.startswith("127."):
            return
        try:
            netconfig.replace_route(host, 32, gateway=self._gw, dev=self._dev)
            self._node_routes.add(host)
        except OSError as exc:
            self._emit(f"could not add route for node {host}: {exc}")

    def _route_watch(self) -> None:
        while self._running.is_set():
            time.sleep(2.0)
            for conn in self.client.connections():
                self.add_node_route(conn.addr[0])

    # -- DNS ------------------------------------------------------------------
    def _set_dns(self) -> None:
        if shutil.which("resolvectl"):
            probe = subprocess.run(["resolvectl", "status"], capture_output=True)
            if probe.returncode == 0:
                subprocess.run(["resolvectl", "dns", TUN_NAME, TUN_GATEWAY], capture_output=True)
                subprocess.run(["resolvectl", "domain", TUN_NAME, "~."], capture_output=True)
                self._dns_mode = "resolvectl"
                self._emit("DNS: systemd-resolved now prefers the tunnel")
                return
        try:
            if not os.path.exists(RESOLV_BACKUP):
                shutil.copy2(RESOLV_CONF, RESOLV_BACKUP)
            with open(RESOLV_CONF, "w") as fh:
                fh.write(f"# managed by SpaceCopVPN (backup: {RESOLV_BACKUP})\n"
                         f"nameserver {TUN_GATEWAY}\n")
            self._dns_mode = "resolv.conf"
            self._emit("DNS: /etc/resolv.conf points at the tunnel (backup kept)")
        except OSError as exc:
            self._emit(f"DNS: could not update resolv.conf ({exc}); DNS may bypass the tunnel")

    def _restore_dns(self) -> None:
        if self._dns_mode == "resolvectl":
            subprocess.run(["resolvectl", "revert", TUN_NAME], capture_output=True)
        elif self._dns_mode == "resolv.conf" and os.path.exists(RESOLV_BACKUP):
            try:
                shutil.move(RESOLV_BACKUP, RESOLV_CONF)
            except OSError:
                pass
        self._dns_mode = None

    # -- foreground runner ---------------------------------------------------
    def run_forever(self, status_every: float = 10.0) -> None:
        """Block until 'stop' on stdin, SIGTERM/SIGINT; print periodic status."""
        stop = threading.Event()

        def on_signal(_signum, _frame):
            stop.set()
        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        def stdin_watch():
            try:
                for line in sys.stdin:
                    if line.strip().lower() in ("stop", "quit", "exit"):
                        break
            except Exception:
                pass
            stop.set()  # 'stop' received, or stdin closed (parent died)
        threading.Thread(target=stdin_watch, daemon=True).start()

        try:
            while not stop.wait(status_every):
                if self.engine is not None:
                    self._emit(f"status: connections={self.engine.active_connections()} "
                               f"opened={self.engine.tcp_opened} failed={self.engine.tcp_failed} "
                               f"dns={self.engine.dns_queries} "
                               f"up={self.engine.bytes_up // 1024}KB down={self.engine.bytes_down // 1024}KB "
                               f"nodes={len(self.client.connections())}")
        finally:
            self.stop()
