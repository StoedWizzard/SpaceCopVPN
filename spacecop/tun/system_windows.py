"""Full-system VPN on Windows: Wintun adapter + routes + DNS, same engine as Linux.

Mirror of :mod:`spacecop.tun.system` for Windows.  Needs Administrator.

``WindowsSystemVPN.start()`` does, and ``stop()`` undoes:

1. create the ``SpaceCopVPN`` Wintun adapter (10.77.0.2/24, MTU 1400);
2. add host routes to every node via the *original* default gateway, so the
   tunnel's own UDP never loops into the tunnel (also for nodes discovered
   later);
3. steal the default route with ``0.0.0.0/1`` + ``128.0.0.0/1`` via the
   adapter (more specific than ``0.0.0.0/0``; the original route survives);
4. point the adapter's DNS at the tunnel gateway and give the adapter the
   lowest interface metric, so Windows prefers it for name resolution;
5. run the packet engine.

Configuration uses the stock ``route``, ``netsh`` and PowerShell
``Get-NetRoute`` commands — nothing to install.  Closing the adapter removes
it together with its routes and DNS settings.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from typing import Callable, List, Optional, Tuple

from .engine import PacketEngine

TUN_ADDR = "10.77.0.2"
TUN_MASK = "255.255.255.0"
TUN_GATEWAY = "10.77.0.1"
TUN_MTU = 1400

_CREATE_NO_WINDOW = 0x08000000


def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True,
                          creationflags=_CREATE_NO_WINDOW if sys.platform.startswith("win") else 0)


def default_route() -> Tuple[Optional[str], Optional[int]]:
    """(gateway, interface index) of the IPv4 default route."""
    ps = ("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | "
          "Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 | "
          "ForEach-Object { $_.NextHop + ' ' + $_.InterfaceIndex }")
    try:
        out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None, None
    if len(out) >= 2:
        try:
            return out[0], int(out[1])
        except ValueError:
            pass
    return None, None


class WindowsSystemVPN:
    def __init__(self, client, dns_server: Tuple[str, int] = ("1.1.1.1", 53),
                 on_event: Optional[Callable[[str], None]] = None):
        self.client = client
        self.dns_server = dns_server
        self.on_event = on_event
        self.tun = None
        self.engine: Optional[PacketEngine] = None
        self._gw: Optional[str] = None
        self._gw_if: Optional[int] = None
        self._if_index: Optional[int] = None
        self._node_routes: set = set()
        self._default_stolen = False
        self._running = threading.Event()

    def _emit(self, text: str) -> None:
        if self.on_event:
            self.on_event(text)

    # -- start / stop --------------------------------------------------------
    def start(self) -> None:
        from .windows import WindowsTun, is_admin

        if not is_admin():
            raise PermissionError("full-system mode needs Administrator rights")
        self._gw, self._gw_if = default_route()
        if self._gw is None or self._gw_if is None:
            raise RuntimeError("no IPv4 default route found; is the network up?")

        self.tun = WindowsTun(mtu=TUN_MTU)
        self._if_index = self.tun.interface_index()
        name = self.tun.name
        self._emit(f"Wintun {self.tun.driver_version()} adapter '{name}' created (if {self._if_index}), "
                   f"default via {self._gw} if {self._gw_if}")

        _run(["netsh", "interface", "ipv4", "set", "address", f"name={name}", "static",
              TUN_ADDR, TUN_MASK])
        _run(["netsh", "interface", "ipv4", "set", "subinterface", name, f"mtu={TUN_MTU}",
              "store=active"], check=False)
        _run(["netsh", "interface", "ipv4", "set", "interface", name, "metric=1"], check=False)
        # Windows takes a moment to bring the address up; routes fail before that.
        time.sleep(1.0)

        for conn in self.client.connections():
            self.add_node_route(conn.addr[0])

        for prefix in ("0.0.0.0", "128.0.0.0"):
            _run(["route", "add", prefix, "mask", "128.0.0.0", TUN_GATEWAY,
                  "metric", "1", "if", str(self._if_index)])
        self._default_stolen = True
        self._emit("default route now goes through the tunnel")

        _run(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "static",
              TUN_GATEWAY, "primary", "validate=no"], check=False)
        _run(["ipconfig", "/flushdns"], check=False)
        self._emit("DNS: adapter resolver set to the tunnel gateway")

        self.engine = PacketEngine(self.tun, self.client, gateway_ip=TUN_GATEWAY,
                                   dns_server=self.dns_server, on_event=self.on_event)
        self.engine.start()
        self._running.set()
        threading.Thread(target=self._route_watch, daemon=True).start()
        self._emit("packet engine running: all TCP and DNS now travel through the overlay")

    def stop(self) -> None:
        self._running.clear()
        if self.engine is not None:
            self.engine.stop()   # also closes the adapter (removes it and its routes)
            self.engine = None
        if self._default_stolen:
            for prefix in ("0.0.0.0", "128.0.0.0"):
                _run(["route", "delete", prefix, "mask", "128.0.0.0", TUN_GATEWAY], check=False)
            self._default_stolen = False
        for host in list(self._node_routes):
            _run(["route", "delete", host, "mask", "255.255.255.255", self._gw or "0.0.0.0"], check=False)
        self._node_routes.clear()
        if self.tun is not None:
            try:
                self.tun.close()
            except Exception:
                pass
            self.tun = None
        _run(["ipconfig", "/flushdns"], check=False)
        self._emit("tunnel removed; routes and DNS restored")

    # -- routes ---------------------------------------------------------------
    def add_node_route(self, host: str) -> None:
        if host in self._node_routes or self._gw is None or host.startswith("127."):
            return
        try:
            _run(["route", "add", host, "mask", "255.255.255.255", self._gw,
                  "metric", "1", "if", str(self._gw_if)])
            self._node_routes.add(host)
        except subprocess.CalledProcessError as exc:
            self._emit(f"could not add route for node {host}: {exc.stderr.strip()}")

    def _route_watch(self) -> None:
        while self._running.is_set():
            time.sleep(2.0)
            for conn in self.client.connections():
                self.add_node_route(conn.addr[0])

    # -- status ---------------------------------------------------------------
    def node_table(self) -> list:
        rows = []
        for conn in self.client._selector.ranking():
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

    def run_forever(self, status_every: float = 10.0) -> None:
        """Block until Ctrl-C / 'stop' on stdin; print periodic status."""
        import json
        import signal

        stop = threading.Event()

        def on_signal(_s, _f):
            stop.set()
        try:
            signal.signal(signal.SIGINT, on_signal)
            signal.signal(signal.SIGTERM, on_signal)
        except Exception:
            pass

        def stdin_watch():
            try:
                for line in sys.stdin:
                    if line.strip().lower() in ("stop", "quit", "exit"):
                        break
            except Exception:
                pass
            stop.set()
        threading.Thread(target=stdin_watch, daemon=True).start()

        try:
            while not stop.wait(status_every):
                if self.engine is not None:
                    self._emit(f"status: connections={self.engine.active_connections()} "
                               f"opened={self.engine.tcp_opened} failed={self.engine.tcp_failed} "
                               f"dns={self.engine.dns_queries} nodes={len(self.client.connections())}")
                    self._emit("NODES " + json.dumps(self.node_table(), separators=(",", ":")))
        finally:
            self.stop()
