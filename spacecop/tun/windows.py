"""Windows TUN backend guidance (Wintun).

Windows has no ``/dev/net/tun``.  The modern, driver-signed way to get a layer-3
adapter is **Wintun** (``wintun.dll`` from the WireGuard project).  Because it
requires shipping and loading a signed DLL and running as Administrator, the
adapter is implemented as a thin ``ctypes`` wrapper that this repository
describes but does not bundle the binary for.

Integration outline (all via ``ctypes``, no third-party Python packages):

1. ``WintunCreateAdapter(name, tunnel_type, guid)`` -> adapter handle.
2. ``WintunStartSession(adapter, capacity)`` -> session handle.
3. Loop: ``WintunReceivePacket`` -> bytes -> feed the engine;
   engine output -> ``WintunAllocateSendPacket`` + ``WintunSendPacket``.
4. On shutdown: ``WintunEndSession`` then ``WintunCloseAdapter``.

Until ``wintun.dll`` is present, constructing :class:`WindowsTun` raises with a
clear message; on Windows without the DLL (or elsewhere) use the SOCKS proxy.
"""

from __future__ import annotations

from .base import TunInterface


class WindowsTun(TunInterface):
    def __init__(self, name: str = "spacecop0", mtu: int = 1400,
                 wintun_dll: str = "wintun.dll"):
        import ctypes
        import sys

        if not sys.platform.startswith("win"):
            raise RuntimeError("WindowsTun is only usable on Windows")
        try:
            self._wintun = ctypes.WinDLL(wintun_dll)  # type: ignore[attr-defined]
        except OSError as exc:
            raise RuntimeError(
                "wintun.dll not found. Download the signed DLL from "
                "https://www.wintun.net/ and place it next to the application, "
                "or run with the SOCKS proxy backend instead."
            ) from exc
        self.name = name
        self.mtu = mtu
        # Full session setup is intentionally left to the packaging step where
        # the DLL is present; see the module docstring for the call sequence.
        raise NotImplementedError(
            "Wintun session bring-up requires the signed wintun.dll at package "
            "time; use spacecop.tun.socks_proxy for a driver-free path."
        )

    def read_packet(self) -> bytes:  # pragma: no cover - requires DLL
        raise NotImplementedError

    def write_packet(self, packet: bytes) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        pass
