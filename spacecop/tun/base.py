"""Abstract virtual-network-interface API used by the platform backends.

A real VPN captures the device's IP packets, tunnels them, and injects the
replies.  The mechanism for capturing packets differs per OS:

* **Linux** — a ``/dev/net/tun`` character device (see :mod:`.linux`).
* **Android** — the ``VpnService`` Java API hands us a file descriptor
  (see :mod:`.android`).
* **Windows** — the Wintun / TAP-Windows driver (see :mod:`.windows`).

They all expose the same tiny interface below, so the packet engine
(:mod:`.engine`) is written once and works everywhere a backend exists.  Where
no TUN backend is available (or no privileges), the userspace SOCKS proxy in
:mod:`.socks_proxy` provides a driver-free path that runs on every platform.
"""

from __future__ import annotations

import abc


class TunInterface(abc.ABC):
    """A bidirectional stream of raw IP packets."""

    mtu: int = 1500
    name: str = "spacecop0"

    @abc.abstractmethod
    def read_packet(self) -> bytes:
        """Block until one IP packet is available and return it."""

    @abc.abstractmethod
    def write_packet(self, packet: bytes) -> None:
        """Inject one IP packet toward the OS network stack."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release the interface."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
