"""Cross-platform device integration.

* :mod:`base` — the common ``TunInterface`` all backends implement.
* :mod:`linux` — real ``/dev/net/tun`` backend.
* :mod:`android` — file-descriptor backend for ``VpnService``.
* :mod:`windows` — Wintun integration guidance.
* :mod:`socks_proxy` — driver-free userspace SOCKS5 tunnel (all platforms).

Only the backend appropriate to the running platform is imported lazily by
:func:`open_default_tun`; importing this package never requires OS-specific
modules.
"""

from __future__ import annotations

import sys

from .base import TunInterface
from .socks_proxy import Socks5Proxy


def open_default_tun(name: str = "spacecop0", mtu: int = 1400) -> TunInterface:
    """Open the best available TUN backend for the current OS.

    Raises ``RuntimeError`` with guidance if no privileged backend is available;
    callers can then fall back to :class:`Socks5Proxy`.
    """
    platform = sys.platform
    if platform.startswith("linux"):
        from .linux import LinuxTun
        return LinuxTun(name=name, mtu=mtu)
    if platform.startswith("win"):
        from .windows import WindowsTun
        return WindowsTun(name=name, mtu=mtu)
    raise RuntimeError(
        f"no native TUN backend for platform {platform!r}; "
        f"use Socks5Proxy for a driver-free tunnel"
    )


__all__ = ["TunInterface", "Socks5Proxy", "open_default_tun"]
