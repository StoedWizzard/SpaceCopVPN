"""Linux TUN backend using ``/dev/net/tun`` directly via ioctl.

No third-party bindings: we open the character device and issue the
``TUNSETIFF`` ioctl ourselves with :mod:`fcntl` and :mod:`struct`.  Creating a
TUN device requires ``CAP_NET_ADMIN`` (typically root), so this backend is used
when the VPN runs with privileges; otherwise fall back to the SOCKS proxy.
"""

from __future__ import annotations

import os
import struct

from .base import TunInterface

# From <linux/if_tun.h> and <net/if.h>.
_TUNSETIFF = 0x400454CA
_IFF_TUN = 0x0001    # TUN device (layer 3, raw IP packets)
_IFF_NO_PI = 0x1000  # no extra packet-info header prepended
_IFNAMSIZ = 16


class LinuxTun(TunInterface):
    def __init__(self, name: str = "spacecop0", mtu: int = 1500):
        try:
            import fcntl  # Linux-only; imported lazily so the module imports anywhere
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("fcntl unavailable; not a Linux system") from exc

        self.mtu = mtu
        self._fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack(f"{_IFNAMSIZ}sH", name.encode("ascii"), _IFF_TUN | _IFF_NO_PI)
        try:
            result = fcntl.ioctl(self._fd, _TUNSETIFF, ifr)
        except OSError:
            os.close(self._fd)
            raise
        self.name = result[:_IFNAMSIZ].rstrip(b"\x00").decode("ascii")

    def fileno(self) -> int:
        return self._fd

    def read_packet(self) -> bytes:
        # Read up to MTU + a little slack for any framing.
        return os.read(self._fd, self.mtu + 4)

    def write_packet(self, packet: bytes) -> None:
        os.write(self._fd, packet)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


def configure_interface_commands(name: str, address: str, netmask_bits: int = 24) -> list:
    """Return the shell commands an operator runs to bring the interface up.

    We deliberately do not shell out automatically; the caller decides how to
    apply these (they need root and vary by distro).
    """
    return [
        f"ip addr add {address}/{netmask_bits} dev {name}",
        f"ip link set dev {name} up",
    ]
