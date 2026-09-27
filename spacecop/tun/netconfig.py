"""Linux network configuration with no external tools (pure ioctl + /proc).

``iproute2`` is not always installed (containers, minimal images), so the
full-system mode configures the TUN interface and routes directly through the
kernel's legacy ioctl interface: ``SIOCSIFADDR``/``SIOCSIFNETMASK``/
``SIOCSIFMTU``/``SIOCSIFFLAGS`` for the interface and ``SIOCADDRT``/
``SIOCDELRT`` (``struct rtentry``) for routes.  The default route is read from
``/proc/net/route``.  IPv4 only, x86_64/aarch64 (64-bit ``long``) layouts.
"""

from __future__ import annotations

import ctypes
import fcntl
import socket
import struct
from typing import Optional, Tuple

# <linux/sockios.h>
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCSIFADDR = 0x8916
SIOCSIFNETMASK = 0x891C
SIOCSIFMTU = 0x8922
SIOCADDRT = 0x890B
SIOCDELRT = 0x890C
# <net/if.h>
IFF_UP = 0x1
IFF_RUNNING = 0x40
# <linux/route.h>
RTF_UP = 0x0001
RTF_GATEWAY = 0x0002
RTF_HOST = 0x0004

_IFNAMSIZ = 16


def _sockaddr_in(addr: str) -> bytes:
    return struct.pack("=H2s4s8x", socket.AF_INET, b"\x00\x00", socket.inet_aton(addr))


def _ifreq(name: str, payload: bytes) -> bytes:
    return name.encode("ascii").ljust(_IFNAMSIZ, b"\x00") + payload.ljust(24, b"\x00")


def _ctl_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------
def set_address(ifname: str, addr: str, prefix: int) -> None:
    mask = socket.inet_ntoa(struct.pack("!I", (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF))
    with _ctl_socket() as s:
        fcntl.ioctl(s, SIOCSIFADDR, _ifreq(ifname, _sockaddr_in(addr)))
        fcntl.ioctl(s, SIOCSIFNETMASK, _ifreq(ifname, _sockaddr_in(mask)))


def set_mtu(ifname: str, mtu: int) -> None:
    with _ctl_socket() as s:
        fcntl.ioctl(s, SIOCSIFMTU, _ifreq(ifname, struct.pack("=i", mtu)))


def set_up(ifname: str, up: bool = True) -> None:
    with _ctl_socket() as s:
        res = fcntl.ioctl(s, SIOCGIFFLAGS, _ifreq(ifname, b""))
        (flags,) = struct.unpack_from("=H", res, _IFNAMSIZ)
        flags = (flags | IFF_UP | IFF_RUNNING) if up else (flags & ~IFF_UP)
        fcntl.ioctl(s, SIOCSIFFLAGS, _ifreq(ifname, struct.pack("=H", flags)))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def _rtentry(dst: str, prefix: int, gateway: Optional[str], dev: Optional[str]):
    """Build a struct rtentry (64-bit layout); returns (bytes, keepalive refs)."""
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    flags = RTF_UP
    if gateway:
        flags |= RTF_GATEWAY
    if prefix == 32:
        flags |= RTF_HOST
    dev_buf = ctypes.create_string_buffer(dev.encode("ascii")) if dev else None
    dev_ptr = ctypes.addressof(dev_buf) if dev_buf is not None else 0
    entry = struct.pack(
        "=Q16s16s16sHh4xQQh6xQQQH6x",
        0,
        _sockaddr_in(dst),
        _sockaddr_in(gateway) if gateway else _sockaddr_in("0.0.0.0"),
        _sockaddr_in(socket.inet_ntoa(struct.pack("!I", mask))),
        flags, 0,
        0, 0,
        0,
        dev_ptr,
        0, 0, 0,
    )
    return entry, dev_buf


def add_route(dst: str, prefix: int, gateway: Optional[str] = None,
              dev: Optional[str] = None) -> None:
    entry, keep = _rtentry(dst, prefix, gateway, dev)
    with _ctl_socket() as s:
        fcntl.ioctl(s, SIOCADDRT, entry)
    del keep


def del_route(dst: str, prefix: int, gateway: Optional[str] = None,
              dev: Optional[str] = None) -> None:
    entry, keep = _rtentry(dst, prefix, gateway, dev)
    with _ctl_socket() as s:
        try:
            fcntl.ioctl(s, SIOCDELRT, entry)
        except OSError:
            pass
    del keep


def replace_route(dst: str, prefix: int, gateway: Optional[str] = None,
                  dev: Optional[str] = None) -> None:
    try:
        add_route(dst, prefix, gateway, dev)
    except FileExistsError:
        del_route(dst, prefix)
        add_route(dst, prefix, gateway, dev)


def default_route() -> Tuple[Optional[str], Optional[str]]:
    """(gateway, interface) of the IPv4 default route, from /proc/net/route."""
    try:
        with open("/proc/net/route") as fh:
            next(fh)
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface, dest, gw, flags = parts[0], parts[1], parts[2], int(parts[3], 16)
                if dest == "00000000" and flags & RTF_UP:
                    gateway = socket.inet_ntoa(struct.pack("<I", int(gw, 16))) if flags & RTF_GATEWAY else None
                    return gateway, iface
    except OSError:
        pass
    return None, None
