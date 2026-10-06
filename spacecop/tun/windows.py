"""Windows TUN backend on top of the Wintun driver (ctypes, no Python packages).

Windows has no ``/dev/net/tun``; the signed, kernel-mode **Wintun** driver
(https://www.wintun.net, from the WireGuard project) provides a layer-3
adapter that user space drives through ``wintun.dll``.  Everything above the
adapter — the protocol, the streams, the userspace TCP/IP engine — is our
own code, exactly as on Linux and Android.

``wintun.dll`` is looked up in this order: ``SPACECOP_WINTUN`` (a path), the
directory of the executable, PyInstaller's ``_MEIPASS``, the package
directory, the current directory, then the normal DLL search path.  The
Windows build in CI bundles it next to ``SpaceCopVPN.exe``.

Creating the adapter needs Administrator rights (the driver is installed on
first use).  Importing this module on other platforms is harmless.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import uuid
from ctypes import POINTER, byref, c_ubyte, c_uint32, c_uint64, c_void_p, c_wchar_p
from typing import Optional

from .base import TunInterface

ADAPTER_NAME = "SpaceCopVPN"
TUNNEL_TYPE = "SpaceCopVPN"
# Fixed adapter GUID so Windows keeps the same interface (and its settings)
# across runs instead of creating "SpaceCopVPN 2", "SpaceCopVPN 3", ...
ADAPTER_GUID = uuid.UUID("7c5cff01-5c8d-4f0b-9b6e-5ac3c0b7a5e1")
RING_CAPACITY = 0x400000       # 4 MiB, Wintun's recommended default
ERROR_NO_MORE_ITEMS = 259
WAIT_TIMEOUT_MS = 250


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def from_uuid(cls, u: uuid.UUID) -> "_GUID":
        g = cls()
        g.Data1 = u.time_low
        g.Data2 = u.time_mid
        g.Data3 = u.time_hi_version
        rest = u.bytes[8:]
        for i in range(8):
            g.Data4[i] = rest[i]
        return g


def find_wintun_dll() -> Optional[str]:
    candidates = []
    env = os.environ.get("SPACECOP_WINTUN")
    if env:
        candidates.append(env)
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    candidates.append(os.path.join(exe_dir, "wintun.dll"))
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "wintun.dll"))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wintun.dll"))
    candidates.append(os.path.join(os.getcwd(), "wintun.dll"))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def load_wintun():
    """Load wintun.dll and declare the function signatures."""
    if not sys.platform.startswith("win"):
        raise RuntimeError("Wintun is only usable on Windows")
    path = find_wintun_dll() or "wintun.dll"
    try:
        dll = ctypes.WinDLL(path, use_last_error=True)  # type: ignore[attr-defined]
    except OSError as exc:
        raise RuntimeError(
            "wintun.dll not found. Download https://www.wintun.net/builds/wintun-0.14.1.zip, "
            "take wintun/bin/amd64/wintun.dll and put it next to SpaceCopVPN.exe "
            "(or set SPACECOP_WINTUN to its path)."
        ) from exc
    dll.WintunCreateAdapter.argtypes = [c_wchar_p, c_wchar_p, POINTER(_GUID)]
    dll.WintunCreateAdapter.restype = c_void_p
    dll.WintunCloseAdapter.argtypes = [c_void_p]
    dll.WintunCloseAdapter.restype = None
    dll.WintunGetAdapterLUID.argtypes = [c_void_p, POINTER(c_uint64)]
    dll.WintunGetAdapterLUID.restype = None
    dll.WintunGetRunningDriverVersion.argtypes = []
    dll.WintunGetRunningDriverVersion.restype = c_uint32
    dll.WintunStartSession.argtypes = [c_void_p, c_uint32]
    dll.WintunStartSession.restype = c_void_p
    dll.WintunEndSession.argtypes = [c_void_p]
    dll.WintunEndSession.restype = None
    dll.WintunGetReadWaitEvent.argtypes = [c_void_p]
    dll.WintunGetReadWaitEvent.restype = c_void_p
    dll.WintunReceivePacket.argtypes = [c_void_p, POINTER(c_uint32)]
    dll.WintunReceivePacket.restype = POINTER(c_ubyte)
    dll.WintunReleaseReceivePacket.argtypes = [c_void_p, POINTER(c_ubyte)]
    dll.WintunReleaseReceivePacket.restype = None
    dll.WintunAllocateSendPacket.argtypes = [c_void_p, c_uint32]
    dll.WintunAllocateSendPacket.restype = POINTER(c_ubyte)
    dll.WintunSendPacket.argtypes = [c_void_p, POINTER(c_ubyte)]
    dll.WintunSendPacket.restype = None
    return dll


def is_admin() -> bool:
    if not sys.platform.startswith("win"):
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


class WindowsTun(TunInterface):
    """A Wintun adapter exposed through the common TunInterface."""

    def __init__(self, name: str = ADAPTER_NAME, mtu: int = 1400):
        self._dll = load_wintun()
        self.name = name
        self.mtu = mtu
        self._closed = False
        self._lock = threading.Lock()

        guid = _GUID.from_uuid(ADAPTER_GUID)
        self._adapter = self._dll.WintunCreateAdapter(name, TUNNEL_TYPE, byref(guid))
        if not self._adapter:
            err = ctypes.get_last_error()
            raise OSError(err, f"WintunCreateAdapter failed (error {err}); run as Administrator")
        self._session = self._dll.WintunStartSession(self._adapter, RING_CAPACITY)
        if not self._session:
            err = ctypes.get_last_error()
            self._dll.WintunCloseAdapter(self._adapter)
            raise OSError(err, f"WintunStartSession failed (error {err})")
        self._event = self._dll.WintunGetReadWaitEvent(self._session)
        self._k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    # -- identity ---------------------------------------------------------
    def luid(self) -> int:
        luid = c_uint64(0)
        self._dll.WintunGetAdapterLUID(self._adapter, byref(luid))
        return luid.value

    def interface_index(self) -> int:
        """Interface index (for `route ... if N`), via iphlpapi."""
        iphlp = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
        luid = c_uint64(self.luid())
        index = c_uint32(0)
        rc = iphlp.ConvertInterfaceLuidToIndex(byref(luid), byref(index))
        if rc != 0:
            raise OSError(rc, "ConvertInterfaceLuidToIndex failed")
        return index.value

    def driver_version(self) -> str:
        v = self._dll.WintunGetRunningDriverVersion()
        return f"{v >> 16}.{v & 0xFFFF}"

    # -- packets ----------------------------------------------------------
    def read_packet(self) -> bytes:
        size = c_uint32(0)
        while True:
            if self._closed:
                raise OSError("Wintun adapter closed")
            ptr = self._dll.WintunReceivePacket(self._session, byref(size))
            if ptr:
                try:
                    return ctypes.string_at(ptr, size.value)
                finally:
                    self._dll.WintunReleaseReceivePacket(self._session, ptr)
            err = ctypes.get_last_error()
            if err == ERROR_NO_MORE_ITEMS:
                self._k32.WaitForSingleObject(self._event, WAIT_TIMEOUT_MS)
                continue
            raise OSError(err, f"WintunReceivePacket failed (error {err})")

    def write_packet(self, packet: bytes) -> None:
        if self._closed:
            return
        with self._lock:
            buf = self._dll.WintunAllocateSendPacket(self._session, len(packet))
            if not buf:
                return  # ring full: drop, like a congested NIC would
            ctypes.memmove(buf, packet, len(packet))
            self._dll.WintunSendPacket(self._session, buf)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._session:
                self._dll.WintunEndSession(self._session)
        finally:
            self._session = None
            if self._adapter:
                self._dll.WintunCloseAdapter(self._adapter)  # removes the adapter
            self._adapter = None
