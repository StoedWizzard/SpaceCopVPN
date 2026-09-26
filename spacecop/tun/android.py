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
