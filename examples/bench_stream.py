"""End-to-end throughput of the overlay on loopback: client -> node -> TCP
server and back, through the real stream engine, with the native crypto
library and with pure Python.

    python examples/bench_stream.py                 # 8 MB download, both backends
    python examples/bench_stream.py --mb 32 --pure  # pure Python only

This is the number a user feels ("how fast does a download go"), and it
includes everything: fragmentation, stream ACKs, the node's worker pool,
UDP on loopback, and two AEAD passes per packet.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient  # noqa: E402
from spacecop.crypto import aead, native  # noqa: E402
from spacecop.node import RelayNode  # noqa: E402


class BlobServer:
    """On 'big N\\n' sends N pseudo-random bytes; on 'bye' closes."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.host, self.port = self.sock.getsockname()
        self.blob = os.urandom(1 << 20)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.startswith(b"big "):
                        n = int(line[4:])
                        conn.sendall(struct.pack("!I", n))
                        sent = 0
                        while sent < n:
                            piece = self.blob[: min(len(self.blob), n - sent)]
                            conn.sendall(piece)
                            sent += len(piece)
                    elif line == b"bye":
                        return


def run(mb: int, label: str) -> float:
    server = BlobServer()
    node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
    node.start()
    client = VPNClient(bind_host="127.0.0.1")
    client.start()
    client.connect(node.identity.x_public, node.address, expected_node_ed=node.identity.ed_public)
    try:
        n = mb * 1024 * 1024
        s = client.open_stream(server.host, server.port)
        t0 = time.perf_counter()
        s.send(b"big %d\n" % n)
        got = 0
        while got < 4 + n:
            chunk = s.recv(timeout=120)
            if not chunk:
                raise RuntimeError("EOF before the whole payload arrived")
            got += len(chunk)
        dt = time.perf_counter() - t0
        s.send(b"bye\n")
        s.close()
        mbit = n * 8 / dt / 1e6
        print(f"{label:12s}: {mb} MB in {dt:6.2f} s  ->  {n / dt / 1e6:6.1f} MB/s  ({mbit:6.1f} Mbit/s)")
        return mbit
    finally:
        client.stop()
        node.stop()
        server.sock.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=int, default=8)
    ap.add_argument("--pure", action="store_true", help="only the pure-Python backend")
    ap.add_argument("--native", action="store_true", help="only the native backend")
    args = ap.parse_args()

    want_native = not args.pure
    want_pure = not args.native
    if want_native:
        if native.available():
            run(args.mb, "native C")
        else:
            print("native C: library not built (run native/build.sh)")
    if want_pure:
        native.disable()
        assert aead.backend() == "python"
        run(max(1, min(args.mb, 4)), "pure Python")


if __name__ == "__main__":
    main()
