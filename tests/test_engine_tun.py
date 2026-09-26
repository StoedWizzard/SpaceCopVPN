"""Live test of the userspace TCP/IP engine on a real Linux TUN interface.

Needs root and /dev/net/tun (skipped otherwise).  A real application socket
connects to an address routed into the TUN; the engine terminates TCP, carries
the bytes through a node as an overlay stream, and the reply comes back as
segments the kernel reassembles for the application.  DNS over UDP into the
TUN is answered through a DNS-over-TCP stream.
"""

import os
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.node import RelayNode
from test_stream import DialogueServer

TUN = "sctest0"
TUN_ADDR = "10.77.9.2"
FAKE_NET = "10.99.0.0/24"
FAKE_HOST = "10.99.0.5"      # routed into the TUN, rewritten to 127.0.0.1 by the engine
FAKE_DNS = "10.99.0.9"


def _have_tun() -> bool:
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        return False
    return os.path.exists("/dev/net/tun")


class FakeDnsOverTcp:
    """Answers any DNS-over-TCP query with a fixed A record 93.184.216.34."""

    def __init__(self):
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self._sock.settimeout(0.5)
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            hdr = conn.recv(2)
            if len(hdr) < 2:
                return
            n = struct.unpack("!H", hdr)[0]
            q = b""
            while len(q) < n:
                chunk = conn.recv(n - len(q))
                if not chunk:
                    return
                q += chunk
            # Minimal answer: copy id, set QR|RD|RA, 1 question echoed, 1 answer.
            qid = q[:2]
            question = q[12:]
            answer = (qid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + question
                      + b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04"
                      + socket.inet_aton("93.184.216.34"))
            conn.sendall(struct.pack("!H", len(answer)) + answer)

    def stop(self):
        self._running = False
        self._sock.close()


@unittest.skipUnless(_have_tun(), "needs root and /dev/net/tun")
class TestEngineOnRealTun(unittest.TestCase):
    def setUp(self):
        from spacecop.tun.engine import PacketEngine
        from spacecop.tun.linux import LinuxTun

        self.server = DialogueServer()
        self.dns = FakeDnsOverTcp()
        self.node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.node.start()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(self.node.identity.x_public, self.node.address,
                            expected_node_ed=self.node.identity.ed_public)

        from spacecop.tun import netconfig
        self.tun = LinuxTun(name=TUN, mtu=1400)
        netconfig.set_address(TUN, TUN_ADDR, 24)
        netconfig.set_mtu(TUN, 1400)
        netconfig.set_up(TUN)
        netconfig.replace_route(FAKE_NET.split("/")[0], 24, dev=TUN)

        self.events = []
        self.engine = PacketEngine(
            self.tun, self.client, gateway_ip="10.77.9.1",
            dns_server=("127.0.0.1", self.dns.port),
            on_event=self.events.append,
            rewrite=lambda h, p: ("127.0.0.1", p) if h.startswith("10.99.") else (h, p),
        )
        self.engine.start()

    def tearDown(self):
        self.engine.stop()
        self.client.stop()
        self.node.stop()
        self.server.stop()
        self.dns.stop()  # closing the TUN fd removes the interface and its routes

    def test_tcp_dialogue_through_tun(self):
        s = socket.create_connection((FAKE_HOST, self.server.port), timeout=15)
        f = s.makefile("rwb", buffering=0)
        for i in range(15):
            f.write(b"ping %d\n" % i)
            self.assertEqual(f.readline(), b"pong %d\n" % i)
        f.write(b"bye\n")
        self.assertEqual(f.readline(), b"ok\n")
        self.assertEqual(f.read(), b"")   # FIN from the far side reached the app
        s.close()
        self.assertEqual(self.engine.tcp_failed, 0, self.events)

    def test_large_download_through_tun(self):
        n = 600 * 1024
        s = socket.create_connection((FAKE_HOST, self.server.port), timeout=20)
        s.sendall(b"big %d\n" % n)
        got = b""
        s.settimeout(30)
        while len(got) < 4 + n:
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        self.assertEqual(len(got), 4 + n, f"got {len(got)} bytes; events={self.events[-5:]}")
        expected = bytes(range(256)) * (n // 256) + bytes(n % 256)
        self.assertEqual(got[4:], expected)
        s.sendall(b"bye\n")
        s.close()

    def test_many_parallel_connections_through_tun(self):
        from concurrent.futures import ThreadPoolExecutor

        def one(i):
            s = socket.create_connection((FAKE_HOST, self.server.port), timeout=20)
            f = s.makefile("rwb", buffering=0)
            ok = True
            for k in range(4):
                f.write(b"ping %d-%d\n" % (i, k))
                ok = ok and f.readline() == b"pong %d-%d\n" % (i, k)
            f.write(b"bye\n")
            ok = ok and f.readline() == b"ok\n"
            s.close()
            return ok
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(one, range(40)))
        self.assertTrue(all(results), f"{results.count(False)} failed")

    def test_dns_udp_through_tun(self):
        # A real DNS query packet for example.com, sent by UDP into the TUN.
        query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x07example\x03com\x00\x00\x01\x00\x01")
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(15)
        u.sendto(query, (FAKE_DNS, 53))
        data, addr = u.recvfrom(512)
        u.close()
        self.assertEqual(addr[0], FAKE_DNS)
        self.assertEqual(data[:2], b"\x12\x34")
        self.assertEqual(data[-4:], socket.inet_aton("93.184.216.34"))

    def test_unreachable_destination_gets_rst(self):
        dead = socket.socket(); dead.bind(("127.0.0.1", 0)); port = dead.getsockname()[1]; dead.close()
        s = socket.create_connection((FAKE_HOST, port), timeout=15)  # SYN-ACK is immediate
        s.settimeout(20)
        with self.assertRaises((ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError)):
            # The engine RSTs once the node reports the connect failure.
            for _ in range(50):
                s.sendall(b"x")
                time.sleep(0.2)
                s.recv(1)
        s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
