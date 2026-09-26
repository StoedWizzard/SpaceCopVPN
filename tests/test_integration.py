"""End-to-end integration over real UDP/TCP sockets on loopback.

Spins up an echo destination, one or more relay nodes, and a client, then
relays fragmented+shuffled+encrypted payloads and checks the results and the
scoring.
"""

import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.node import RelayNode


class EchoServer:
    """A tiny TCP server that echoes back everything it receives."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.host, self.port = self._sock.getsockname()
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

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
            data = b""
            conn.settimeout(2.0)
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            conn.sendall(data)  # echo everything back

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.echo = EchoServer()
        self.nodes = []
        self.client = None

    def tearDown(self):
        if self.client:
            self.client.stop()
        for n in self.nodes:
            n.stop()
        self.echo.stop()

    def _start_node(self):
        node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        node.start()
        self.nodes.append(node)
        return node

    def test_single_node_relay_small(self):
        node = self._start_node()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(node.identity.x_public, node.address,
                            expected_node_ed=node.identity.ed_public)
        payload = b"GET / HTTP/1.0\r\n\r\n"
        response = self.client.relay(self.echo.host, self.echo.port, payload)
        self.assertEqual(response, payload)

    def test_single_node_relay_large_fragmented(self):
        node = self._start_node()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(node.identity.x_public, node.address,
                            expected_node_ed=node.identity.ed_public)
        # 130 KB payload -> 7 fragments each way, shuffled and encrypted.
        payload = os.urandom(130 * 1024)
        response = self.client.relay(self.echo.host, self.echo.port, payload, timeout=20)
        self.assertEqual(response, payload)

    def test_node_earns_points(self):
        node = self._start_node()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(node.identity.x_public, node.address,
                            expected_node_ed=node.identity.ed_public)
        payload = os.urandom(50 * 1024)
        self.client.relay(self.echo.host, self.echo.port, payload)
        # The receipt is sent asynchronously over UDP; give it a moment.
        deadline = time.time() + 3.0
        while time.time() < deadline and node.score() == 0:
            time.sleep(0.05)
        self.assertGreater(node.score(), 0)
        standing = node.ledger.standing(node.identity.ed_public)
        self.assertEqual(standing.receipts, 1)

    def test_multiple_nodes_compete(self):
        node_a = self._start_node()
        node_b = self._start_node()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(node_a.identity.x_public, node_a.address,
                            expected_node_ed=node_a.identity.ed_public)
        self.client.connect(node_b.identity.x_public, node_b.address,
                            expected_node_ed=node_b.identity.ed_public)
        # Fire many requests; the selector distributes them across both nodes.
        for _ in range(12):
            payload = os.urandom(4096)
            resp = self.client.relay(self.echo.host, self.echo.port, payload)
            self.assertEqual(resp, payload)
        time.sleep(0.5)
        total = node_a.score() + node_b.score()
        self.assertGreater(total, 0)
        # Both nodes should have served at least one request between them.
        self.assertGreaterEqual(node_a.relayed_requests + node_b.relayed_requests, 12)

    def test_identity_mismatch_rejected(self):
        node = self._start_node()
        other = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        from spacecop.client import RelayTimeout
        # Present the real node's DH key but claim to expect a different identity.
        with self.assertRaises((RelayTimeout, Exception)):
            self.client.connect(node.identity.x_public, node.address,
                                expected_node_ed=other.identity.ed_public,
                                timeout=2.0)
        other.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
