"""End-to-end test of the SOCKS5 proxy tunnelling through a relay node."""

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.node import RelayNode
from spacecop.tun.socks_proxy import Socks5Proxy

# Reuse the echo server from the integration tests.
from test_integration import EchoServer


class TestSocksProxy(unittest.TestCase):
    def setUp(self):
        self.echo = EchoServer()
        self.node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.node.start()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(self.node.identity.x_public, self.node.address,
                            expected_node_ed=self.node.identity.ed_public)
        self.proxy = Socks5Proxy(self.client, listen_host="127.0.0.1", listen_port=0)
        self.proxy.start()

    def tearDown(self):
        self.proxy.stop()
        self.client.stop()
        self.node.stop()
        self.echo.stop()

    def _socks_connect(self, proxy_addr, dest_host, dest_port):
        s = socket.create_connection(proxy_addr, timeout=5)
        # Greeting: version 5, 1 method, no-auth (0x00).
        s.sendall(bytes([0x05, 0x01, 0x00]))
        self.assertEqual(s.recv(2), bytes([0x05, 0x00]))
        # CONNECT request with a domain/IP address.
        host_bytes = dest_host.encode()
        req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + struct.pack("!H", dest_port)
        s.sendall(req)
        reply = s.recv(10)
        self.assertEqual(reply[0], 0x05)
        self.assertEqual(reply[1], 0x00)  # success
        return s

    def test_socks_tunnel_roundtrip(self):
        s = self._socks_connect(self.proxy.address, "127.0.0.1", self.echo.port)
        payload = b"hello through the overlay " * 50
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)  # signal end of request so the gather completes
        received = b""
        s.settimeout(5)
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                received += chunk
        except socket.timeout:
            pass
        s.close()
        self.assertEqual(received, payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
