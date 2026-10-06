"""Diagnostics: PING reachability, handshake rejection reasons, INIT retransmit."""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import RelayTimeout, VPNClient
from spacecop.node import RelayNode
from spacecop.protocol import HandshakeError


class TestDiagnostics(unittest.TestCase):
    def setUp(self):
        self.node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.node.start()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()

    def tearDown(self):
        self.client.stop()
        self.node.stop()

    def test_ping_reachable(self):
        rtt = self.client.ping(self.node.address, timeout=3.0)
        self.assertIsNotNone(rtt)
        self.assertLess(rtt, 3.0)

    def test_probe_reports_node_version(self):
        from spacecop import __version__
        rtt, version = self.client.probe(self.node.address, timeout=3.0)
        self.assertIsNotNone(rtt)
        self.assertEqual(version, __version__)

    def test_probe_old_node_has_no_version(self):
        """A pre-0.2.0 node echoes the PING body verbatim: version must be ''."""
        from spacecop.protocol import constants as c, framing
        node_send = self.node.transport.send

        def legacy_send(data, addr):
            msg_type, body = framing.decode_frame(data)
            if msg_type == c.MSG_PONG:
                data = framing.encode_frame(c.MSG_PONG, body[:8])  # old behaviour
            node_send(data, addr)
        self.node.transport.send = legacy_send
        rtt, version = self.client.probe(self.node.address, timeout=3.0)
        self.assertIsNotNone(rtt)
        self.assertEqual(version, "")

    def test_ping_unreachable(self):
        # A bound-but-unused UDP port: nothing answers.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        try:
            self.assertIsNone(self.client.ping(s.getsockname(), timeout=1.0, attempts=2))
        finally:
            s.close()

    def test_rejection_reason_reported(self):
        """A node that rejects the handshake tells the client why (MSG_ERROR)."""
        def reject(_body):
            raise HandshakeError("handshake timestamp skew too large (999s)")
        self.node._handshaker.handle_init = reject
        with self.assertRaises(HandshakeError) as ctx:
            self.client.connect(self.node.identity.x_public, self.node.address, timeout=3.0)
        self.assertIn("node rejected the handshake", str(ctx.exception))
        self.assertIn("skew", str(ctx.exception))

    def test_init_retransmit_survives_first_loss(self):
        """Dropping the first INIT must not fail the handshake."""
        original = self.node._handshaker.handle_init
        calls = {"n": 0}

        def flaky(body):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated loss")  # node acts as if it never got it
            return original(body)
        self.node._handshaker.handle_init = flaky
        # The RuntimeError path sends MSG_ERROR; make it a true silent drop instead:
        node_send = self.node.transport.send

        def send_no_error(data, addr):
            from spacecop.protocol import constants as c, framing
            try:
                msg_type, _ = framing.decode_frame(data)
            except Exception:
                msg_type = None
            if msg_type == c.MSG_ERROR and calls["n"] == 1:
                return  # swallow the error for the first (lost) INIT
            node_send(data, addr)
        self.node.transport.send = send_no_error

        conn = self.client.connect(self.node.identity.x_public, self.node.address,
                                   expected_node_ed=self.node.identity.ed_public, timeout=5.0)
        self.assertGreaterEqual(calls["n"], 2)
        self.assertEqual(conn.node_ed_public, self.node.identity.ed_public)

    def test_timeout_message_is_explanatory(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        try:
            with self.assertRaises(RelayTimeout) as ctx:
                self.client.connect(self.node.identity.x_public, s.getsockname(), timeout=1.5)
            self.assertIn("firewall", str(ctx.exception))
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
