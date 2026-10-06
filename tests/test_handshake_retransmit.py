"""Regression tests for the handshake-retransmit key desync.

On a lossy link (mobile!) the client re-sends its handshake INIT while waiting
for the RESP.  Two defences keep the ends synchronised:

* the client uses a *fresh* handshake (new session id + ephemeral keys) for
  every retransmit, so any RESP the node sends is self-consistent;
* the node answers an exact duplicate INIT (same session id, same client
  ephemeral) with the stored RESP instead of rotating the session keys.

Before these fixes, a stale RESP arriving after a retransmitted INIT left the
client and the node holding different session keys: the handshake reported
success and then every stream timed out with "no answer from node (update the
server)", which is what Android users on cellular networks hit.
"""

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client.vpnclient import VPNClient  # noqa: E402
from spacecop.node.relay import RelayNode  # noqa: E402
from spacecop.protocol import framing, constants as c  # noqa: E402
from spacecop.protocol.handshake import ClientHandshake  # noqa: E402


class TestDuplicateInitNodeSide(unittest.TestCase):
    def setUp(self):
        self.node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.node.start()
        self.addr = self.node.address

    def tearDown(self):
        self.node.stop()

    def _recv_frame(self, sock, timeout=3.0):
        sock.settimeout(timeout)
        data, _ = sock.recvfrom(65535)
        return framing.decode_frame(data)

    def test_duplicate_init_gets_identical_resp_and_one_session(self):
        import socket
        hs = ClientHandshake(self.node.identity.x_public,
                             expected_node_ed_pub=self.node.identity.ed_public)
        init = hs.build_init()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(init, self.addr)
            t1, resp1 = self._recv_frame(sock)
            sock.sendto(init, self.addr)  # exact retransmit
            t2, resp2 = self._recv_frame(sock)
            self.assertEqual(t1, c.MSG_HANDSHAKE_RESP)
            self.assertEqual(t2, c.MSG_HANDSHAKE_RESP)
            # Same stored RESP, not a re-keyed one:
            self.assertEqual(resp1, resp2)
            self.assertEqual(self.node.active_sessions(), 1)
            # And the RESP must still verify into a working session.
            session = hs.consume_response(resp2)
            self.assertEqual(session.session_id, hs.session_id)
        finally:
            sock.close()


class TestStaleRespClientSide(unittest.TestCase):
    """A RESP from an earlier attempt arrives after later INITs were sent."""

    def test_stream_works_when_stale_resp_wins(self):
        node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        node.start()
        client = VPNClient(discovery_enabled=False)
        client.start()
        try:
            # Swallow every handshake RESP; deliver the first one at t=1.4s,
            # after the client has retransmitted (fresh INIT at t=1s).
            orig = client._handle_handshake_resp
            held = []

            def swallow(body):
                held.append(body)

            client._handle_handshake_resp = swallow

            def deliver_late():
                time.sleep(1.4)
                orig(held[0])

            threading.Thread(target=deliver_late, daemon=True).start()
            conn = client.connect(node.identity.x_public, node.address,
                                  expected_node_ed=node.identity.ed_public,
                                  timeout=8.0)
            # The accepted RESP and the node's session for it must agree:
            # opening a stream gets a real answer (status 2 = connect refused
            # here, but an *answer* — before the fix this timed out).
            try:
                client.open_stream("127.0.0.1", 9, timeout=6.0)
                self.fail("port 9 should be refused, but an answer must arrive")
            except Exception as exc:
                self.assertNotIn("no answer from node", str(exc))
                self.assertIn("could not connect", str(exc))
        finally:
            client.stop()
            node.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
