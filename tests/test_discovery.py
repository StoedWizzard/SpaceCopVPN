"""Client-side node discovery: one URI is enough to reach the whole overlay."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.node import RelayNode


def _wait(predicate, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        # A is the seed; B and C bootstrap from A, so A's directory learns them
        # through their announcements (gossip between nodes).
        self.a = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.a.start()
        self.b = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.c = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.b.start(bootstrap=[self.a.address])
        self.c.start(bootstrap=[self.a.address])
        self.assertTrue(_wait(lambda: len(self.a.directory.known_nodes()) >= 2, 10),
                        "gossip: A never learned B and C")
        self.events = []
        self.client = None

    def tearDown(self):
        if self.client:
            self.client.stop()
        for n in (self.a, self.b, self.c):
            n.stop()

    def _ids(self):
        return {c.node_ed_public for c in self.client.connections()}

    def test_one_uri_discovers_all_nodes(self):
        self.client = VPNClient(bind_host="127.0.0.1", on_event=self.events.append)
        self.client.start()
        self.client.connect(self.a.identity.x_public, self.a.address,
                            expected_node_ed=self.a.identity.ed_public)
        self.assertTrue(_wait(lambda: len(self._ids()) == 3, 15),
                        f"discovered only {len(self._ids())} nodes; events: {self.events}")
        self.assertEqual(self._ids(), {self.a.identity.ed_public, self.b.identity.ed_public,
                                       self.c.identity.ed_public})
        self.assertTrue(any("discovered node" in e for e in self.events))
        # Discovered connections are verified against the gossiped identity key.
        for conn in self.client.connections():
            self.assertTrue(conn.node_ed_public)

    def test_discovery_can_be_disabled(self):
        self.client = VPNClient(bind_host="127.0.0.1", discovery_enabled=False)
        self.client.start()
        self.client.connect(self.a.identity.x_public, self.a.address,
                            expected_node_ed=self.a.identity.ed_public)
        time.sleep(2.5)
        self.assertEqual(len(self._ids()), 1)

    def test_max_auto_nodes_cap(self):
        self.client = VPNClient(bind_host="127.0.0.1", max_auto_nodes=2)
        self.client.start()
        self.client.connect(self.a.identity.x_public, self.a.address,
                            expected_node_ed=self.a.identity.ed_public)
        time.sleep(3.0)
        self.assertLessEqual(len(self._ids()), 2)

    def test_no_duplicate_connections(self):
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(self.a.identity.x_public, self.a.address,
                            expected_node_ed=self.a.identity.ed_public)
        self.assertTrue(_wait(lambda: len(self._ids()) == 3, 15))
        # Repeated pulls must not open second sessions to already-known nodes.
        for _ in range(3):
            self.client.request_peers()
            time.sleep(0.5)
        time.sleep(1.0)
        self.assertEqual(len(self.client.connections()), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
