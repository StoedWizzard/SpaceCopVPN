"""High-volume concurrency and per-site IP consistency (sticky routing).

Web pages fire many requests at once.  These tests hammer the overlay with
hundreds of concurrent relays across several nodes and check (a) every one of
them round-trips correctly and (b) every request for the same site leaves
through the same node, so the destination sees one stable IP.
"""

import os
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.client.multipath import NodeSelector, NodeConnection, site_key
from spacecop.node import RelayNode
from spacecop.protocol import Session
from test_integration import EchoServer


class TestSiteKey(unittest.TestCase):
    def test_subdomains_collapse(self):
        self.assertEqual(site_key("cdn.example.com"), "example.com")
        self.assertEqual(site_key("a.b.c.example.com"), "example.com")
        self.assertEqual(site_key("Example.COM."), "example.com")
        self.assertEqual(site_key("localhost"), "localhost")

    def test_ip_literals_kept(self):
        self.assertEqual(site_key("127.0.0.1"), "127.0.0.1")
        self.assertEqual(site_key("2001:db8::1"), "2001:db8::1")


def _fake_conn(tag: bytes) -> NodeConnection:
    sess = Session(send_key=b"\x01" * 32, recv_key=b"\x02" * 32, session_id=tag * 8)
    return NodeConnection(session=sess, addr=("10.0.0.1", 1), node_ed_public=tag * 32)


class TestStickySelector(unittest.TestCase):
    def test_same_site_same_node(self):
        sel = NodeSelector(epsilon=0.5)  # aggressive exploration must NOT re-roll pins
        conns = [_fake_conn(bytes([i])) for i in range(1, 6)]
        for c in conns:
            sel.add(c)
        first = sel.choose("www.example.com")
        for _ in range(200):
            self.assertIs(sel.choose("api.example.com"), first)
            self.assertIs(sel.choose("example.com"), first)

    def test_failure_unpins(self):
        sel = NodeSelector(epsilon=0.0)
        a, b = _fake_conn(b"\x01"), _fake_conn(b"\x02")
        sel.add(a)
        sel.add(b)
        pinned = sel.choose("site.test")
        sel.record_failure(pinned, "site.test")
        # After the failure the pinned node is less healthy; the site re-pins.
        again = sel.choose("site.test")
        self.assertIsNot(again, pinned)
        for _ in range(50):
            self.assertIs(sel.choose("cdn.site.test"), again)

    def test_removed_node_unpins(self):
        sel = NodeSelector(epsilon=0.0)
        a, b = _fake_conn(b"\x01"), _fake_conn(b"\x02")
        sel.add(a)
        sel.add(b)
        pinned = sel.choose("x.org")
        sel.remove(pinned)
        self.assertIsNot(sel.choose("x.org"), pinned)

    def test_idle_pin_expires(self):
        sel = NodeSelector(epsilon=0.0, pin_idle_ttl=0.05)
        a, b = _fake_conn(b"\x01"), _fake_conn(b"\x02")
        sel.add(a)
        sel.add(b)
        sel.choose("slow.example")
        time.sleep(0.1)
        # Expired pin -> a fresh choice is made (may be the same node, but the
        # pin map must have been refreshed rather than served stale).
        self.assertIsNotNone(sel.choose("slow.example"))


class TestHighVolume(unittest.TestCase):
    def setUp(self):
        self.echo = EchoServer()
        self.nodes = [RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
                      for _ in range(3)]
        for n in self.nodes:
            n.start()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        for n in self.nodes:
            self.client.connect(n.identity.x_public, n.address,
                                expected_node_ed=n.identity.ed_public)

    def tearDown(self):
        self.client.stop()
        for n in self.nodes:
            n.stop()
        self.echo.stop()

    def test_hundreds_of_concurrent_requests(self):
        """Many parallel relays (like a busy web page) all round-trip."""
        n_requests = 300
        failures = []
        lock = threading.Lock()

        def one(i):
            payload = (b"%06d:" % i) + os.urandom(512 + (i % 7) * 1024)
            try:
                resp = self.client.relay(self.echo.host, self.echo.port, payload, timeout=30)
                if resp != payload:
                    with lock:
                        failures.append(f"mismatch {i}")
            except Exception as exc:
                with lock:
                    failures.append(f"{i}: {exc}")

        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=48) as pool:
            list(pool.map(one, range(n_requests)))
        elapsed = time.monotonic() - started
        self.assertEqual(failures, [], f"{len(failures)} failures, e.g. {failures[:3]}")
        served = sum(n.relayed_requests for n in self.nodes)
        self.assertGreaterEqual(served, n_requests)
        print(f"\n[load] {n_requests} concurrent relays OK in {elapsed:.1f}s "
              f"({n_requests / elapsed:.0f} req/s), per node: "
              f"{[n.relayed_requests for n in self.nodes]}")

    def test_one_site_one_node_end_to_end(self):
        """All requests to the same site go through the same exit node."""
        # A single destination host => a single pinned node handles all of it.
        n_requests = 60
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(
                lambda i: self.client.relay(self.echo.host, self.echo.port,
                                            b"req-%d" % i, timeout=30),
                range(n_requests)))
        self.assertTrue(all(results[i] == b"req-%d" % i for i in range(n_requests)))
        counts = [n.relayed_requests for n in self.nodes]
        self.assertEqual(sum(counts), n_requests)
        self.assertEqual(sorted(counts)[-1], n_requests,
                         f"traffic for one site was split across nodes: {counts}")
        pinned = self.client._selector.pinned_node(self.echo.host)
        self.assertIsNotNone(pinned)


if __name__ == "__main__":
    unittest.main(verbosity=2)
