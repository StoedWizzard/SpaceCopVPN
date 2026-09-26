"""Streaming relay: multi-round-trip TCP through the overlay, loss recovery,
many concurrent connections, and the SOCKS5 proxy carrying a real
request/response *dialogue* (what HTTPS needs)."""

import os
import random
import socket
import struct
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.node import RelayNode
from spacecop.protocol import constants as c
from spacecop.protocol.messages import StreamAck, StreamData
from spacecop.protocol.stream import StreamEndpoint
from spacecop.tun.socks_proxy import Socks5Proxy


class DialogueServer:
    """A TCP server that needs several round trips per connection:
    for each line 'ping N' it answers 'pong N'; on 'bye' it replies 'ok' and
    closes.  A one-shot request/response relay cannot talk to it."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(512)
        self.host, self.port = self._sock.getsockname()
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
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.startswith(b"ping "):
                        conn.sendall(b"pong " + line[5:] + b"\n")
                    elif line.startswith(b"big "):
                        n = int(line[4:])
                        conn.sendall(struct.pack("!I", n) + bytes(range(256)) * (n // 256) + bytes(n % 256))
                    elif line == b"bye":
                        conn.sendall(b"ok\n")
                        return

    def stop(self):
        self._running = False
        self._sock.close()


def _readline(stream, buf: bytearray) -> bytes:
    while b"\n" not in buf:
        chunk = stream.recv(timeout=20)
        if not chunk:
            raise EOFError
        buf.extend(chunk)
    line, _, rest = bytes(buf).partition(b"\n")
    buf[:] = rest
    return line


class TestStreamEndpointUnit(unittest.TestCase):
    def test_lossy_channel_delivers_in_order(self):
        """Two endpoints over a channel that drops 30% and reorders messages."""
        rnd = random.Random(7)
        a_to_b, b_to_a = [], []
        got_b, got_a = bytearray(), bytearray()
        eof = {"a": False, "b": False}

        a = StreamEndpoint(b"s" * 8, lambda f: a_to_b.append(f), got_a.extend,
                           lambda: eof.__setitem__("a", True), lambda w: None, chunk_size=100, window=8)
        b = StreamEndpoint(b"s" * 8, lambda f: b_to_a.append(f), got_b.extend,
                           lambda: eof.__setitem__("b", True), lambda w: None, chunk_size=100, window=8)
        # note: A's on_deliver appends to got_a? No — A *receives* into got_a.
        # Wire semantics: frames A emits go to B and vice versa.

        from spacecop.protocol import framing

        def pump(queue_, dest):
            rnd.shuffle(queue_)
            while queue_:
                frame = queue_.pop()
                if rnd.random() < 0.3:
                    continue  # lost
                msg_type, body = framing.decode_frame(frame)
                if msg_type == c.MSG_STREAM_DATA:
                    dest.on_data(StreamData.decode(body))
                elif msg_type == c.MSG_STREAM_ACK:
                    dest.on_ack(StreamAck.decode(body))

        payload = os.urandom(5000)
        sender = threading.Thread(target=lambda: (a.send(payload), a.send_fin()), daemon=True)
        sender.start()
        deadline = time.monotonic() + 30
        fake_now = time.monotonic()
        while time.monotonic() < deadline and not (eof["b"] and a.both_directions_done or eof["b"] and a.in_flight() == 0):
            pump(a_to_b, b)
            pump(b_to_a, a)
            fake_now += 0.5  # advance time so retransmits fire
            a.tick(fake_now)
            b.tick(fake_now)
            time.sleep(0.005)
        self.assertEqual(bytes(got_b), payload)
        self.assertTrue(eof["b"])


class TestStreamingRelay(unittest.TestCase):
    def setUp(self):
        self.server = DialogueServer()
        self.node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        self.node.start()
        self.client = VPNClient(bind_host="127.0.0.1")
        self.client.start()
        self.client.connect(self.node.identity.x_public, self.node.address,
                            expected_node_ed=self.node.identity.ed_public)

    def tearDown(self):
        self.client.stop()
        self.node.stop()
        self.server.stop()

    def test_multi_round_trip_dialogue(self):
        s = self.client.open_stream(self.server.host, self.server.port)
        buf = bytearray()
        for i in range(20):
            s.send(b"ping %d\n" % i)
            self.assertEqual(_readline(s, buf), b"pong %d" % i)
        s.send(b"bye\n")
        self.assertEqual(_readline(s, buf), b"ok")
        self.assertEqual(s.recv(timeout=10), b"")  # server closed -> EOF
        s.close()

    def test_large_transfer_both_ways(self):
        s = self.client.open_stream(self.server.host, self.server.port)
        n = 700 * 1024  # 700 KB back -> hundreds of chunks, window cycling
        s.send(b"big %d\n" % n)
        got = bytearray()
        while len(got) < 4 + n:
            chunk = s.recv(timeout=30)
            self.assertTrue(chunk, "EOF before the whole payload arrived")
            got.extend(chunk)
        self.assertEqual(struct.unpack("!I", bytes(got[:4]))[0], n)
        expected = bytes(range(256)) * (n // 256) + bytes(n % 256)
        self.assertEqual(bytes(got[4:4 + n]), expected)
        s.send(b"bye\n")
        s.close()

    def test_connect_failure_reported(self):
        from spacecop.client import RelayTimeout
        dead = socket.socket(); dead.bind(("127.0.0.1", 0)); port = dead.getsockname()[1]; dead.close()
        with self.assertRaises(RelayTimeout):
            self.client.open_stream("127.0.0.1", port, timeout=8)

    def test_many_concurrent_streams(self):
        def one(i):
            s = self.client.open_stream(self.server.host, self.server.port)
            buf = bytearray()
            try:
                for k in range(5):
                    s.send(b"ping %d-%d\n" % (i, k))
                    if _readline(s, buf) != b"pong %d-%d" % (i, k):
                        return False
                s.send(b"bye\n")
                return _readline(s, buf) == b"ok"
            finally:
                s.close()
        with ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(one, range(120)))
        self.assertTrue(all(results), f"{results.count(False)} streams failed")
        self.assertGreater(self.node.score(), 0)  # receipts issued for streams


class TestSocksStreaming(unittest.TestCase):
    def setUp(self):
        self.server = DialogueServer()
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
        self.server.stop()

    def _socks_connect(self, host, port):
        s = socket.create_connection(self.proxy.address, timeout=10)
        s.sendall(bytes([0x05, 0x01, 0x00]))
        self.assertEqual(s.recv(2), bytes([0x05, 0x00]))
        hb = host.encode()
        s.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(hb)]) + hb + struct.pack("!H", port))
        reply = s.recv(10)
        self.assertEqual(reply[1], 0x00, "SOCKS CONNECT failed")
        return s

    def test_dialogue_through_socks(self):
        s = self._socks_connect("127.0.0.1", self.server.port)
        f = s.makefile("rwb", buffering=0)
        for i in range(10):
            f.write(b"ping %d\n" % i)
            self.assertEqual(f.readline(), b"pong %d\n" % i)
        f.write(b"bye\n")
        self.assertEqual(f.readline(), b"ok\n")
        self.assertEqual(f.read(), b"")  # EOF propagated
        s.close()

    def test_unreachable_destination_socks_error(self):
        dead = socket.socket(); dead.bind(("127.0.0.1", 0)); port = dead.getsockname()[1]; dead.close()
        s = socket.create_connection(self.proxy.address, timeout=15)
        s.sendall(bytes([0x05, 0x01, 0x00])); s.recv(2)
        s.sendall(bytes([0x05, 0x01, 0x00, 0x01]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", port))
        reply = s.recv(10)
        self.assertNotEqual(reply[1], 0x00)
        s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
