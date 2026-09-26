"""Self-contained demo: several competing nodes, a client, and a leaderboard.

Runs entirely on loopback with no privileges or external network.  It starts an
echo destination, launches several relay nodes, connects a client to all of
them, fires a batch of requests (which the client distributes across the
competing nodes), and prints the resulting score leaderboard.

    python examples/local_demo.py
"""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.node import RelayNode
from spacecop.node.scoring import Ledger


class EchoServer:
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
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
            conn.settimeout(2.0)
            data = b""
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            conn.sendall(data)

    def stop(self):
        self._running = False
        self._sock.close()


def main():
    print("SpaceCopVPN local demo")
    print("=" * 60)
    echo = EchoServer()
    print(f"echo destination on 127.0.0.1:{echo.port}")

    n_nodes = 4
    nodes = []
    for i in range(n_nodes):
        node = RelayNode(bind_host="127.0.0.1", advertised_host="127.0.0.1")
        node.start()
        nodes.append(node)
        print(f"node {i}: {node.node_id_hex} on udp/{node.address[1]}")

    client = VPNClient(bind_host="127.0.0.1")
    client.start()
    print(f"client identity {client.ed_public.hex()[:16]}")
    for node in nodes:
        client.connect(node.identity.x_public, node.address,
                       expected_node_ed=node.identity.ed_public)
    print(f"client connected to {len(client.connections())} competing nodes\n")

    n_requests = 40
    print(f"sending {n_requests} relayed requests (fragmented, shuffled, encrypted)...")
    total_bytes = 0
    for i in range(n_requests):
        payload = os.urandom((i % 5 + 1) * 15 * 1024)  # 15..75 KB
        response = client.relay(echo.host, echo.port, payload, timeout=20)
        assert response == payload, "round-trip mismatch!"
        total_bytes += len(payload)
    print(f"all {n_requests} requests round-tripped correctly "
          f"({total_bytes // 1024} KB relayed each way)\n")

    # Let the asynchronous receipts settle.
    time.sleep(1.0)

    # Build a combined view of the competition from each node's self-score.
    print("Leaderboard (nodes compete for points by relaying traffic):")
    print("-" * 60)
    standings = []
    for i, node in enumerate(nodes):
        standing = node.ledger.standing(node.identity.ed_public)
        standings.append((i, node, standing))
    standings.sort(key=lambda t: t[2].points, reverse=True)
    print(f"{'rank':<5}{'node':<20}{'points':<10}{'requests':<10}{'MB relayed':<12}")
    for rank, (idx, node, standing) in enumerate(standings, 1):
        mb = standing.total_bytes / (1024 * 1024)
        print(f"{rank:<5}{node.node_id_hex:<20}{standing.points:<10}"
              f"{node.relayed_requests:<10}{mb:<12.2f}")

    print("\nclient's view of node health (latency-ranked):")
    for conn in client._selector.ranking():
        print(f"  {conn.node_id_hex():<20} health={conn.health_score():8.1f} "
              f"reqs={conn.requests} avg_latency={conn.ewma_latency*1000:.1f}ms")

    client.stop()
    for node in nodes:
        node.stop()
    echo.stop()
    print("\ndemo complete.")


if __name__ == "__main__":
    main()
