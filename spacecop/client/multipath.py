"""Node selection across multiple competing connections.

The client keeps sessions to several nodes at once.  For each request it picks
one, and it tracks how each node performs (latency, bytes served, failures).
This is where the competition plays out: nodes that answer faster and carry
more traffic are chosen more often and, via the receipts the client issues,
accumulate more points.  Fragment-level striping across nodes is a documented
extension (see docs/ARCHITECTURE.md); this selector distributes at the request
level, which keeps reassembly simple and correct.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional

from ..protocol import Session
from ..transport import Address

_sysrandom = random.SystemRandom()


@dataclass
class NodeConnection:
    session: Session
    addr: Address
    node_ed_public: bytes = b""

    # Live performance stats used for selection.
    requests: int = 0
    failures: int = 0
    bytes_served: int = 0
    ewma_latency: float = 0.0  # exponentially-weighted moving average, seconds

    def node_id_hex(self) -> str:
        return self.node_ed_public.hex()[:16] if self.node_ed_public else "unknown"

    def health_score(self) -> float:
        """Higher is better. Rewards low latency and penalises failures."""
        latency = self.ewma_latency if self.ewma_latency > 0 else 0.05
        reliability = 1.0 - (self.failures / (self.requests + 1))
        return reliability / latency


class NodeSelector:
    def __init__(self, epsilon: float = 0.15):
        # epsilon: fraction of requests routed to a random node to keep
        # exploring alternatives rather than starving newcomers.
        self.epsilon = epsilon
        self._conns: List[NodeConnection] = []

    def add(self, conn: NodeConnection) -> None:
        self._conns.append(conn)

    def remove(self, conn: NodeConnection) -> None:
        if conn in self._conns:
            self._conns.remove(conn)

    def choose(self) -> Optional[NodeConnection]:
        if not self._conns:
            return None
        if len(self._conns) == 1:
            return self._conns[0]
        # Epsilon-greedy: mostly exploit the best node, sometimes explore.
        if _sysrandom.random() < self.epsilon:
            return _sysrandom.choice(self._conns)
        return max(self._conns, key=lambda c: c.health_score())

    def record_success(self, conn: NodeConnection, latency: float, byte_count: int) -> None:
        conn.requests += 1
        conn.bytes_served += byte_count
        alpha = 0.3
        if conn.ewma_latency == 0.0:
            conn.ewma_latency = latency
        else:
            conn.ewma_latency = alpha * latency + (1 - alpha) * conn.ewma_latency

    def record_failure(self, conn: NodeConnection) -> None:
        conn.requests += 1
        conn.failures += 1

    def ranking(self) -> List[NodeConnection]:
        return sorted(self._conns, key=lambda c: c.health_score(), reverse=True)
