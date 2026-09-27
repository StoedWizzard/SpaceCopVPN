"""Node selection across multiple competing connections, with per-site pinning.

The client keeps sessions to several nodes at once.  For each request it picks
one, and it tracks how each node performs (latency, bytes served, failures).
This is where the competition plays out: nodes that answer faster and carry
more traffic are chosen more often and, via the receipts the client issues,
accumulate more points.

**IP consistency per site.**  A web site makes many requests during one visit
and often ties a login/session to the client's IP.  If every request left
through a different exit node the site would see the IP change constantly and
could log the user out or flag the session.  The selector therefore *pins* each
site (registrable domain, e.g. ``example.com`` for ``cdn.example.com``, or the
literal IP) to the node first chosen for it, and keeps using that node for the
whole session.  The pin is only broken when that node fails or has been idle
for a long time, in which case a new node is chosen and pinned.

Fragment-level striping across nodes is a documented extension (see
docs/ARCHITECTURE.md); this selector distributes at the request level, which
keeps reassembly simple and correct.
"""

from __future__ import annotations

import ipaddress
import random
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..protocol import Session
from ..transport import Address

_sysrandom = random.SystemRandom()

# A site pin is dropped after this much idle time so a long-dead node does not
# keep a site captive, and so load can rebalance between visits.
PIN_IDLE_TTL = 30 * 60.0


def site_key(host: str) -> str:
    """Collapse a hostname to the identity of the *site* it belongs to.

    ``cdn.example.com`` and ``api.example.com`` map to ``example.com`` so all
    of a site's subdomains leave through the same node.  IP literals are used
    as-is.  This is a pragmatic heuristic (it treats ``co.uk``-style suffixes
    as two labels); it errs on the side of grouping, which is the safe
    direction for IP consistency.
    """
    host = host.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])


MIN_LATENCY = 0.005   # 5 ms floor: keeps health finite and comparable
HEALTH_CAP = 100.0    # health = reliability / latency, capped for display sanity


@dataclass(eq=False)  # identity semantics: usable in sets, compared by object
class NodeConnection:
    session: Session
    addr: Address
    node_ed_public: bytes = b""
    x_public: bytes = b""      # node's X25519 key (lets us rebuild its URI)

    # Live performance stats used for selection.
    requests: int = 0
    failures: int = 0
    bytes_served: int = 0
    ewma_latency: float = 0.0  # exponentially-weighted moving average, seconds

    def node_id_hex(self) -> str:
        return self.node_ed_public.hex()[:16] if self.node_ed_public else "unknown"

    def uri(self) -> str:
        from ..protocol.uri import build_uri
        return build_uri(self.addr[0], self.addr[1], self.x_public, self.node_ed_public)

    def health_score(self) -> float:
        """Higher is better (0..100). Rewards low latency, penalises failures."""
        latency = max(self.ewma_latency, MIN_LATENCY) if self.ewma_latency > 0 else 0.05
        reliability = 1.0 - (self.failures / (self.requests + 1))
        return min(HEALTH_CAP, reliability / latency)


@dataclass
class _Pin:
    conn: NodeConnection
    last_used: float


class NodeSelector:
    def __init__(self, epsilon: float = 0.15, pin_idle_ttl: float = PIN_IDLE_TTL):
        # epsilon: fraction of *new-site* decisions routed to a random node to
        # keep exploring alternatives rather than starving newcomers.  Pinned
        # sites are never re-rolled by exploration.
        self.epsilon = epsilon
        self.pin_idle_ttl = pin_idle_ttl
        self._conns: List[NodeConnection] = []
        self._pins: Dict[str, _Pin] = {}
        self._lock = threading.Lock()

    # -- membership ---------------------------------------------------------
    def add(self, conn: NodeConnection) -> None:
        with self._lock:
            self._conns.append(conn)

    def remove(self, conn: NodeConnection) -> None:
        with self._lock:
            if conn in self._conns:
                self._conns.remove(conn)
            for key in [k for k, p in self._pins.items() if p.conn is conn]:
                del self._pins[key]

    # -- selection ----------------------------------------------------------
    def choose(self, dest_host: Optional[str] = None,
               exclude: Optional[set] = None) -> Optional[NodeConnection]:
        """Pick a node; the same site always gets the same node while healthy.

        ``exclude`` lists nodes that already failed for this destination (used
        for failover): they are skipped, and a pin pointing at one of them is
        replaced.
        """
        exclude = exclude or set()
        with self._lock:
            candidates = [c for c in self._conns if c not in exclude]
            if not candidates:
                return None
            now = time.monotonic()
            key = site_key(dest_host) if dest_host else None

            if key is not None:
                pin = self._pins.get(key)
                if pin is not None:
                    if (pin.conn in candidates
                            and now - pin.last_used <= self.pin_idle_ttl):
                        pin.last_used = now
                        return pin.conn
                    del self._pins[key]

            conn = self._pick_unpinned(candidates)
            if key is not None:
                self._pins[key] = _Pin(conn=conn, last_used=now)
            return conn

    def _pick_unpinned(self, candidates: List[NodeConnection]) -> NodeConnection:
        if len(candidates) == 1:
            return candidates[0]
        # Epsilon-greedy: mostly exploit the best node, sometimes explore.
        if _sysrandom.random() < self.epsilon:
            return _sysrandom.choice(candidates)
        return max(candidates, key=lambda c: c.health_score())

    def node_count(self) -> int:
        with self._lock:
            return len(self._conns)

    def pinned_node(self, dest_host: str) -> Optional[NodeConnection]:
        with self._lock:
            pin = self._pins.get(site_key(dest_host))
            return pin.conn if pin else None

    # -- feedback -----------------------------------------------------------
    def record_success(self, conn: NodeConnection, latency: Optional[float],
                       byte_count: int) -> None:
        """``latency`` is a real measured round trip in seconds, or None when
        the event carries no timing (e.g. a stream closing).  A zero/None value
        must never feed the average — it would drive it to 0 and health to
        infinity."""
        with self._lock:
            conn.requests += 1
            conn.bytes_served += byte_count
            if latency is None or latency <= 0.0:
                return
            alpha = 0.3
            if conn.ewma_latency == 0.0:
                conn.ewma_latency = latency
            else:
                conn.ewma_latency = alpha * latency + (1 - alpha) * conn.ewma_latency

    def record_failure(self, conn: NodeConnection, dest_host: Optional[str] = None) -> None:
        """A failed relay breaks the site's pin so the next request can move on."""
        with self._lock:
            conn.requests += 1
            conn.failures += 1
            if dest_host is not None:
                key = site_key(dest_host)
                pin = self._pins.get(key)
                if pin is not None and pin.conn is conn:
                    del self._pins[key]

    def ranking(self) -> List[NodeConnection]:
        with self._lock:
            return sorted(self._conns, key=lambda c: c.health_score(), reverse=True)
