"""The decentralised scoring ledger — nodes earn points for relaying traffic.

Every time a node relays data for a client, the client hands back a *signed
receipt* (see :class:`spacecop.protocol.messages.Receipt`).  A node collects
these receipts as proof of the useful work it performed; its score is derived
from the total volume it has demonstrably relayed.  Because each receipt is
signed by the client and carries a per-client sequence number, the ledger can:

* **verify** a receipt actually came from the client that issued it, and
* **deduplicate** so the same relayed bytes are never counted twice.

Nodes compete: more relayed traffic means more points and a higher rank on the
leaderboard.  This is a proof-of-*useful*-work analogue of mining — the scarce
resource being spent is real bandwidth and uptime rather than hash power.

See docs/SCORING.md for the trust model and its limitations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ..protocol import constants as c
from ..protocol.messages import Receipt

# One point per fragment-sized unit of relayed data (20 KB), rounded up, so
# that any relayed traffic earns at least one point.
BYTES_PER_POINT = c.FRAGMENT_SIZE


def points_for_bytes(byte_count: int) -> int:
    if byte_count <= 0:
        return 0
    return (byte_count + BYTES_PER_POINT - 1) // BYTES_PER_POINT


@dataclass
class NodeStanding:
    ed_public: bytes
    points: int = 0
    total_bytes: int = 0
    receipts: int = 0
    _seen: Dict[Tuple[bytes, int], int] = field(default_factory=dict, repr=False)

    def hex_id(self) -> str:
        return self.ed_public.hex()[:16]


class Ledger:
    """Tracks verified, de-duplicated receipts and ranks nodes by points."""

    def __init__(self):
        self._standings: Dict[bytes, NodeStanding] = {}
        self.rejected = 0     # receipts that failed verification
        self.duplicates = 0   # receipts that were already counted

    def record(self, receipt: Receipt) -> bool:
        """Verify and count a receipt.

        Returns True if it added new score, False if invalid or a duplicate.
        """
        if not receipt.verify():
            self.rejected += 1
            return False

        standing = self._standings.get(receipt.node_ed_public)
        if standing is None:
            standing = NodeStanding(ed_public=receipt.node_ed_public)
            self._standings[receipt.node_ed_public] = standing

        key = (receipt.client_ed_public, receipt.seq)
        if key in standing._seen:
            self.duplicates += 1
            return False

        standing._seen[key] = receipt.byte_count
        standing.total_bytes += receipt.byte_count
        standing.points += points_for_bytes(receipt.byte_count)
        standing.receipts += 1
        return True

    def score(self, node_ed_public: bytes) -> int:
        standing = self._standings.get(node_ed_public)
        return standing.points if standing else 0

    def standing(self, node_ed_public: bytes) -> NodeStanding:
        return self._standings.get(node_ed_public, NodeStanding(node_ed_public))

    def leaderboard(self) -> List[NodeStanding]:
        """Nodes ranked by points (descending) — the competition standings."""
        return sorted(self._standings.values(),
                      key=lambda s: (s.points, s.total_bytes), reverse=True)

    def total_nodes(self) -> int:
        return len(self._standings)
