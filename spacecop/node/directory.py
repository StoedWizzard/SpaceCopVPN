"""Decentralised peer discovery: a gossiped directory of known nodes.

There is no central server.  A node (or client) starts from a small bootstrap
list, asks those peers for *their* known peers, and merges the signed
announcements it receives.  Over time every participant converges on a view of
the overlay.  Announcements are self-signed (Ed25519), so a gossiped entry
cannot be forged to impersonate another node's identity.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..protocol.messages import NodeAnnounce, PeerEntry, PeerList

_sysrandom = random.SystemRandom()


@dataclass
class PeerInfo:
    ed_public: bytes
    x_public: bytes
    host: str
    port: int
    score: int = 0
    last_seen: float = 0.0

    def address(self):
        return (self.host, self.port)

    def to_entry(self) -> PeerEntry:
        return PeerEntry(self.ed_public, self.x_public, self.host, self.port)


class PeerDirectory:
    def __init__(self, ttl: float = 900.0):
        self.ttl = ttl
        self._peers: Dict[bytes, PeerInfo] = {}

    # -- ingestion ----------------------------------------------------------
    def add_announce(self, announce: NodeAnnounce, observed_host: Optional[str] = None) -> bool:
        """Add/update a peer from a signed announcement. Returns False if invalid."""
        if not announce.verify():
            return False
        host = announce.host
        # If the node advertised a non-routable/unspecified host, fall back to
        # the address we actually observed the packet coming from.
        if observed_host and host in ("0.0.0.0", "", "127.0.0.1", "::"):
            host = observed_host
        info = PeerInfo(
            ed_public=announce.ed_public,
            x_public=announce.x_public,
            host=host,
            port=announce.port,
            score=announce.score,
            last_seen=time.monotonic(),
        )
        self._peers[announce.ed_public] = info
        return True

    def add_peer_entry(self, entry: PeerEntry) -> None:
        """Add a peer learned via a PEER_LIST (identity key, no fresh signature)."""
        existing = self._peers.get(entry.ed_public)
        if existing is None:
            self._peers[entry.ed_public] = PeerInfo(
                ed_public=entry.ed_public, x_public=entry.x_public,
                host=entry.host, port=entry.port, last_seen=time.monotonic(),
            )

    def add_bootstrap(self, host: str, port: int) -> None:
        """Seed an address with no identity yet; a handshake/announce fills it in."""
        placeholder = f"bootstrap:{host}:{port}".encode()[:32].ljust(32, b"\x00")
        if placeholder not in self._peers:
            self._peers[placeholder] = PeerInfo(
                ed_public=placeholder, x_public=b"\x00" * 32,
                host=host, port=port, last_seen=time.monotonic(),
            )

    # -- queries ------------------------------------------------------------
    def peers(self, include_bootstrap: bool = True) -> List[PeerInfo]:
        self.expire()
        result = list(self._peers.values())
        if not include_bootstrap:
            result = [p for p in result if p.x_public != b"\x00" * 32]
        return result

    def known_nodes(self) -> List[PeerInfo]:
        """Fully-identified peers (excludes unresolved bootstrap addresses)."""
        return self.peers(include_bootstrap=False)

    def sample(self, n: int, include_bootstrap: bool = True) -> List[PeerInfo]:
        pool = self.peers(include_bootstrap=include_bootstrap)
        if len(pool) <= n:
            return pool
        return _sysrandom.sample(pool, n)

    def to_peer_list(self, max_peers: int = 32) -> PeerList:
        entries = [p.to_entry() for p in self.known_nodes()[:max_peers]]
        return PeerList(entries)

    def expire(self) -> None:
        now = time.monotonic()
        stale = [k for k, p in self._peers.items()
                 if p.last_seen and now - p.last_seen > self.ttl]
        for k in stale:
            del self._peers[k]

    def __len__(self) -> int:
        return len(self._peers)
