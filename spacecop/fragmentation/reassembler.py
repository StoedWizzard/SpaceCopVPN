"""Reassemble shuffled, possibly-duplicated fragments back into payloads.

The reassembler is fed fragments in whatever order they arrive.  It groups them
by ``group_id`` and, once every index of a group has been seen, concatenates the
fragments in index order to recover the original payload.  It is defensive
about the hostile things a network does:

* **out-of-order** arrival is fine — fragments are stored by index;
* **duplicates** are ignored;
* **inconsistent** metadata (a fragment claiming a different count for a group)
  is rejected;
* **incomplete** groups are expired after a timeout, and the number of
  in-flight groups is capped, so a peer cannot exhaust memory by sending only
  partial groups.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..protocol import constants as c
from .fragmenter import Fragment


class ReassemblyError(Exception):
    """Raised on inconsistent or abusive fragment streams."""


@dataclass
class _Group:
    count: int
    fragments: Dict[int, bytes] = field(default_factory=dict)
    created: float = field(default_factory=time.monotonic)

    def is_complete(self) -> bool:
        return len(self.fragments) == self.count


class Reassembler:
    """Collect fragments and yield completed payloads."""

    def __init__(self, group_timeout: float = 30.0, max_groups: int = 4096):
        self.group_timeout = group_timeout
        self.max_groups = max_groups
        self._groups: Dict[int, _Group] = {}

    # -- ingestion ----------------------------------------------------------
    def add(self, fragment: Fragment) -> Optional[bytes]:
        """Add one fragment; return the full payload if its group is now complete."""
        if fragment.count <= 0 or fragment.count > c.MAX_FRAGMENTS_PER_MESSAGE:
            raise ReassemblyError("invalid fragment count")
        if not 0 <= fragment.index < fragment.count:
            raise ReassemblyError("fragment index out of range")

        self._maybe_expire()

        group = self._groups.get(fragment.group_id)
        if group is None:
            if len(self._groups) >= self.max_groups:
                self._evict_oldest()
            group = _Group(count=fragment.count)
            self._groups[fragment.group_id] = group
        elif group.count != fragment.count:
            raise ReassemblyError("inconsistent fragment count for group")

        # Ignore duplicates rather than trusting a possibly-different copy.
        if fragment.index not in group.fragments:
            group.fragments[fragment.index] = fragment.payload

        if group.is_complete():
            payload = self._assemble(group)
            del self._groups[fragment.group_id]
            return payload
        return None

    def add_bytes(self, data: bytes) -> Optional[bytes]:
        """Decode raw fragment bytes and add them."""
        return self.add(Fragment.decode(data))

    # -- introspection ------------------------------------------------------
    def missing_indices(self, group_id: int) -> List[int]:
        """Which indices of an in-flight group have not yet arrived."""
        group = self._groups.get(group_id)
        if group is None:
            return []
        return [i for i in range(group.count) if i not in group.fragments]

    def pending_groups(self) -> int:
        return len(self._groups)

    # -- internals ----------------------------------------------------------
    @staticmethod
    def _assemble(group: _Group) -> bytes:
        return b"".join(group.fragments[i] for i in range(group.count))

    def _maybe_expire(self) -> None:
        if not self._groups:
            return
        now = time.monotonic()
        stale = [gid for gid, g in self._groups.items()
                 if now - g.created > self.group_timeout]
        for gid in stale:
            del self._groups[gid]

    def _evict_oldest(self) -> None:
        oldest = min(self._groups.items(), key=lambda kv: kv[1].created)[0]
        del self._groups[oldest]
