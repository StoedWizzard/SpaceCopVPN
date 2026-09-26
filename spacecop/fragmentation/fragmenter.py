"""Split a payload into fixed-size fragments emitted in random order.

The VPN transmits every payload as a set of equal-size fragments (20 KB by
default).  The fragments of one payload share a random 4-byte *group id* and
are numbered 0..count-1.  The fragmenter returns them **shuffled**, so the
order on the wire reveals nothing about the original byte order; the receiver
uses the index to put them back together (see :mod:`.reassembler`).

Fragment wire layout (this is the plaintext that the session layer then
encrypts individually)::

    +----------+--------+--------+------------------+
    | group_id | count  | index  | fragment payload |
    | 4 B      | 4 B    | 4 B    | <= FRAGMENT_SIZE |
    +----------+--------+--------+------------------+
"""

from __future__ import annotations

import os
import random
import struct
from dataclasses import dataclass
from typing import List

from ..protocol import constants as c

FRAGMENT_HEADER_SIZE = 12  # group_id(4) + count(4) + index(4)

# A cryptographically-seeded RNG for the shuffle so the emission order is not
# predictable from outside.
_sysrandom = random.SystemRandom()


@dataclass
class Fragment:
    group_id: int
    count: int
    index: int
    payload: bytes

    def encode(self) -> bytes:
        return struct.pack("!III", self.group_id, self.count, self.index) + self.payload

    @staticmethod
    def decode(data: bytes) -> "Fragment":
        if len(data) < FRAGMENT_HEADER_SIZE:
            raise ValueError("fragment shorter than header")
        group_id, count, index = struct.unpack_from("!III", data, 0)
        return Fragment(group_id, count, index, data[FRAGMENT_HEADER_SIZE:])


class Fragmenter:
    """Turn payloads into shuffled fragments."""

    def __init__(self, fragment_size: int = c.FRAGMENT_SIZE):
        if fragment_size <= 0:
            raise ValueError("fragment_size must be positive")
        self.fragment_size = fragment_size

    def _new_group_id(self) -> int:
        return struct.unpack("!I", os.urandom(4))[0]

    def fragment(self, payload: bytes, group_id: int = None,
                 shuffle: bool = True) -> List[Fragment]:
        """Split ``payload`` into fragments, returned in random order by default.

        An empty payload still produces exactly one (empty) fragment so the
        receiver can reconstruct a zero-length message unambiguously.
        """
        if len(payload) > c.MAX_MESSAGE_SIZE:
            raise ValueError("payload exceeds MAX_MESSAGE_SIZE")
        if group_id is None:
            group_id = self._new_group_id()

        chunks = [payload[i:i + self.fragment_size]
                  for i in range(0, len(payload), self.fragment_size)]
        if not chunks:
            chunks = [b""]
        count = len(chunks)
        if count > c.MAX_FRAGMENTS_PER_MESSAGE:
            raise ValueError("too many fragments for one message")

        fragments = [Fragment(group_id, count, idx, chunk)
                     for idx, chunk in enumerate(chunks)]
        if shuffle:
            _sysrandom.shuffle(fragments)
        return fragments

    def fragment_encoded(self, payload: bytes, group_id: int = None,
                         shuffle: bool = True) -> List[bytes]:
        """Like :meth:`fragment` but return already-serialised fragment bytes."""
        return [f.encode() for f in self.fragment(payload, group_id, shuffle)]
