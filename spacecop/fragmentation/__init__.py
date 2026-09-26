"""Packet fragmentation: split payloads into shuffled fixed-size fragments and
reassemble them on the receiving device."""

from .fragmenter import Fragment, Fragmenter
from .reassembler import Reassembler, ReassemblyError

__all__ = ["Fragment", "Fragmenter", "Reassembler", "ReassemblyError"]
