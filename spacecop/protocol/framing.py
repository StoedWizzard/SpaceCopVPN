"""Wire framing: encode/decode the fixed header and typed message bodies.

Every datagram is::

    +--------+---------+----------+------------------+
    | MAGIC  | VERSION | MSG_TYPE | body (variable)  |
    | 2 B    | 1 B     | 1 B      |                  |
    +--------+---------+----------+------------------+

The body format depends on the message type and is handled by the individual
message codecs in :mod:`spacecop.protocol.messages`.  This module only knows
about the common header.
"""

from __future__ import annotations

import struct
from typing import Tuple

from . import constants as c


class ProtocolError(Exception):
    """Raised for any malformed or unexpected wire data."""


def encode_frame(msg_type: int, body: bytes) -> bytes:
    """Prepend the fixed header to ``body``."""
    if not 0 <= msg_type <= 0xFF:
        raise ProtocolError(f"invalid message type {msg_type}")
    return c.MAGIC + bytes([c.VERSION, msg_type]) + body


def decode_frame(data: bytes) -> Tuple[int, bytes]:
    """Split a datagram into ``(msg_type, body)`` after validating the header."""
    if len(data) < c.HEADER_SIZE:
        raise ProtocolError("datagram shorter than header")
    if data[:2] != c.MAGIC:
        raise ProtocolError("bad magic")
    version = data[2]
    if version != c.VERSION:
        raise ProtocolError(f"unsupported version {version}")
    msg_type = data[3]
    return msg_type, data[c.HEADER_SIZE:]


# ---------------------------------------------------------------------------
# Small primitive codecs reused by the message layer
# ---------------------------------------------------------------------------
def write_bytes(buf: bytearray, data: bytes) -> None:
    """Length-prefix (2-byte big-endian) and append ``data``."""
    if len(data) > 0xFFFF:
        raise ProtocolError("field too long for 16-bit length prefix")
    buf.extend(struct.pack("!H", len(data)))
    buf.extend(data)


def read_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Read a 2-byte length-prefixed field; return ``(field, new_offset)``."""
    if offset + 2 > len(data):
        raise ProtocolError("truncated length prefix")
    (length,) = struct.unpack_from("!H", data, offset)
    offset += 2
    if offset + length > len(data):
        raise ProtocolError("truncated field body")
    return data[offset:offset + length], offset + length


def write_bytes32(buf: bytearray, data: bytes) -> None:
    """Length-prefix (4-byte big-endian) and append ``data``.

    Used for large fields (e.g. a relay blob that carries a whole payload
    before it is fragmented), which do not fit a 16-bit length.
    """
    if len(data) > 0xFFFFFFFF:
        raise ProtocolError("field too long for 32-bit length prefix")
    buf.extend(struct.pack("!I", len(data)))
    buf.extend(data)


def read_bytes32(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Read a 4-byte length-prefixed field; return ``(field, new_offset)``."""
    if offset + 4 > len(data):
        raise ProtocolError("truncated 32-bit length prefix")
    (length,) = struct.unpack_from("!I", data, offset)
    offset += 4
    if offset + length > len(data):
        raise ProtocolError("truncated field body")
    return data[offset:offset + length], offset + length


def write_u8(buf: bytearray, value: int) -> None:
    buf.append(value & 0xFF)


def write_u16(buf: bytearray, value: int) -> None:
    buf.extend(struct.pack("!H", value))


def write_u32(buf: bytearray, value: int) -> None:
    buf.extend(struct.pack("!I", value))


def write_u64(buf: bytearray, value: int) -> None:
    buf.extend(struct.pack("!Q", value))


def read_u8(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 1 > len(data):
        raise ProtocolError("truncated u8")
    return data[offset], offset + 1


def read_u16(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 2 > len(data):
        raise ProtocolError("truncated u16")
    return struct.unpack_from("!H", data, offset)[0], offset + 2


def read_u32(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 4 > len(data):
        raise ProtocolError("truncated u32")
    return struct.unpack_from("!I", data, offset)[0], offset + 4


def read_u64(data: bytes, offset: int) -> Tuple[int, int]:
    if offset + 8 > len(data):
        raise ProtocolError("truncated u64")
    return struct.unpack_from("!Q", data, offset)[0], offset + 8
