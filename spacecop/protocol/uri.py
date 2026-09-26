"""Connection URIs: one copy-pasteable string that fully describes a node.

Format::

    spacecop://<host>:<port>/<x25519_pub_hex>[/<ed25519_pub_hex>]

The X25519 key is what the client needs to perform the handshake; the optional
Ed25519 key pins the node's identity so a man-in-the-middle presenting a
different identity is rejected.  A node prints its URI on start-up and the
server deploy script prints it at the end, so configuring a client is a single
paste into the GUI or CLI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

SCHEME = "spacecop"


class URIError(ValueError):
    pass


@dataclass
class NodeURI:
    host: str
    port: int
    x_public: bytes
    ed_public: bytes = b""

    def __str__(self) -> str:
        return build_uri(self.host, self.port, self.x_public, self.ed_public)

    @property
    def address(self):
        return (self.host, self.port)


def build_uri(host: str, port: int, x_public: bytes, ed_public: bytes = b"") -> str:
    if len(x_public) != 32:
        raise URIError("x25519 public key must be 32 bytes")
    if ed_public and len(ed_public) != 32:
        raise URIError("ed25519 public key must be 32 bytes")
    host_part = f"[{host}]" if ":" in host else host  # IPv6 literal
    uri = f"{SCHEME}://{host_part}:{port}/{x_public.hex()}"
    if ed_public:
        uri += f"/{ed_public.hex()}"
    return uri


def parse_uri(text: str) -> NodeURI:
    text = text.strip()
    prefix = f"{SCHEME}://"
    if not text.startswith(prefix):
        raise URIError(f"URI must start with {prefix}")
    rest = text[len(prefix):]
    if "/" not in rest:
        raise URIError("URI is missing the key section")
    authority, _, keys = rest.partition("/")
    parts = [p for p in keys.split("/") if p]
    if not parts or len(parts) > 2:
        raise URIError("URI must contain one or two hex keys")

    if authority.startswith("["):
        end = authority.find("]")
        if end < 0 or not authority[end + 1:].startswith(":"):
            raise URIError("malformed IPv6 authority")
        host = authority[1:end]
        port_text = authority[end + 2:]
    else:
        host, sep, port_text = authority.rpartition(":")
        if not sep or not host:
            raise URIError("URI must contain host:port")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise URIError("port is not a number") from exc
    if not 0 < port < 65536:
        raise URIError("port out of range")

    try:
        x_public = bytes.fromhex(parts[0])
        ed_public = bytes.fromhex(parts[1]) if len(parts) == 2 else b""
    except ValueError as exc:
        raise URIError("keys must be hex") from exc
    if len(x_public) != 32 or (ed_public and len(ed_public) != 32):
        raise URIError("keys must be 32 bytes (64 hex chars)")
    return NodeURI(host, port, x_public, ed_public)


def try_parse(text: str) -> Optional[NodeURI]:
    try:
        return parse_uri(text)
    except URIError:
        return None
