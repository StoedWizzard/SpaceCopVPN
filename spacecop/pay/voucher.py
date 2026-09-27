"""The payment voucher: a client-signed, cumulative IOU to one node.

A voucher says "client C has authorised paying node N a cumulative total of
``cumulative_micros`` micro-dollars for this escrow (identified by ``nonce``)".
It is *cumulative* and *monotonic*: the client re-signs a larger total as more
traffic is relayed, and the node only ever needs to keep the latest one — the
same design as a payment channel's signed balance.

Signed content (exactly what a Solana program would verify):

    client_pubkey(32) || node_pubkey(32) || cumulative_micros(u64) || nonce(u64)

The signature is Ed25519 over that content, using the project's own Ed25519
implementation (the same keys the VPN identities already use).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto import ed25519
from ..protocol import framing


@dataclass
class Voucher:
    client_pub: bytes          # client's Ed25519 public key (32 bytes)
    node_pub: bytes            # payee node's Ed25519 public key (32 bytes)
    cumulative_micros: int     # total authorised to this node so far
    nonce: int                 # identifies the escrow/deposit (anti-replay across escrows)
    signature: bytes = b""

    def signed_content(self) -> bytes:
        if len(self.client_pub) != 32 or len(self.node_pub) != 32:
            raise ValueError("public keys must be 32 bytes")
        if self.cumulative_micros < 0 or self.nonce < 0:
            raise ValueError("cumulative_micros and nonce must be non-negative")
        buf = bytearray()
        buf.extend(self.client_pub)
        buf.extend(self.node_pub)
        framing.write_u64(buf, self.cumulative_micros)
        framing.write_u64(buf, self.nonce)
        return bytes(buf)

    def sign(self, client_ed_private: bytes) -> "Voucher":
        self.signature = ed25519.sign(client_ed_private, self.signed_content())
        return self

    def verify(self) -> bool:
        """True if the signature is the client's over this exact content."""
        try:
            content = self.signed_content()
        except ValueError:
            return False
        return ed25519.verify(self.client_pub, content, self.signature)

    def encode(self) -> bytes:
        buf = bytearray(self.signed_content())
        framing.write_bytes(buf, self.signature)
        return bytes(buf)

    @staticmethod
    def decode(data: bytes) -> "Voucher":
        client_pub = data[0:32]
        node_pub = data[32:64]
        cumulative, off = framing.read_u64(data, 64)
        nonce, off = framing.read_u64(data, off)
        signature, off = framing.read_bytes(data, off)
        return Voucher(client_pub, node_pub, cumulative, nonce, signature)
