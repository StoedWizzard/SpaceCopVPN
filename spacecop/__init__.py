"""SpaceCopVPN — a from-scratch, decentralised, incentivised VPN protocol.

Subpackages:
* :mod:`spacecop.crypto` — ChaCha20, Poly1305, AEAD, X25519, Ed25519, HKDF.
* :mod:`spacecop.protocol` — the custom wire protocol, handshake, and sessions.
* :mod:`spacecop.fragmentation` — 20 KB shuffled fragments + reassembly.
* :mod:`spacecop.transport` — UDP datagram I/O.
* :mod:`spacecop.node` — relay nodes, discovery, and the scoring ledger.
* :mod:`spacecop.client` — the VPN client and multi-node selection.
* :mod:`spacecop.tun` — cross-platform device integration + SOCKS proxy.
"""

__version__ = "0.3.2"

__all__ = ["__version__"]
