# SpaceCopVPN

A **from-scratch, decentralised, incentivised VPN protocol**. No OpenVPN, no
WireGuard, no third-party networking or crypto libraries — the wire protocol,
the packet fragmentation, the node overlay, the scoring ledger, and even the
cryptographic primitives are implemented directly on top of the Python standard
library.

> **Scope & intent.** This is a privacy-networking project built for learning
> and experimentation, in the same spirit as open projects like WireGuard, Tor,
> and incentivised mesh networks (Mysterium, Orchid, Sentinel). The
> cryptographic primitives are faithful re-implementations of published,
> peer-reviewed standards (ChaCha20-Poly1305, X25519, Ed25519, HKDF), verified
> against RFC test vectors and OpenSSL. Rolling entirely novel cryptography
> would be irresponsible, so the *algorithms* are standard while the *code* is
> written here from their specifications. See
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the security model and its
> limitations; a from-scratch stack like this should be audited before any use
> where real safety depends on it.

## What it does

* **Custom wire protocol** — a 4-byte framed, versioned datagram protocol with
  an authenticated, forward-secret handshake (a Noise-like `e, es, ee` pattern),
  per-direction keys, monotonic nonces, and sliding-window replay protection.
* **Cross-platform** — pure standard-library Python (3.8+), so the core runs
  unchanged on Windows, Linux, and Android. Device integration has a Linux
  `/dev/net/tun` backend, an Android `VpnService` file-descriptor backend,
  Windows/Wintun guidance, and a **driver-free SOCKS5 proxy** that works
  everywhere with no root.
* **Decentralised** — nodes discover each other by gossiping signed
  announcements from a small bootstrap set; there is no central server. A
  client connects to many nodes at once.
* **Nodes compete and earn points** — like miners spending a scarce resource
  (here, real bandwidth and uptime), nodes race to relay traffic. Each relay
  is rewarded with a client-signed, verifiable proof-of-relay receipt; a ledger
  tallies points and ranks nodes on a leaderboard. A hashcash-style
  proof-of-work gates node registration to blunt Sybil attacks.
* **20 KB shuffled, encrypted fragments** — every payload (in both directions)
  is split into 20 KB fragments, emitted in random order, each independently
  encrypted, and reassembled on the receiving device.

## Quick start

Everything runs on loopback with no privileges. Run the self-contained demo:

```
python examples/local_demo.py
```

It launches an echo destination, four competing relay nodes, and a client;
sends 40 fragmented/encrypted requests distributed across the nodes; and prints
the score leaderboard and the client's latency-ranked view of the nodes.

Run the pieces yourself:

```
# Terminal 1 — a relay node (prints its keys)
python examples/run_node.py 51820

# Terminal 2 — a client + local SOCKS5 proxy through that node
python examples/run_client.py 127.0.0.1:51820 <x25519_hex> <ed25519_hex>
#   then point an app at socks5://127.0.0.1:1080
```

Or via the CLI:

```
python -m spacecop.cli node --port 51820 --advertise <your_ip>
python -m spacecop.cli proxy --node <ip>:51820 --node-key <hex> --node-id <hex>
python -m spacecop.cli relay --node <ip>:51820 --node-key <hex> --dest example.com:80
```

## Tests

```
python -m unittest discover -s tests -p 'test_*.py'
```

62 tests cover the crypto (against RFC 8439/7748/5869 vectors and OpenSSL), the
handshake and session layer, fragmentation and reassembly, the scoring ledger
and proof-of-work, and full end-to-end relaying over real UDP/TCP sockets
(including the SOCKS proxy).

## Layout

```
spacecop/
  crypto/         ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD, X25519, Ed25519, HKDF
  protocol/       constants, framing, handshake, session, message codecs
  fragmentation/  20 KB shuffled fragmenter + out-of-order reassembler
  transport/      threaded UDP datagram I/O
  node/           relay node, peer directory (gossip), scoring ledger, proof-of-work
  client/         VPN client + multi-node (competition-aware) selection
  tun/            Linux TUN, Android fd backend, Windows/Wintun guide, SOCKS5 proxy
  cli.py          node / proxy / relay commands
examples/         local_demo.py, run_node.py, run_client.py
docs/             PROTOCOL.md, ARCHITECTURE.md, SCORING.md
tests/            RFC-vector + integration test suite
```

## Documentation

* [docs/PROTOCOL.md](docs/PROTOCOL.md) — the exact wire format, message by message.
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system design, threat model, limits, roadmap.
* [docs/SCORING.md](docs/SCORING.md) — the incentive/points design and its trust assumptions.
