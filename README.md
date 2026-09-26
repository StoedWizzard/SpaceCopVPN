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
* **Real TCP streams: HTTPS just works** — the SOCKS5 proxy carries every
  connection as a stream (a small TCP-like engine over the encrypted
  datagrams: MTU-safe chunks, window, selective acks, retransmission), so TLS
  handshakes, keep-alive, WebSockets and SSH all pass through. Verified with a
  live HTTPS request via `curl --socks5-hostname`.
* **One site, one IP** — all requests to the same site (including its
  subdomains) are pinned to the same exit node for the session, so a web site
  sees a stable IP and does not drop logins.
* **Built for many requests** — nodes relay on a worker pool, lost fragments
  are retransmitted, and responses are cached so a retransmit never hits the
  destination twice. 300 concurrent relays are exercised in the test-suite.
* **Graphical client + packaging** — a Tkinter GUI (profiles, paste a
  `spacecop://…` connection URI, SOCKS5, test, node health table), an
  **Arch Linux** package, and a one-command server installer.

📖 **Документация на русском: [README.ru.md](README.ru.md), [docs/ru/](docs/ru/).**

## Quick start

Everything runs on loopback with no privileges. Run the self-contained demo:

```
python examples/local_demo.py
```

It launches an echo destination, four competing relay nodes, and a client;
sends 40 fragmented/encrypted requests distributed across the nodes; and prints
the score leaderboard and the client's latency-ranked view of the nodes.

### Server (node) on any Linux, one command

```
sudo ./deploy/install_server.sh
```

Installs python3, copies the project to `/opt/spacecop`, generates a
**persistent identity** in `/etc/spacecop/identity.json`, installs and starts
the `spacecop-node` systemd service, opens the UDP port in ufw/firewalld, and
prints a **connection URI**:

```
spacecop://203.0.113.9:51820/<x25519_hex>/<ed25519_hex>
```

Update a running node later with `sudo ./deploy/update_server.sh` (the service
runs from `/opt/spacecop`, so a `git pull` elsewhere does not update it).

### Graphical client (Arch Linux)

```
./packaging/install_client_arch.sh     # builds + installs the package (or --user)
spacecop-gui                            # or "SpaceCopVPN" in the app menu
```

Paste the URI → «Добавить узел» → «Подключиться», then point apps at the local
SOCKS5 proxy (default `127.0.0.1:1080`). Details: [docs/ru/INSTALL.md](docs/ru/INSTALL.md).

### CLI

```
python -m spacecop.cli keygen --identity id.json --host <ip>   # keys + URI
python -m spacecop.cli node --port 51820 --advertise <ip> --identity id.json
python -m spacecop.cli proxy --uri spacecop://... --listen 127.0.0.1:1080
python -m spacecop.cli relay --uri spacecop://... --dest example.com:80
python -m spacecop.cli gui
```

## Tests

```
python -m unittest discover -s tests -p 'test_*.py'
```

89 tests cover the crypto (against RFC 8439/7748/5869 vectors and OpenSSL), the
handshake and session layer, replay protection, fragmentation and reassembly,
the scoring ledger and proof-of-work, connection URIs and identity persistence,
full end-to-end relaying over real UDP/TCP sockets, streaming (multi-round-trip
dialogues, 700 KB transfers, 120 concurrent streams, a 30%-loss channel, SOCKS5),
300 concurrent relays under load, one-site-one-node IP consistency, and the
ping/handshake diagnostics.

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
  gui/            Tkinter graphical client
  cli.py          keygen / uri / node / proxy / relay / gui commands
deploy/           install_server.sh — one-command node installer for any Linux
packaging/        Arch PKGBUILD + build script, .desktop entry, client installer
examples/         local_demo.py, run_node.py, run_client.py
docs/             PROTOCOL.md, ARCHITECTURE.md, SCORING.md  (+ docs/ru/ in Russian)
tests/            RFC-vector, integration, load and sticky-routing tests
```

## Documentation

* [docs/PROTOCOL.md](docs/PROTOCOL.md) — the exact wire format, message by message.
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system design, threat model, limits, roadmap.
* [docs/SCORING.md](docs/SCORING.md) — the incentive/points design and its trust assumptions.
* Russian: [README.ru.md](README.ru.md), [docs/ru/INSTALL.md](docs/ru/INSTALL.md)
  (install + app setup), [docs/ru/REVIEW.md](docs/ru/REVIEW.md) (code-review report),
  and Russian versions of the three documents above in [docs/ru/](docs/ru/).
