# Architecture

## Layers

```
        application traffic (SOCKS5 / TUN packets)
                        │
   ┌────────────────────▼─────────────────────┐
   │ client relay()  /  node relay/exit        │   request/response over the overlay
   ├────────────────────┬─────────────────────┤
   │ fragmentation (20 KB, shuffled)           │   split → shuffle → reassemble
   ├────────────────────┬─────────────────────┤
   │ session (AEAD, counters, replay window)   │   per-direction ChaCha20-Poly1305
   ├────────────────────┬─────────────────────┤
   │ handshake (X25519 e/es/ee + Ed25519 id)   │   forward-secret, node-authenticated
   ├────────────────────┬─────────────────────┤
   │ framing (magic/version/type) over UDP     │   one datagram per message
   └────────────────────────────────────────── ┘
   overlay control plane: gossip discovery + scoring ledger + proof-of-work
```

Each layer is independent and separately tested. The crypto layer depends on
nothing but the standard library; higher layers depend only on the layers below
them.

## Data flow of one relayed request

1. Client builds a `RELAY_REQUEST` (a full framed message) naming the
   destination and carrying the opaque payload.
2. The fragmenter splits it into 20 KB fragments, assigns a random `group_id`,
   and **shuffles** them.
3. Each fragment is sealed independently by the session (ChaCha20-Poly1305 with
   a monotonic counter) and sent as a `DATA` datagram.
4. The node decrypts each fragment, feeds the reassembler, and once the group is
   complete decodes the `RELAY_REQUEST`.
5. The node opens TCP to the destination, relays the blob, and reads the reply.
6. The reply is wrapped in a `RELAY_RESPONSE`, fragmented, shuffled, sealed, and
   sent back; the client reassembles it and returns it to the caller.
7. The client signs a `RECEIPT` for the bytes relayed and sends it to the node,
   which records it in its ledger (see SCORING.md). Receipts are issued only
   for successful relays.

## Throughput, loss recovery, and IP consistency

* **Worker pool.** The node hands each reassembled request to a pool of 64
  worker threads; the UDP receive loop only decrypts and reassembles, so a slow
  destination never stalls other clients. Web pages that fire hundreds of
  requests at once are the normal case (the test-suite runs 300 concurrently).
* **Retransmission.** If no reply arrives within 2 s the client re-sends the
  *identical* sealed fragments (up to twice). This is safe by construction: the
  replay window drops copies already seen, the reassembler ignores duplicate
  fragments, and the node keeps finished responses in a 60 s cache keyed by
  `(session_id, request_id)` so a retransmit is answered from cache rather than
  by contacting the destination a second time; retransmits of a request still
  in flight are coalesced.
* **One site, one node.** The client's selector pins each *site* (registrable
  domain such as `example.com` for `cdn.example.com`, or the IP literal) to the
  node first chosen for it and keeps routing that site through the same node,
  so the destination sees one stable IP for the whole session. The pin breaks
  only if that node fails, is removed, or has been idle for 30 minutes.
  Different sites still spread across nodes, so competition is preserved.

## Streams: HTTPS and arbitrary TCP through the overlay

Request/response cannot serve a browser: a TLS handshake is several round
trips inside *one* connection. So the SOCKS5 proxy opens a **stream** per
`CONNECT` (`spacecop/protocol/stream.py`): both ends run a small TCP-like
engine — 1200 B chunks (one MTU-safe datagram each), a 128-chunk window with
back-pressure, in-order delivery, an ack per chunk with selective acks,
retransmission on an exponential timeout, FIN for half-close. The node keeps a
TCP socket per stream with a reader thread (destination → overlay) and a
queue-fed writer thread (overlay → destination), so the UDP loop never blocks.
Chunks in the window go out in random order; messages above 20 KB still use
the 20 KB fragmentation. Verified with a real HTTPS request via
`curl --socks5-hostname` (TLS handshake, response and keep-alive inside one
stream), 120 concurrent connections, and a channel with 30% loss. A receipt
for a stream is issued on close for the bytes carried in both directions.

## Decentralisation

There is no coordinator. A node/client starts from a small bootstrap address
list, sends `PEER_REQUEST`s, and merges the signed `NODE_ANNOUNCE`s it receives
(directly or via `PEER_LIST`). Announcements are Ed25519-signed, so a gossiped
entry cannot forge another node's identity. The client keeps sessions to many
nodes and load-balances requests across them with an epsilon-greedy,
latency-and-reliability-weighted selector, so faster/steadier nodes win more
traffic (and thus more points).

## Cross-platform device integration

The protocol core is platform-agnostic pure Python. Capturing device traffic is
the only OS-specific part, isolated behind `TunInterface`:

* **Linux** — `spacecop/tun/linux.py` opens `/dev/net/tun` and issues
  `TUNSETIFF` via `fcntl.ioctl`. Needs `CAP_NET_ADMIN`.
* **Android** — `spacecop/tun/android.py` wraps the file descriptor from a
  `VpnService.Builder.establish()` call in the app; the Python engine reads and
  writes packets on that fd (e.g. via Chaquopy). A Kotlin sketch is in the
  module docstring.
* **Windows** — `spacecop/tun/windows.py` documents the Wintun (`wintun.dll`,
  `ctypes`) call sequence; the signed DLL is shipped at packaging time.
* **Any platform, no driver/root** — `spacecop/tun/socks_proxy.py` is a
  userspace SOCKS5 proxy that tunnels connections through the overlay. This is
  the recommended path for portability and for Android/Termux.

## Threat model and what is (not) protected

* **Confidentiality/integrity to the exit node.** Traffic between client and the
  relay is encrypted and authenticated with ChaCha20-Poly1305; tampering and
  replay are detected. The **exit node sees plaintext it forwards**, exactly
  like any VPN exit or Tor exit. Use end-to-end encryption (TLS) to the final
  destination for privacy from the exit.
* **Node authentication + forward secrecy.** The handshake authenticates the
  node and uses ephemeral keys, so compromising a node's long-term key later
  does not decrypt captured past sessions. The client is anonymous by design.
* **Not anonymity by default.** A single relay hop hides the client from the
  destination but not from the relay. Onion-style multi-hop (nesting
  `RELAY_REQUEST`s so each hop only learns the next) is a natural extension of
  the existing opaque-blob relay and is the intended path to sender anonymity.
* **Metadata / traffic analysis.** Fixed 20 KB fragments and random emission
  order blunt simple size/order correlation, but this is not a full defence
  against a global passive adversary. Constant-rate padding/cover traffic would
  be needed for that.
* **Implementation caveats.** The crypto is standard algorithms re-implemented
  from RFCs and checked against test vectors and OpenSSL, but it is not
  constant-time and has not been independently audited. Treat this as a learning
  and experimentation platform, not a hardened production VPN.

## Known limits / roadmap

* **Fragment-level multipath.** Today one request's fragments go through one
  node. Striping fragments of a single message across multiple nodes (with a
  shared reassembly rendezvous) is a documented extension of the fragmentation
  layer.
* **MTU.** Streams already use 1200 B chunks (one MTU-safe datagram). The
  request/response mode (`relay()`, CLI `relay`) still sends each 20 KB
  fragment as one datagram that is IP-fragmented; fine on LAN/loopback, but
  over the Internet it should get the same MTU-sized segmentation.
* **Sybil economics.** Proof-of-work gates registration and client-signed
  receipts prevent trivial forgery, but a fully trustless incentive system needs
  staking/payments; see SCORING.md.
