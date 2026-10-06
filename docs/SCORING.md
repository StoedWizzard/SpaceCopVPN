# Scoring: how nodes compete and earn points

Nodes in the overlay compete to serve client traffic, and the ones that carry
more traffic earn more points and rank higher on the leaderboard. The analogy
to cryptocurrency mining is deliberate: instead of spending hash power on an
arbitrary puzzle, nodes spend a genuinely useful scarce resource — **bandwidth
and uptime** — and are rewarded for it. This is "proof of useful work."

## Proof-of-relay receipts

Every time a node relays data for a client, the client hands back a **signed
receipt**:

```
Receipt = { client_ed_public, node_ed_public, seq, byte_count, timestamp, signature }
signature = Ed25519.sign(client_priv, everything-before-signature)
```

A node collects receipts as evidence of the work it performed. Because each
receipt is signed by the client's Ed25519 key:

* **Authenticity** — anyone can verify the client actually issued it; a node
  cannot mint receipts for itself.
* **No double-counting** — the `(client_ed_public, seq)` pair is unique per
  client, so replaying the same receipt is ignored by the ledger.

## Points

```
BYTES_PER_POINT = 20 KB (one fragment-sized unit)
points_for_bytes(n) = ceil(n / BYTES_PER_POINT)   # any relayed traffic earns ≥ 1
```

A node's score is the sum of `points_for_bytes(byte_count)` over its verified,
de-duplicated receipts. The `Ledger` tracks per-node points, total bytes, and
receipt counts, and produces a `leaderboard()` ranked by points then volume.

## Client-side competition

The client keeps sessions to several nodes and, for each request, picks one via
an epsilon-greedy selector that favours low latency and high reliability while
occasionally exploring. Nodes that answer faster and fail less get more requests
— and therefore more receipts and points. This closes the competitive loop:
better service → more traffic → more points.

## Anti-Sybil: proof-of-work registration

To make it costly to flood the overlay with fake identities, joining requires a
hashcash-style proof: find a `nonce` such that
`SHA256(challenge || nonce)` has at least `difficulty` leading zero bits
(`spacecop/node/proofofwork.py`). This is a spam/Sybil speed bump, not a
consensus mechanism.

## Trust model and limitations

This is an intentionally simple, transparent design; it is **not** a trustless
economic system:

* **Client–node collusion.** A client and node that cooperate can mint receipts
  for traffic that was never really relayed, inflating the node's score. In a
  system where points had real value you would need the client to be *spending*
  something it cannot fabricate — a stake, a micropayment, or a scarce token —
  so that issuing a receipt has a cost. Orchid's probabilistic nanopayments and
  staked-bandwidth designs (Mysterium, Sentinel) are the reference points for
  hardening this.
* **No global consensus.** Each node keeps its own ledger; there is no
  blockchain or agreed global state. Receipts are portable and verifiable, so a
  future version could publish them to a shared, append-only log or contract to
  produce a single authoritative leaderboard.
* **Freshness.** Receipts carry a timestamp but the current ledger does not
  expire old ones; a production system would window or decay scores.

The value of the current design is that every point is backed by a
cryptographically verifiable receipt, and the competitive routing and
proof-of-work registration make the "miners competing for rewards" model
concrete and testable.
