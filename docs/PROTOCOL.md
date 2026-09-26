# SpaceCopVPN wire protocol

Version 1. All multi-byte integers are **big-endian** unless noted. The
fragment header uses network byte order via `struct` as marked.

## 1. Frame header

Every UDP datagram begins with a fixed 4-byte header:

```
+--------+--------+---------+----------+
| 'S'    | 'C'    | version | msg_type |
| 0x53   | 0x43   | 1 byte  | 1 byte   |
+--------+--------+---------+----------+
```

* `magic` = `b"SC"` — cheap rejection of non-protocol traffic.
* `version` = `1`.
* `msg_type` — one of the codes in §2. The remainder of the datagram is the
  message **body**, whose layout depends on the type.

## 2. Message types

| Code   | Name             | Direction        | Purpose                                   |
|--------|------------------|------------------|-------------------------------------------|
| `0x01` | HANDSHAKE_INIT   | client → node    | begin a session                           |
| `0x02` | HANDSHAKE_RESP   | node → client    | complete a session                        |
| `0x03` | DATA             | both             | one encrypted fragment                    |
| `0x04` | ACK              | both             | acknowledge fragment indices              |
| `0x05` | PING             | both             | liveness probe                            |
| `0x06` | PONG             | both             | liveness reply                            |
| `0x10` | NODE_ANNOUNCE    | node → overlay   | signed self-advertisement                 |
| `0x11` | PEER_REQUEST     | both             | request known peers                       |
| `0x12` | PEER_LIST        | both             | list of known peers                       |
| `0x20` | RELAY_REQUEST    | client → node    | forward an opaque blob to a destination   |
| `0x21` | RECEIPT          | client → node    | signed proof-of-relay (earns points)      |
| `0x22` | SCORE_QUERY      | both             | ask a node for its score                  |
| `0x23` | SCORE_REPORT     | node → asker     | report accumulated score                  |
| `0x24` | RELAY_RESPONSE   | node → client    | the destination's reply                   |

## 3. Field encodings

* `u8/u16/u32/u64` — fixed-width big-endian integers.
* `bytes16` — a 2-byte length prefix followed by that many bytes.
* `bytes32` — a 4-byte length prefix followed by that many bytes (large fields).

## 4. Handshake

A custom Noise-like exchange. The client already knows the node's static X25519
key `S` (from a signed `NODE_ANNOUNCE`).

**HANDSHAKE_INIT body** (48 bytes):

```
session_id : 8 bytes (client-chosen, random)
e_c_pub    : 32 bytes (client ephemeral X25519 public key)
timestamp  : u64 (unix seconds; rejected if skew > 120 s)
```

The node generates its own ephemeral `e_n` and computes two shared secrets:

```
ss_static = X25519(node_static_priv, e_c_pub)     # authenticates the node
ss_eph    = X25519(e_n_priv,        e_c_pub)       # forward secrecy
transcript = SHA256(MAGIC || VERSION || session_id || e_c_pub || e_n_pub || S)
PRK        = HKDF-Extract(salt = transcript, IKM = ss_static || ss_eph)
k_c2n || k_n2c || k_confirm = HKDF-Expand(PRK, "spacecop/v1 session-keys", 96)
```

**HANDSHAKE_RESP body**:

```
session_id : 8 bytes (echoed)
e_n_pub    : 32 bytes (node ephemeral X25519 public key)
sealed     : ChaCha20-Poly1305( key = k_confirm, nonce = 0,
                                 aad = transcript,
                                 plaintext = node_ed_pub(32) || Ed25519_sig(64) )
```

The signature is over `transcript`, binding the node's Ed25519 identity to the
key exchange. The client recomputes the same secrets from its ephemeral private
key, opens `sealed`, verifies the signature (and, if it had an expected
identity, that it matches).

Result: the client sends with `k_c2n` / receives with `k_n2c`; the node does the
reverse. `k_confirm` is used only for the response, so data-plane nonces start
cleanly at 0. The client presents no long-term identity (anonymous client).

## 5. Session records (DATA)

Each direction has a 64-bit counter used as the nonce. A sealed record is:

```
counter : u64
ct||tag : ChaCha20-Poly1305( key = direction_key,
                             nonce = 0x00000000 || counter,
                             aad = <caller aad> || counter,
                             plaintext = <fragment bytes> )
```

**DATA body** = `session_id(8) || sealed_record`. The receiver looks up the
session by `session_id`, decrypts, and checks the counter against a
1024-entry sliding replay window (newer-than-window always accepted; within
window rejected if already seen; older than window rejected).

## 6. Fragmentation

The plaintext inside a session record is a **fragment**:

```
group_id : u32 (random per logical message)
count    : u32 (total fragments in the group)
index    : u32 (0 .. count-1)
payload  : up to 20480 bytes (FRAGMENT_SIZE)
```

A logical application message (itself a full framed message, e.g. a
RELAY_REQUEST) is split into `count` fragments of ≤20 KB, which are **shuffled**
and each sealed independently. The receiver groups by `group_id`, ignores
duplicates, and once all `count` indices have arrived concatenates them in
index order to recover the message. Incomplete groups expire after 30 s and the
number of in-flight groups is capped.

## 7. Relaying

Carried as application messages *inside* the encrypted session (so a relay node
sees only ciphertext until it reassembles a full request):

**RELAY_REQUEST body**: `request_id(bytes16) || dest_host(bytes16) ||
dest_port(u16) || blob(bytes32)`. The node opens a TCP connection to
`(dest_host, dest_port)`, sends `blob`, reads the reply (with time/size caps),
and returns:

**RELAY_RESPONSE body**: `request_id(bytes16) || status(u8) || blob(bytes32)`,
`status = 0` on success.

## 8. Discovery

**NODE_ANNOUNCE body**: `ed_pub(32) || x_pub(32) || host(bytes16) || port(u16) ||
score(u64) || timestamp(u64) || signature(bytes16)`, where the signature is
Ed25519 over everything before it. **PEER_LIST body**: `count(u16)` then
`count` × `{ed_pub(32) || x_pub(32) || host(bytes16) || port(u16)}`.

## 9. Streaming relay (full TCP connections)

Browsers need real connections — HTTPS is several round trips inside *one*
TCP connection — so besides request/response there are **streams**. All
stream messages travel inside the encrypted session as application messages.

| Message | Body |
|---------|------|
| `STREAM_OPEN` (0x30) | `stream_id(8) || dest_host(bytes16) || dest_port(u16)` |
| `STREAM_OPENED` (0x31) | `stream_id(8) || status(u8) || text(bytes16)`, `status = 0` = connected |
| `STREAM_DATA` (0x32) | `stream_id(8) || seq(u32) || fin(u8) || data(bytes16)` |
| `STREAM_ACK` (0x33) | `stream_id(8) || ack(u32) || n(u16) || sack(u32)×n` |
| `STREAM_CLOSE` (0x34) | `stream_id(8) || reason(u8)` |

Per direction this is a small TCP over datagrams: chunks of at most
`STREAM_CHUNK_SIZE` (1200 B, one MTU-safe datagram each — a 20 KB datagram is
IP-fragmented into ~14 pieces that many networks drop), a window of
`STREAM_WINDOW` (128) chunks in flight with back-pressure, in-order delivery
with buffering of out-of-order chunks, an ack per chunk carrying the next
expected seq plus selective acks, retransmission after 0.4 s → 3 s
(exponential), stream death after 30 s without progress, `fin` for half-close,
`STREAM_OPEN` re-sent every second until `STREAM_OPENED` (duplicates for an
open stream are ignored). Chunks within the window (and retransmits) go out in
random order. Messages larger than 20 KB still use the §6 fragmentation.

The SOCKS5 proxy maps each `CONNECT` to one stream; all connections to a site
are pinned to one node (stable IP).

## 10. Receipts

**RECEIPT body**: `client_ed_pub(32) || node_ed_pub(32) || seq(u64) ||
byte_count(u64) || timestamp(u64) || signature(bytes16)`, Ed25519-signed by the
client over everything before the signature. See [SCORING.md](SCORING.md).
