"""Protocol-wide constants for the SpaceCopVPN wire format.

The wire protocol is fully custom (no OpenVPN/WireGuard/etc.).  Every datagram
begins with a small fixed header so a receiver can dispatch on message type
before doing any cryptographic work.
"""

from __future__ import annotations

# Two-byte magic: ASCII "SC" for SpaceCop.  Lets a receiver cheaply reject
# stray traffic that is not part of this protocol.
MAGIC = b"SC"

# Protocol version.  Bumped on any incompatible wire change.
VERSION = 1

# Fixed header layout: magic(2) | version(1) | msg_type(1)
HEADER_SIZE = 4

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------
# Data plane (session establishment + encrypted payload transport)
MSG_HANDSHAKE_INIT = 0x01   # client -> node: open a session
MSG_HANDSHAKE_RESP = 0x02   # node -> client: complete the session
MSG_DATA = 0x03             # encrypted fragment of a larger payload
MSG_ACK = 0x04              # acknowledge received fragments
MSG_PING = 0x05             # liveness probe
MSG_PONG = 0x06             # liveness reply

# Control plane (decentralised overlay: discovery, gossip, scoring)
MSG_NODE_ANNOUNCE = 0x10    # a node advertises its identity + address
MSG_PEER_REQUEST = 0x11     # request known peers
MSG_PEER_LIST = 0x12        # response carrying known peers
MSG_RELAY_REQUEST = 0x20    # client asks a node to relay a fragment onward
MSG_RECEIPT = 0x21          # signed proof-of-relay receipt (earns points)
MSG_SCORE_QUERY = 0x22      # ask a node for its current score ledger
MSG_SCORE_REPORT = 0x23     # a node reports its accumulated score
MSG_RELAY_RESPONSE = 0x24   # a node returns the relayed destination's reply
MSG_ERROR = 0x7F            # node -> client: why a request was rejected (in the clear)

# Streaming relay (full TCP connections through the overlay, e.g. HTTPS).
# These travel *inside* the encrypted session as application messages.
MSG_STREAM_OPEN = 0x30      # client -> node: connect to dest_host:dest_port
MSG_STREAM_OPENED = 0x31    # node -> client: connect result
MSG_STREAM_DATA = 0x32      # both: an ordered chunk of the byte stream
MSG_STREAM_ACK = 0x33       # both: cumulative + selective acknowledgement
MSG_STREAM_CLOSE = 0x34     # both: tear the stream down

# Stream chunks are sized so that one chunk = one MTU-safe UDP datagram
# (~1.3 KB on the wire).  A 20 KB datagram is IP-fragmented into ~14 pieces
# and many networks drop IP fragments, so for interactive streams small
# chunks are far more robust.  The 20 KB logical fragmentation still applies
# to any application message larger than this.
STREAM_CHUNK_SIZE = 1200
STREAM_WINDOW = 128         # chunks in flight per direction (~150 KB)

MESSAGE_NAMES = {
    MSG_HANDSHAKE_INIT: "HANDSHAKE_INIT",
    MSG_HANDSHAKE_RESP: "HANDSHAKE_RESP",
    MSG_DATA: "DATA",
    MSG_ACK: "ACK",
    MSG_PING: "PING",
    MSG_PONG: "PONG",
    MSG_NODE_ANNOUNCE: "NODE_ANNOUNCE",
    MSG_PEER_REQUEST: "PEER_REQUEST",
    MSG_PEER_LIST: "PEER_LIST",
    MSG_RELAY_REQUEST: "RELAY_REQUEST",
    MSG_RECEIPT: "RECEIPT",
    MSG_SCORE_QUERY: "SCORE_QUERY",
    MSG_SCORE_REPORT: "SCORE_REPORT",
    MSG_RELAY_RESPONSE: "RELAY_RESPONSE",
    MSG_ERROR: "ERROR",
    MSG_STREAM_OPEN: "STREAM_OPEN",
    MSG_STREAM_OPENED: "STREAM_OPENED",
    MSG_STREAM_DATA: "STREAM_DATA",
    MSG_STREAM_ACK: "STREAM_ACK",
    MSG_STREAM_CLOSE: "STREAM_CLOSE",
}

# ---------------------------------------------------------------------------
# Fragmentation parameters
# ---------------------------------------------------------------------------
# Payloads are split into fixed-size fragments.  The task specifies 20 KB.
FRAGMENT_SIZE = 20 * 1024  # 20480 bytes of application payload per fragment

# A logical message is identified by a 4-byte group id; fragments within it are
# numbered 0..count-1.  These bounds keep the reassembly buffers finite.
MAX_FRAGMENTS_PER_MESSAGE = 1 << 16   # up to 65536 fragments (~1.25 GB message)
MAX_MESSAGE_SIZE = FRAGMENT_SIZE * MAX_FRAGMENTS_PER_MESSAGE

# ---------------------------------------------------------------------------
# Cryptographic sizes (see spacecop.crypto)
# ---------------------------------------------------------------------------
KEY_SIZE = 32          # X25519 / ChaCha20 key
NONCE_SIZE = 12        # ChaCha20-Poly1305 nonce
TAG_SIZE = 16          # Poly1305 tag
SESSION_KEY_SIZE = 32
ED25519_PUB_SIZE = 32
ED25519_SIG_SIZE = 64

# HKDF context strings — domain separation so keys can never be confused.
HKDF_INFO_SESSION = b"spacecop/v1 session-keys"
HKDF_SALT_TRANSCRIPT = b"spacecop/v1 handshake"

# Replay protection window (number of most-recent nonces tracked per session).
REPLAY_WINDOW = 1024

# Anti-replay / freshness: reject handshakes whose timestamp skews more than this.
MAX_CLOCK_SKEW_SECONDS = 300
