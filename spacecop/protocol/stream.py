"""Reliable, ordered byte streams over the unreliable encrypted message channel.

A web browser needs real TCP connections (HTTPS is several round trips inside
*one* connection), so the overlay carries **streams**: each end runs a
:class:`StreamEndpoint`, a small TCP-like engine that turns an unreliable,
unordered channel (UDP datagrams, each an encrypted session record) into an
ordered, lossless byte stream in both directions.

Mechanics (per stream, per direction):

* the sender cuts bytes into chunks of at most ``STREAM_CHUNK_SIZE`` (1200 B,
  so one chunk is one MTU-safe datagram), numbers them with a sequence
  number, and may have up to ``STREAM_WINDOW`` chunks in flight — ``send()``
  blocks when the window is full (back-pressure);
* the receiver delivers chunks in order, buffers out-of-order ones, and acks
  every chunk with the next expected seq plus a list of out-of-order seqs it
  already holds (selective ack);
* unacked chunks are retransmitted after a timeout that backs off from
  0.4 s to 3 s; a chunk that is not acked for ``DEAD_AFTER`` seconds kills
  the stream;
* a chunk with ``fin`` marks the end of that direction (half-close), exactly
  like TCP's FIN.

The endpoint is transport-agnostic: the owner passes ``send_msg`` (which
fragments, encrypts and transmits an application message) and callbacks for
delivered bytes / EOF / error.  Chunks inside the window are emitted in a
random order, so the wire order still reveals nothing about byte order.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Callable, Dict, List, Optional

from . import constants as c
from .messages import StreamAck, StreamClose, StreamData

_sysrandom = random.SystemRandom()

RTO_INITIAL = 0.4
RTO_MAX = 3.0
ACK_EVERY = 4              # in-order chunks per ACK (gaps, dups and FIN ack at once)
ACK_DELAY_MAX = 0.05       # a pending ACK never waits longer than this (via tick)
DEAD_AFTER = 30.0          # no ack progress for this long -> stream is dead
RECV_BUFFER_CHUNKS = c.STREAM_WINDOW * 2


class StreamError(Exception):
    pass


class StreamEndpoint:
    def __init__(self, stream_id: bytes, send_msg: Callable[[bytes], None],
                 on_deliver: Callable[[bytes], None], on_eof: Callable[[], None],
                 on_error: Callable[[str], None],
                 chunk_size: int = c.STREAM_CHUNK_SIZE, window: int = c.STREAM_WINDOW):
        self.stream_id = stream_id
        self._send_msg = send_msg
        self._on_deliver = on_deliver
        self._on_eof = on_eof
        self._on_error = on_error
        self.chunk_size = chunk_size
        self.window = window

        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)

        # send side
        self._next_seq = 0
        self._unacked: Dict[int, List] = {}   # seq -> [frame_bytes, last_sent, retries]
        self._fin_sent = False
        self._send_closed = False              # local side will send no more

        # receive side
        self._expected = 0
        self._ooo: Dict[int, StreamData] = {}  # out-of-order chunks
        self._fin_received = False
        self._eof_delivered = False
        self._unacked_rx = 0                   # in-order chunks received since last ACK
        self._ack_pending_since: Optional[float] = None

        self._closed = False
        self._last_progress = time.monotonic()
        self.bytes_sent = 0
        self.bytes_received = 0

    # ------------------------------------------------------------------ send
    def send(self, data: bytes, timeout: float = 20.0) -> None:
        """Queue ``data`` for ordered delivery; blocks while the window is full."""
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            chunk = bytes(view[offset:offset + self.chunk_size])
            offset += len(chunk)
            with self._cv:
                deadline = time.monotonic() + timeout
                while len(self._unacked) >= self.window and not self._closed:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise StreamError("send window stalled (peer not acking)")
                    self._cv.wait(min(remaining, 0.5))
                if self._closed or self._send_closed:
                    raise StreamError("stream is closed")
                seq = self._next_seq
                self._next_seq += 1
                frame = StreamData(self.stream_id, seq, False, chunk).encode()
                self._unacked[seq] = [frame, time.monotonic(), 0]
                self.bytes_sent += len(chunk)
            self._transmit(frame)

    def send_fin(self) -> None:
        """Half-close: tell the peer no more data will follow."""
        with self._lock:
            if self._fin_sent or self._closed:
                return
            self._fin_sent = True
            self._send_closed = True
            seq = self._next_seq
            self._next_seq += 1
            frame = StreamData(self.stream_id, seq, True, b"").encode()
            self._unacked[seq] = [frame, time.monotonic(), 0]
        self._transmit(frame)

    def _transmit(self, frame: bytes) -> None:
        try:
            self._send_msg(frame)
        except Exception:
            pass

    # --------------------------------------------------------------- receive
    def on_data(self, msg: StreamData) -> None:
        deliver: List[StreamData] = []
        ack = None
        with self._lock:
            if self._closed:
                return
            if msg.seq == self._expected:
                deliver.append(msg)
                self._expected += 1
                while self._expected in self._ooo:
                    deliver.append(self._ooo.pop(self._expected))
                    self._expected += 1
                self._unacked_rx += 1
                # Delayed ACK: one ACK per ACK_EVERY in-order chunks halves the
                # packet count; gaps, duplicates and FIN are acked immediately
                # and tick() flushes a pending ACK within ACK_DELAY_MAX.
                if self._unacked_rx >= ACK_EVERY or msg.fin or self._ooo:
                    ack = self._make_ack()
                elif self._ack_pending_since is None:
                    self._ack_pending_since = time.monotonic()
            elif msg.seq > self._expected:
                if len(self._ooo) < RECV_BUFFER_CHUNKS and msg.seq not in self._ooo:
                    self._ooo[msg.seq] = msg
                ack = self._make_ack()
            else:
                ack = self._make_ack()  # duplicate of delivered data -> re-ack now
        if ack is not None:
            self._transmit(ack)
        for m in deliver:
            if m.data:
                self.bytes_received += len(m.data)
                try:
                    self._on_deliver(m.data)
                except Exception:
                    pass
            if m.fin:
                with self._lock:
                    self._fin_received = True
                    already = self._eof_delivered
                    self._eof_delivered = True
                if not already:
                    try:
                        self._on_eof()
                    except Exception:
                        pass

    def _make_ack(self) -> bytes:
        """Build the cumulative + selective ACK; caller holds the lock."""
        self._unacked_rx = 0
        self._ack_pending_since = None
        sacks = sorted(self._ooo)[:64] if self._ooo else []
        return StreamAck(self.stream_id, self._expected, sacks).encode()

    def on_ack(self, msg: StreamAck) -> None:
        with self._cv:
            progressed = False
            for seq in [s for s in self._unacked if s < msg.ack]:
                del self._unacked[seq]
                progressed = True
            for seq in msg.sacks:
                if self._unacked.pop(seq, None) is not None:
                    progressed = True
            if progressed:
                self._last_progress = time.monotonic()
                self._cv.notify_all()

    def on_close(self, reason: int = 0) -> None:
        """Peer tore the stream down."""
        self._finish("closed by peer" if reason == 0 else "aborted by peer",
                     error=(reason != 0))

    # ------------------------------------------------------------------ tick
    def tick(self, now: Optional[float] = None) -> None:
        """Retransmit overdue chunks; call every ~100 ms."""
        now = now or time.monotonic()
        to_send: List[bytes] = []
        ack = None
        with self._lock:
            if self._closed:
                return
            if self._ack_pending_since is not None and now - self._ack_pending_since >= ACK_DELAY_MAX:
                ack = self._make_ack()
            if self._unacked and now - self._last_progress > DEAD_AFTER:
                dead = True
            else:
                dead = False
            if not dead:
                for entry in self._unacked.values():
                    frame, last_sent, retries = entry
                    rto = min(RTO_MAX, RTO_INITIAL * (2 ** retries))
                    if now - last_sent >= rto:
                        entry[1] = now
                        entry[2] = retries + 1
                        to_send.append(frame)
        if dead:
            self._finish("peer stopped acknowledging", error=True)
            return
        if ack is not None:
            self._transmit(ack)
        _sysrandom.shuffle(to_send)  # retransmits too go out in random order
        for frame in to_send:
            self._transmit(frame)

    # ----------------------------------------------------------------- close
    def close(self, reason: int = 0) -> None:
        """Local teardown; notifies the peer (best effort, sent twice)."""
        if self._closed:
            return
        frame = StreamClose(self.stream_id, reason).encode()
        self._transmit(frame)
        self._transmit(frame)
        self._finish("closed locally", error=False, notify_error=False)

    def _finish(self, why: str, error: bool, notify_error: bool = True) -> None:
        with self._cv:
            if self._closed:
                return
            self._closed = True
            self._unacked.clear()
            self._cv.notify_all()
            eof_pending = not self._eof_delivered
            self._eof_delivered = True
        if eof_pending:
            try:
                self._on_eof()
            except Exception:
                pass
        if error and notify_error:
            try:
                self._on_error(why)
            except Exception:
                pass

    # ------------------------------------------------------------ properties
    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def both_directions_done(self) -> bool:
        """True once we sent FIN and it was acked, and the peer's FIN arrived."""
        with self._lock:
            return self._fin_sent and not self._unacked and self._fin_received

    def in_flight(self) -> int:
        with self._lock:
            return len(self._unacked)
