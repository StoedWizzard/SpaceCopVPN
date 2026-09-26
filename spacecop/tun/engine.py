"""Packet engine: a small userspace TCP/IP stack that turns TUN packets into
overlay streams (what "tun2socks" does, written from scratch).

With a TUN interface (Linux ``/dev/net/tun``, Android ``VpnService``) the OS
hands us *every* IP packet the device sends.  The overlay carries TCP byte
streams, not packets, so this module terminates TCP locally: for each
connection an application opens it plays the remote host — answers the SYN,
acknowledges data, honours the window, sends FIN/RST — while the payload is
carried by a :class:`~spacecop.client.vpnclient.ClientStream` to the real
destination through a node.  The application never notices.

Supported:
* IPv4 + TCP — full connections (HTTPS, SSH, anything).
* IPv4 + UDP port 53 — DNS queries are forwarded through the tunnel as
  DNS-over-TCP to ``dns_server`` and answered as UDP, so no DNS leaks.
* ICMP echo to the tunnel gateway — so ``ping 10.77.0.1`` works.
Dropped (documented): other UDP (QUIC falls back to TCP automatically in
browsers because we answer nothing), IPv6.

Thread model: one packet-reader thread per engine; per TCP connection one
"uplink" thread (app -> stream, blocks on the stream window) and one
"downlink" thread (stream -> app segments).  Writes to the TUN are
per-packet atomic, so many threads may write.
"""

from __future__ import annotations

import os
import random
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

import queue as _queue

from .base import TunInterface

_sysrandom = random.SystemRandom()

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

DEFAULT_MSS = 1360           # fits a 1400 MTU with IP+TCP headers
APP_RETRANSMIT_AFTER = 0.6   # seconds without ACK progress before we resend to the app
APP_DEAD_AFTER = 20.0        # give up on an app that never acks
CONN_IDLE_TIMEOUT = 15 * 60.0


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_header(src: bytes, dst: bytes, proto: int, payload_len: int, ident: int = 0) -> bytes:
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, 64, proto, 0, src, dst)
    csum = _checksum(hdr)
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:]


def _l4_checksum(src: bytes, dst: bytes, proto: int, segment: bytes) -> int:
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(segment))
    return _checksum(pseudo + segment)


def build_tcp(src: bytes, sport: int, dst: bytes, dport: int, seq: int, ack: int,
              flags: int, window: int, payload: bytes = b"", mss: Optional[int] = None) -> bytes:
    options = struct.pack("!BBH", 2, 4, mss) if mss is not None else b""
    data_offset = (5 + len(options) // 4) << 4
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      data_offset, flags, window, 0, 0) + options + payload
    csum = _l4_checksum(src, dst, IP_PROTO_TCP, tcp)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    return _ip_header(src, dst, IP_PROTO_TCP, len(tcp), _sysrandom.randrange(65536)) + tcp


def build_udp(src: bytes, sport: int, dst: bytes, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = _l4_checksum(src, dst, IP_PROTO_UDP, udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", csum) + udp[8:]
    return _ip_header(src, dst, IP_PROTO_UDP, len(udp), _sysrandom.randrange(65536)) + udp


def build_icmp_echo_reply(src: bytes, dst: bytes, icmp_in: bytes) -> bytes:
    body = b"\x00\x00\x00\x00" + icmp_in[4:]  # type 0 (echo reply), code 0, csum 0
    csum = _checksum(body)
    body = body[:2] + struct.pack("!H", csum) + body[4:]
    return _ip_header(src, dst, IP_PROTO_ICMP, len(body))


@dataclass
class _TcpSeg:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    mss: Optional[int]
    payload: bytes


def parse_tcp(segment: bytes) -> Optional[_TcpSeg]:
    if len(segment) < 20:
        return None
    sport, dport, seq, ack, off_flags, window = struct.unpack("!HHIIHH", segment[:16])
    data_offset = (off_flags >> 12) * 4
    flags = off_flags & 0x1FF
    if data_offset < 20 or data_offset > len(segment):
        return None
    mss = None
    opts = segment[20:data_offset]
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        if length < 2:
            break
        if kind == 2 and length == 4:
            mss = struct.unpack("!H", opts[i + 2:i + 4])[0]
        i += length
    return _TcpSeg(sport, dport, seq, ack, flags, window, mss, segment[data_offset:])


def _seq_lt(a: int, b: int) -> bool:
    return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF


def _seq_le(a: int, b: int) -> bool:
    return a == b or _seq_lt(a, b)


# ---------------------------------------------------------------------------
# One terminated TCP connection
# ---------------------------------------------------------------------------
class _TcpConn:
    """We are the "server" for a connection the app initiated toward dst."""

    def __init__(self, engine: "PacketEngine", key, app_seq: int, app_mss: Optional[int],
                 app_window: int):
        self.engine = engine
        self.key = key                      # (app_ip, app_port, dst_ip, dst_port)
        self.app_ip, self.app_port, self.dst_ip, self.dst_port = key
        self.mss = min(app_mss or DEFAULT_MSS, DEFAULT_MSS)
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)

        # Sequence space toward the app.
        self.snd_iss = _sysrandom.randrange(1 << 32)
        self.snd_una = self.snd_iss         # oldest unacknowledged byte (ours)
        self.snd_nxt = self.snd_iss         # next seq we will send
        self.app_window = app_window or 65535
        self.retrans = bytearray()          # bytes from snd_una..snd_nxt (after SYN)
        self.last_ack_progress = time.monotonic()
        self.last_sent = 0.0

        # Sequence space from the app.
        self.rcv_nxt = (app_seq + 1) & 0xFFFFFFFF

        self.state = "SYN_RCVD"
        self.stream = None
        self.uplink: "_queue.Queue" = _queue.Queue()
        self.app_fin = False                # app closed its write side
        self.our_fin_sent = False
        self.our_fin_seq = None
        self.done = False
        self.opened_at = time.monotonic()
        self.last_activity = time.monotonic()

    # -- sending to the app --------------------------------------------------
    def _send(self, flags: int, payload: bytes = b"", seq: Optional[int] = None,
              mss: Optional[int] = None) -> None:
        pkt = build_tcp(self.dst_ip, self.dst_port, self.app_ip, self.app_port,
                        self.snd_nxt if seq is None else seq, self.rcv_nxt, flags,
                        65535, payload, mss)
        self.engine.tun.write_packet(pkt)
        self.last_sent = time.monotonic()

    def send_syn_ack(self) -> None:
        self._send(TCP_SYN | TCP_ACK, seq=self.snd_iss, mss=self.mss)
        self.snd_nxt = (self.snd_iss + 1) & 0xFFFFFFFF
        self.snd_una = self.snd_nxt

    def send_ack(self) -> None:
        self._send(TCP_ACK)

    def send_rst(self) -> None:
        try:
            self._send(TCP_RST | TCP_ACK)
        except Exception:
            pass

    def deliver_to_app(self, data: bytes) -> None:
        """Split ``data`` into segments, honouring the app's window."""
        view = memoryview(data)
        off = 0
        while off < len(view):
            with self.cv:
                deadline = time.monotonic() + APP_DEAD_AFTER
                while (not self.done and
                       ((self.snd_nxt - self.snd_una) & 0xFFFFFFFF) + self.mss > self.app_window
                       and self.app_window > 0):
                    if time.monotonic() > deadline:
                        self.done = True
                    self.cv.wait(0.2)
                if self.done:
                    return
                chunk = bytes(view[off:off + self.mss])
                off += len(chunk)
                seq = self.snd_nxt
                self.snd_nxt = (self.snd_nxt + len(chunk)) & 0xFFFFFFFF
                self.retrans.extend(chunk)
            self._send(TCP_PSH | TCP_ACK, chunk, seq=seq)

    def send_fin(self) -> None:
        with self.lock:
            if self.our_fin_sent or self.done:
                return
            self.our_fin_sent = True
            self.our_fin_seq = self.snd_nxt
            seq = self.snd_nxt
            self.snd_nxt = (self.snd_nxt + 1) & 0xFFFFFFFF
        self._send(TCP_FIN | TCP_ACK, seq=seq)

    # -- receiving from the app ---------------------------------------------
    def on_segment(self, seg: _TcpSeg) -> None:
        self.last_activity = time.monotonic()
        if seg.flags & TCP_RST:
            self.close(rst=False)
            return
        if seg.flags & TCP_ACK:
            self._on_app_ack(seg.ack, seg.window)
        if self.state == "SYN_RCVD":
            if seg.flags & TCP_ACK and seg.ack == self.snd_nxt:
                self.state = "ESTABLISHED"
            elif seg.flags & TCP_SYN:
                self.send_syn_ack()  # retransmitted SYN
                return
        if seg.payload:
            if seg.seq == self.rcv_nxt:
                self.rcv_nxt = (self.rcv_nxt + len(seg.payload)) & 0xFFFFFFFF
                self.uplink.put(seg.payload)
                self.send_ack()
            elif _seq_lt(seg.seq, self.rcv_nxt):
                # Old/duplicate data (our ACK was lost): re-ack.
                self.send_ack()
            else:
                # Out of order (rare on a TUN): ask for what we expect.
                self.send_ack()
        if seg.flags & TCP_FIN and not self.app_fin:
            fin_seq = (seg.seq + len(seg.payload)) & 0xFFFFFFFF
            if fin_seq == self.rcv_nxt:
                self.app_fin = True
                self.rcv_nxt = (self.rcv_nxt + 1) & 0xFFFFFFFF
                self.uplink.put(None)   # EOF toward the stream
                self.send_ack()
        self._maybe_finish()

    def _on_app_ack(self, ack: int, window: int) -> None:
        with self.cv:
            self.app_window = window
            if _seq_lt(self.snd_una, ack) and _seq_le(ack, self.snd_nxt):
                advanced = (ack - self.snd_una) & 0xFFFFFFFF
                # The FIN occupies one sequence number but no retrans bytes.
                if self.our_fin_sent and self.our_fin_seq is not None and _seq_lt(self.our_fin_seq, ack):
                    advanced_bytes = max(0, advanced - 1)
                else:
                    advanced_bytes = advanced
                del self.retrans[:advanced_bytes]
                self.snd_una = ack
                self.last_ack_progress = time.monotonic()
            self.cv.notify_all()

    def _maybe_finish(self) -> None:
        with self.lock:
            fin_acked = self.our_fin_sent and self.snd_una == self.snd_nxt
            both = self.app_fin and fin_acked
        if both:
            self.close(rst=False)

    # -- maintenance ---------------------------------------------------------
    def tick(self, now: float) -> None:
        if self.done:
            return
        with self.lock:
            outstanding = bytes(self.retrans)
            base = self.snd_una
            stalled = outstanding and now - self.last_ack_progress > APP_RETRANSMIT_AFTER \
                and now - self.last_sent > APP_RETRANSMIT_AFTER
            dead = outstanding and now - self.last_ack_progress > APP_DEAD_AFTER
            idle = now - self.last_activity > CONN_IDLE_TIMEOUT
            if stalled:
                self.last_ack_progress = now  # pace retransmits
        if dead or idle:
            self.close(rst=True)
            return
        if stalled:
            # Resend from the oldest unacknowledged byte, one window's worth.
            off = 0
            while off < len(outstanding) and off < self.mss * 8:
                chunk = outstanding[off:off + self.mss]
                self._send(TCP_PSH | TCP_ACK, chunk, seq=(base + off) & 0xFFFFFFFF)
                off += len(chunk)
            if self.our_fin_sent and self.our_fin_seq is not None and \
                    _seq_le(self.snd_una, self.our_fin_seq):
                self._send(TCP_FIN | TCP_ACK, seq=self.our_fin_seq)

    def close(self, rst: bool) -> None:
        with self.cv:
            if self.done:
                return
            self.done = True
            self.cv.notify_all()
        if rst:
            self.send_rst()
        self.uplink.put(None)
        if self.stream is not None:
            try:
                self.stream.close()
            except Exception:
                pass
        self.engine._forget(self.key)


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------
class PacketEngine:
    def __init__(self, tun: TunInterface, client, gateway_ip: str = "10.77.0.1",
                 dns_server: Tuple[str, int] = ("1.1.1.1", 53),
                 on_event: Optional[Callable[[str], None]] = None,
                 rewrite: Optional[Callable[[str, int], Tuple[str, int]]] = None):
        self.tun = tun
        self.client = client
        self.gateway = socket.inet_aton(gateway_ip)
        self.dns_server = dns_server
        self.on_event = on_event
        # Optional (host, port) -> (host, port) mapping applied before a stream
        # is opened; used by tests and available for split routing.
        self.rewrite = rewrite
        self._conns: Dict[tuple, _TcpConn] = {}
        self._lock = threading.Lock()
        self._running = threading.Event()
        self._reader: Optional[threading.Thread] = None
        self._ticker: Optional[threading.Thread] = None
        # Stats
        self.tcp_opened = 0
        self.tcp_failed = 0
        self.dns_queries = 0
        self.bytes_up = 0
        self.bytes_down = 0

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        self._running.set()
        self._reader = threading.Thread(target=self._read_loop, daemon=True, name="spacecop-tun-read")
        self._reader.start()
        self._ticker = threading.Thread(target=self._tick_loop, daemon=True, name="spacecop-tun-tick")
        self._ticker.start()

    def stop(self) -> None:
        self._running.clear()
        with self._lock:
            conns = list(self._conns.values())
        for c in conns:
            c.close(rst=True)
        # Let the reader leave its select() before the fd goes away; a thread
        # blocked in read() would keep the TUN device alive ("resource busy").
        if self._reader is not None and self._reader is not threading.current_thread():
            self._reader.join(timeout=2.0)
        try:
            self.tun.close()
        except Exception:
            pass

    def active_connections(self) -> int:
        with self._lock:
            return len(self._conns)

    def _emit(self, text: str) -> None:
        if self.on_event:
            try:
                self.on_event(text)
            except Exception:
                pass

    def _forget(self, key) -> None:
        with self._lock:
            self._conns.pop(key, None)

    # -- packet loop ---------------------------------------------------------
    def _read_loop(self) -> None:
        fd = self.tun.fileno() if hasattr(self.tun, "fileno") else None
        while self._running.is_set():
            try:
                if fd is not None:
                    ready, _, _ = select.select([fd], [], [], 0.5)
                    if not ready:
                        continue
                pkt = self.tun.read_packet()
            except (OSError, ValueError):
                break
            if not pkt:
                continue
            try:
                self._handle_packet(pkt)
            except Exception as exc:  # never let one bad packet kill the loop
                self._emit(f"packet error: {exc}")

    def _handle_packet(self, pkt: bytes) -> None:
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            return  # not IPv4 (IPv6 is dropped by design)
        ihl = (pkt[0] & 0x0F) * 4
        total = struct.unpack("!H", pkt[2:4])[0]
        proto = pkt[9]
        src, dst = pkt[12:16], pkt[16:20]
        payload = pkt[ihl:total] if total <= len(pkt) else pkt[ihl:]
        if proto == IP_PROTO_TCP:
            self._handle_tcp(src, dst, payload)
        elif proto == IP_PROTO_UDP:
            self._handle_udp(src, dst, payload)
        elif proto == IP_PROTO_ICMP and dst == self.gateway and payload[:1] == b"\x08":
            self.tun.write_packet(build_icmp_echo_reply(dst, src, payload))

    # -- TCP -------------------------------------------------------------------
    def _handle_tcp(self, src: bytes, dst: bytes, segment: bytes) -> None:
        seg = parse_tcp(segment)
        if seg is None:
            return
        key = (src, seg.sport, dst, seg.dport)
        with self._lock:
            conn = self._conns.get(key)
        if conn is None:
            if seg.flags & TCP_SYN and not (seg.flags & TCP_ACK):
                self._open_conn(key, seg)
            elif not (seg.flags & TCP_RST):
                # Stray segment for an unknown connection: reset it.
                self.tun.write_packet(build_tcp(dst, seg.dport, src, seg.sport,
                                                seg.ack, (seg.seq + len(seg.payload)) & 0xFFFFFFFF,
                                                TCP_RST | TCP_ACK, 0))
            return
        conn.on_segment(seg)

    def _open_conn(self, key, seg: _TcpSeg) -> None:
        conn = _TcpConn(self, key, seg.seq, seg.mss, seg.window)
        with self._lock:
            self._conns[key] = conn
        # Reply SYN-ACK immediately (the app sees a fast connect); open the
        # overlay stream in the background and RST if that fails.
        conn.send_syn_ack()
        threading.Thread(target=self._connect_worker, args=(conn,), daemon=True).start()

    def _connect_worker(self, conn: _TcpConn) -> None:
        host, port = socket.inet_ntoa(conn.dst_ip), conn.dst_port
        if self.rewrite is not None:
            host, port = self.rewrite(host, port)
        try:
            stream = self.client.open_stream(host, port, timeout=15.0)
        except Exception as exc:
            self.tcp_failed += 1
            self._emit(f"connect {host}:{conn.dst_port} failed: {exc}")
            conn.close(rst=True)
            return
        if conn.done:
            stream.close()
            return
        conn.stream = stream
        self.tcp_opened += 1
        threading.Thread(target=self._uplink, args=(conn,), daemon=True).start()
        threading.Thread(target=self._downlink, args=(conn,), daemon=True).start()

    def _uplink(self, conn: _TcpConn) -> None:
        """app -> overlay"""
        try:
            while True:
                item = conn.uplink.get()
                if item is None:
                    conn.stream.send_eof()
                    break
                self.bytes_up += len(item)
                conn.stream.send(item)
        except Exception:
            conn.close(rst=True)

    def _downlink(self, conn: _TcpConn) -> None:
        """overlay -> app"""
        try:
            while not conn.done:
                chunk = conn.stream.recv()
                if not chunk:
                    conn.send_fin()
                    break
                self.bytes_down += len(chunk)
                conn.deliver_to_app(chunk)
        except Exception:
            conn.close(rst=True)

    # -- UDP (DNS only) ----------------------------------------------------------
    def _handle_udp(self, src: bytes, dst: bytes, datagram: bytes) -> None:
        if len(datagram) < 8:
            return
        sport, dport, length = struct.unpack("!HHH", datagram[:6])
        payload = datagram[8:length] if length <= len(datagram) else datagram[8:]
        if dport != 53 or not payload:
            return  # other UDP is not carried (QUIC etc. fall back to TCP)
        self.dns_queries += 1
        threading.Thread(target=self._dns_worker, args=(src, sport, dst, payload),
                         daemon=True).start()

    def _dns_worker(self, app_ip: bytes, app_port: int, dns_ip: bytes, query: bytes) -> None:
        """Forward one DNS query through the tunnel as DNS-over-TCP."""
        try:
            stream = self.client.open_stream(self.dns_server[0], self.dns_server[1], timeout=10.0)
        except Exception as exc:
            self._emit(f"dns: cannot reach resolver through the tunnel: {exc}")
            return
        try:
            stream.send(struct.pack("!H", len(query)) + query)
            stream.send_eof()
            buf = b""
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                chunk = stream.recv(timeout=max(0.1, deadline - time.monotonic()))
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 2 and len(buf) >= 2 + struct.unpack("!H", buf[:2])[0]:
                    break
            if len(buf) >= 2:
                n = struct.unpack("!H", buf[:2])[0]
                answer = buf[2:2 + n]
                if answer:
                    self.tun.write_packet(build_udp(dns_ip, 53, app_ip, app_port, answer))
        except Exception as exc:
            self._emit(f"dns error: {exc}")
        finally:
            try:
                stream.close()
            except Exception:
                pass

    # -- maintenance ---------------------------------------------------------
    def _tick_loop(self) -> None:
        while self._running.is_set():
            time.sleep(0.2)
            now = time.monotonic()
            with self._lock:
                conns = list(self._conns.values())
            for c in conns:
                try:
                    c.tick(now)
                except Exception:
                    pass
