"""Tests for the wire protocol: handshake, sessions, replay, and codecs."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.protocol import (
    ClientHandshake,
    HandshakeError,
    NodeHandshake,
    NodeIdentity,
    ReplayError,
    Session,
    constants as c,
    framing,
    messages,
)


class TestFraming(unittest.TestCase):
    def test_roundtrip(self):
        frame = framing.encode_frame(c.MSG_DATA, b"hello")
        msg_type, body = framing.decode_frame(frame)
        self.assertEqual(msg_type, c.MSG_DATA)
        self.assertEqual(body, b"hello")

    def test_bad_magic(self):
        with self.assertRaises(framing.ProtocolError):
            framing.decode_frame(b"XX\x01\x03body")

    def test_bad_version(self):
        with self.assertRaises(framing.ProtocolError):
            framing.decode_frame(c.MAGIC + bytes([99, c.MSG_DATA]))

    def test_primitive_codecs(self):
        buf = bytearray()
        framing.write_u8(buf, 7)
        framing.write_u16(buf, 258)
        framing.write_u32(buf, 70000)
        framing.write_u64(buf, 10 ** 12)
        framing.write_bytes(buf, b"payload")
        data = bytes(buf)
        v8, off = framing.read_u8(data, 0)
        v16, off = framing.read_u16(data, off)
        v32, off = framing.read_u32(data, off)
        v64, off = framing.read_u64(data, off)
        field, off = framing.read_bytes(data, off)
        self.assertEqual((v8, v16, v32, v64, field), (7, 258, 70000, 10 ** 12, b"payload"))


class TestHandshake(unittest.TestCase):
    def test_full_handshake_and_agreement(self):
        node_id = NodeIdentity.generate()
        client = ClientHandshake(node_id.x_public, expected_node_ed_pub=node_id.ed_public)
        init = client.build_init()
        msg_type, init_body = framing.decode_frame(init)
        self.assertEqual(msg_type, c.MSG_HANDSHAKE_INIT)

        node = NodeHandshake(node_id)
        resp_frame, node_session = node.handle_init(init_body)
        _, resp_body = framing.decode_frame(resp_frame)
        client_session = client.consume_response(resp_body)

        # The two sessions must agree on complementary keys.
        self.assertEqual(client_session.send_key, node_session.recv_key)
        self.assertEqual(client_session.recv_key, node_session.send_key)
        self.assertEqual(client_session.session_id, node_session.session_id)
        # Client learned and verified the node's identity.
        self.assertEqual(client_session.peer_identity, node_id.ed_public)

    def test_wrong_expected_identity_rejected(self):
        node_id = NodeIdentity.generate()
        other_id = NodeIdentity.generate()
        client = ClientHandshake(node_id.x_public, expected_node_ed_pub=other_id.ed_public)
        _, init_body = framing.decode_frame(client.build_init())
        node = NodeHandshake(node_id)
        resp_frame, _ = node.handle_init(init_body)
        _, resp_body = framing.decode_frame(resp_frame)
        with self.assertRaises(HandshakeError):
            client.consume_response(resp_body)

    def test_tampered_response_rejected(self):
        node_id = NodeIdentity.generate()
        client = ClientHandshake(node_id.x_public)
        _, init_body = framing.decode_frame(client.build_init())
        node = NodeHandshake(node_id)
        resp_frame, _ = node.handle_init(init_body)
        _, resp_body = framing.decode_frame(resp_frame)
        tampered = bytearray(resp_body)
        tampered[-1] ^= 0x01
        with self.assertRaises(HandshakeError):
            client.consume_response(bytes(tampered))

    def test_stale_timestamp_rejected(self):
        node_id = NodeIdentity.generate()
        client = ClientHandshake(node_id.x_public)
        _, init_body = framing.decode_frame(client.build_init())
        # Rewind the embedded timestamp far into the past.
        import struct
        stale = bytearray(init_body)
        old = int(time.time()) - (c.MAX_CLOCK_SKEW_SECONDS + 60)
        stale[-8:] = struct.pack("!Q", old)
        node = NodeHandshake(node_id)
        with self.assertRaises(HandshakeError):
            node.handle_init(bytes(stale))


class TestSession(unittest.TestCase):
    def _pair(self):
        node_id = NodeIdentity.generate()
        client = ClientHandshake(node_id.x_public)
        _, init_body = framing.decode_frame(client.build_init())
        node = NodeHandshake(node_id)
        resp_frame, node_session = node.handle_init(init_body)
        _, resp_body = framing.decode_frame(resp_frame)
        client_session = client.consume_response(resp_body)
        return client_session, node_session

    def test_encrypt_decrypt_roundtrip(self):
        client_session, node_session = self._pair()
        for i in range(5):
            msg = f"packet number {i}".encode() * 100
            sealed = client_session.seal(msg)
            self.assertEqual(node_session.open(sealed), msg)

    def test_bidirectional(self):
        client_session, node_session = self._pair()
        c2n = client_session.seal(b"hello node")
        self.assertEqual(node_session.open(c2n), b"hello node")
        n2c = node_session.seal(b"hello client")
        self.assertEqual(client_session.open(n2c), b"hello client")

    def test_replay_rejected(self):
        client_session, node_session = self._pair()
        sealed = client_session.seal(b"once")
        self.assertEqual(node_session.open(sealed), b"once")
        with self.assertRaises(ReplayError):
            node_session.open(sealed)

    def test_out_of_order_accepted(self):
        client_session, node_session = self._pair()
        s0 = client_session.seal(b"zero")
        s1 = client_session.seal(b"one")
        s2 = client_session.seal(b"two")
        # Deliver out of order: 2, 0, 1
        self.assertEqual(node_session.open(s2), b"two")
        self.assertEqual(node_session.open(s0), b"zero")
        self.assertEqual(node_session.open(s1), b"one")
        # And a replay of any of them still fails.
        with self.assertRaises(ReplayError):
            node_session.open(s0)

    def test_tamper_rejected(self):
        client_session, node_session = self._pair()
        sealed = bytearray(client_session.seal(b"secret"))
        sealed[-1] ^= 0x01
        from spacecop.crypto import aead
        with self.assertRaises(aead.AuthenticationError):
            node_session.open(bytes(sealed))


class TestMessageCodecs(unittest.TestCase):
    def test_data_message(self):
        m = messages.DataMessage(session_id=b"12345678", sealed=b"\x00" * 40)
        frame = m.encode()
        _, body = framing.decode_frame(frame)
        back = messages.DataMessage.decode(body)
        self.assertEqual(back.session_id, b"12345678")
        self.assertEqual(back.sealed, b"\x00" * 40)

    def test_ack_message(self):
        m = messages.AckMessage(session_id=b"sessid00", group_id=42, indices=[0, 3, 7, 65535])
        _, body = framing.decode_frame(m.encode())
        back = messages.AckMessage.decode(body)
        self.assertEqual(back.group_id, 42)
        self.assertEqual(back.indices, [0, 3, 7, 65535])

    def test_node_announce_sign_verify(self):
        node_id = NodeIdentity.generate()
        ann = messages.NodeAnnounce(
            ed_public=node_id.ed_public, x_public=node_id.x_public,
            host="203.0.113.5", port=51820, score=123, timestamp=int(time.time()),
        ).sign(node_id.ed_private)
        _, body = framing.decode_frame(ann.encode())
        back = messages.NodeAnnounce.decode(body)
        self.assertTrue(back.verify())
        self.assertEqual(back.host, "203.0.113.5")
        self.assertEqual(back.port, 51820)
        # Tampering with the advertised score breaks the signature.
        back.score = 999999
        self.assertFalse(back.verify())

    def test_peer_list(self):
        entries = [
            messages.PeerEntry(os.urandom(32), os.urandom(32), "10.0.0.1", 5000),
            messages.PeerEntry(os.urandom(32), os.urandom(32), "example.net", 6000),
        ]
        m = messages.PeerList(entries)
        _, body = framing.decode_frame(m.encode())
        back = messages.PeerList.decode(body)
        self.assertEqual(len(back.peers), 2)
        self.assertEqual(back.peers[1].host, "example.net")
        self.assertEqual(back.peers[0].port, 5000)

    def test_receipt_sign_verify(self):
        from spacecop.crypto import ed25519
        client_priv, client_pub = ed25519.generate_keypair()
        node_priv, node_pub = ed25519.generate_keypair()
        r = messages.Receipt(
            client_ed_public=client_pub, node_ed_public=node_pub,
            seq=7, byte_count=20480, timestamp=int(time.time()),
        ).sign(client_priv)
        _, body = framing.decode_frame(r.encode())
        back = messages.Receipt.decode(body)
        self.assertTrue(back.verify())
        self.assertEqual(back.byte_count, 20480)
        back.byte_count = 1  # tamper
        self.assertFalse(back.verify())

    def test_relay_request(self):
        m = messages.RelayRequest(request_id=b"\x01\x02", dest_host="1.2.3.4",
                                  dest_port=443, blob=b"opaque ciphertext")
        _, body = framing.decode_frame(m.encode())
        back = messages.RelayRequest.decode(body)
        self.assertEqual(back.dest_host, "1.2.3.4")
        self.assertEqual(back.dest_port, 443)
        self.assertEqual(back.blob, b"opaque ciphertext")


if __name__ == "__main__":
    unittest.main(verbosity=2)
