"""Tests for connection URIs and persistent node identities."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.protocol import HandshakeError, NodeIdentity
from spacecop.protocol.uri import URIError, build_uri, parse_uri, try_parse


class TestURI(unittest.TestCase):
    def test_roundtrip_with_identity(self):
        ident = NodeIdentity.generate()
        text = build_uri("203.0.113.9", 51820, ident.x_public, ident.ed_public)
        self.assertTrue(text.startswith("spacecop://203.0.113.9:51820/"))
        parsed = parse_uri(text)
        self.assertEqual(parsed.host, "203.0.113.9")
        self.assertEqual(parsed.port, 51820)
        self.assertEqual(parsed.x_public, ident.x_public)
        self.assertEqual(parsed.ed_public, ident.ed_public)
        self.assertEqual(str(parsed), text)

    def test_roundtrip_without_identity(self):
        ident = NodeIdentity.generate()
        parsed = parse_uri(build_uri("vpn.example.net", 5000, ident.x_public))
        self.assertEqual(parsed.host, "vpn.example.net")
        self.assertEqual(parsed.ed_public, b"")

    def test_ipv6_literal(self):
        ident = NodeIdentity.generate()
        text = build_uri("2001:db8::1", 51820, ident.x_public)
        self.assertIn("[2001:db8::1]:51820", text)
        self.assertEqual(parse_uri(text).host, "2001:db8::1")

    def test_invalid(self):
        for bad in ("http://x:1/aa", "spacecop://host/aa", "spacecop://host:abc/aa",
                    "spacecop://host:1/zz", "spacecop://host:1/" + "00" * 31,
                    "spacecop://host:99999/" + "00" * 32):
            with self.assertRaises(URIError, msg=bad):
                parse_uri(bad)
        self.assertIsNone(try_parse("garbage"))


class TestIdentityPersistence(unittest.TestCase):
    def test_save_load_roundtrip(self):
        ident = NodeIdentity.generate()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "identity.json")
            os.makedirs(os.path.dirname(path))
            ident.save(path)
            if os.name == "posix":  # Windows has no POSIX mode bits
                self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))
            loaded = NodeIdentity.load(path)
            self.assertEqual(loaded.ed_private, ident.ed_private)
            self.assertEqual(loaded.x_public, ident.x_public)

    def test_load_or_create(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "id.json")
            first = NodeIdentity.load_or_create(path)
            second = NodeIdentity.load_or_create(path)
            self.assertEqual(first.ed_public, second.ed_public)

    def test_corrupt_rejected(self):
        ident = NodeIdentity.generate()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "id.json")
            ident.save(path)
            with open(path, encoding="utf-8") as f:
                text = f.read().replace(ident.ed_public.hex(), "00" * 32)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            with self.assertRaises(HandshakeError):
                NodeIdentity.load(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
