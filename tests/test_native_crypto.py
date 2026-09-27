"""The native ChaCha20-Poly1305 library must be byte-for-byte identical to the
pure-Python reference (RFC 8439 vectors + random cross-checks), and the AEAD
layer must fall back cleanly when the library is absent."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.crypto import aead, chacha20, native, poly1305  # noqa: E402

# RFC 8439 section 2.8.2 AEAD test vector.
_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
_NONCE = bytes.fromhex("070000004041424344454647")
_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
_PT = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
       b"tip for the future, sunscreen would be it.")
_CT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116")
_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

needs_native = unittest.skipUnless(native.available(), "native library not built (native/build.sh)")


class TestPureReference(unittest.TestCase):
    """The pure-Python path is always exercised, even when the library is loaded."""

    def test_rfc_vector_pure(self):
        self.assertEqual(aead._encrypt_pure(_KEY, _NONCE, _PT, _AAD), _CT + _TAG)
        self.assertEqual(aead._decrypt_pure(_KEY, _NONCE, _CT + _TAG, _AAD), _PT)


@needs_native
class TestNativeCrypto(unittest.TestCase):
    def test_version_and_path(self):
        self.assertTrue(native.version())
        self.assertTrue(os.path.isfile(native.path()))
        self.assertTrue(aead.backend().startswith("native"))

    def test_rfc_vector_native(self):
        self.assertEqual(native.aead_encrypt(_KEY, _NONCE, _PT, _AAD), _CT + _TAG)
        self.assertEqual(native.aead_decrypt(_KEY, _NONCE, _CT + _TAG, _AAD), _PT)

    def test_chacha20_and_poly1305_primitives_match(self):
        key, nonce = os.urandom(32), os.urandom(12)
        for n in (0, 1, 63, 64, 65, 1000, 20480):
            data = os.urandom(n)
            self.assertEqual(native.chacha20_xor(key, 7, nonce, data),
                             chacha20.chacha20_xor(key, 7, nonce, data))
            self.assertEqual(native.poly1305(key, data), poly1305.poly1305_mac(data, key))

    def test_random_equivalence_all_sizes(self):
        for n in (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1199, 1200, 1201, 20480, 65536):
            key, nonce = os.urandom(32), os.urandom(12)
            aad = os.urandom(n % 37)
            pt = os.urandom(n)
            ct_native = native.aead_encrypt(key, nonce, pt, aad)
            ct_pure = aead._encrypt_pure(key, nonce, pt, aad)
            self.assertEqual(ct_native, ct_pure, n)
            self.assertEqual(native.aead_decrypt(key, nonce, ct_native, aad), pt)
            self.assertEqual(aead._decrypt_pure(key, nonce, ct_native, aad), pt)

    def test_tamper_and_wrong_aad_rejected(self):
        key, nonce = os.urandom(32), os.urandom(12)
        ct = aead.encrypt(key, nonce, b"hello", b"aad")
        for i in range(len(ct)):
            bad = bytearray(ct)
            bad[i] ^= 0x01
            with self.assertRaises(aead.AuthenticationError):
                aead.decrypt(key, nonce, bytes(bad), b"aad")
        with self.assertRaises(aead.AuthenticationError):
            aead.decrypt(key, nonce, ct, b"AAD")
        with self.assertRaises(aead.AuthenticationError):
            aead.decrypt(key, nonce, ct[:15], b"aad")

    def test_native_and_pure_interoperate(self):
        """A session encrypting natively must decrypt on a pure-Python peer and back."""
        key, nonce = os.urandom(32), os.urandom(12)
        pt = os.urandom(5000)
        self.assertEqual(aead._decrypt_pure(key, nonce, native.aead_encrypt(key, nonce, pt, b""), b""), pt)
        self.assertEqual(native.aead_decrypt(key, nonce, aead._encrypt_pure(key, nonce, pt, b""), b""), pt)


class TestFallback(unittest.TestCase):
    def test_disable_switches_to_python(self):
        was = native.available()
        try:
            native.disable()
            self.assertFalse(native.available())
            self.assertEqual(aead.backend(), "python")
            self.assertEqual(aead.encrypt(_KEY, _NONCE, _PT, _AAD), _CT + _TAG)
        finally:
            native._tried = False
            native._lib = None
            self.assertEqual(native.available(), was)


if __name__ == "__main__":
    unittest.main(verbosity=2)
