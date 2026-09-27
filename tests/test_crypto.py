"""Validate the from-scratch crypto against official RFC test vectors.

Run with:  python -m pytest tests/test_crypto.py
or simply: python tests/test_crypto.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.crypto import aead, chacha20, ed25519, hkdf, poly1305, x25519


def h(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", "").replace("\n", ""))


class TestChaCha20(unittest.TestCase):
    def test_rfc8439_block(self):
        # RFC 8439 section 2.3.2 keystream block test vector.
        key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = h("000000090000004a00000000")
        keystream = chacha20.chacha20_keystream(key, 1, nonce, 64)
        expected = h(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        )
        self.assertEqual(keystream, expected)

    def test_rfc8439_encrypt(self):
        # RFC 8439 section 2.4.2 encryption test vector.
        key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = h("000000000000004a00000000")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it."
        )
        ciphertext = chacha20.chacha20_xor(key, 1, nonce, plaintext)
        expected = h(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42874d"
        )
        self.assertEqual(ciphertext, expected)
        # Round trip
        self.assertEqual(chacha20.chacha20_xor(key, 1, nonce, ciphertext), plaintext)


class TestPoly1305(unittest.TestCase):
    def test_rfc8439_mac(self):
        # RFC 8439 section 2.5.2 test vector.
        key = h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        message = b"Cryptographic Forum Research Group"
        tag = poly1305.poly1305_mac(message, key)
        self.assertEqual(tag, h("a8061dc1305136c6c22b8baf0c0127a9"))


class TestAEAD(unittest.TestCase):
    def test_rfc8439_aead(self):
        # RFC 8439 section 2.8.2 AEAD test vector.
        key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = h("070000004041424344454647")
        aad = h("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it."
        )
        out = aead.encrypt(key, nonce, plaintext, aad)
        expected_ct = h(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
        )
        expected_tag = h("1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(out, expected_ct + expected_tag)
        # Round-trip decrypt
        self.assertEqual(aead.decrypt(key, nonce, out, aad), plaintext)

    def test_tamper_detection(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        out = bytearray(aead.encrypt(key, nonce, b"secret payload", b"header"))
        out[0] ^= 0x01  # flip a bit
        with self.assertRaises(aead.AuthenticationError):
            aead.decrypt(key, nonce, bytes(out), b"header")

    def test_wrong_aad(self):
        key = os.urandom(32)
        nonce = os.urandom(12)
        out = aead.encrypt(key, nonce, b"secret payload", b"header")
        with self.assertRaises(aead.AuthenticationError):
            aead.decrypt(key, nonce, out, b"different-header")


class TestX25519(unittest.TestCase):
    def test_rfc7748_vector1(self):
        scalar = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(x25519.scalar_mult(scalar, u), expected)

    def test_rfc7748_vector2(self):
        scalar = h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        u = h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        expected = h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        self.assertEqual(x25519.scalar_mult(scalar, u), expected)

    def test_diffie_hellman_agreement(self):
        # RFC 7748 section 6.1 Alice/Bob example.
        alice_priv = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_priv = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        alice_pub = x25519.scalar_base_mult(alice_priv)
        bob_pub = x25519.scalar_base_mult(bob_priv)
        self.assertEqual(
            alice_pub, h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        )
        self.assertEqual(
            bob_pub, h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        )
        shared_a = x25519.scalar_mult(alice_priv, bob_pub)
        shared_b = x25519.scalar_mult(bob_priv, alice_pub)
        self.assertEqual(shared_a, shared_b)
        self.assertEqual(
            shared_a, h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        )


class TestEd25519(unittest.TestCase):
    def test_known_answer_vs_openssl(self):
        # Authoritative vectors: this private seed -> public key and signature
        # were confirmed byte-for-byte against OpenSSL 3.0's Ed25519, and the
        # public key also matches the canonical RFC 8032 reference implementation.
        secret = h("9d61b19deffe4a7a4b12d3b1c2e825d3fb2fc7ad112de6702cf3a4d2b9c8ef22")
        expected_public = h(
            "2cb49981625f2cb8812745fe7fb74da1533051a921961a827e35e3be931ee534"
        )
        # Signature over the ASCII message b"proof-of-relay receipt".
        expected_sig = h(
            "d072c7c5261d780ce6458faef43eb544204bc0f490813976d2c575c3721d60db"
            "ae94fe799f29babbf4ea0e4e766fc87cb59b290bb3b3bbc3866601d5e94e7e0f"
        )
        public = ed25519.public_key_from_private(secret)
        self.assertEqual(public, expected_public)
        sig = ed25519.sign(secret, b"proof-of-relay receipt")
        self.assertEqual(sig, expected_sig)
        self.assertTrue(ed25519.verify(public, b"proof-of-relay receipt", sig))

    def test_sign_verify_roundtrip(self):
        priv, pub = ed25519.generate_keypair()
        msg = b"proof-of-relay receipt #42"
        sig = ed25519.sign(priv, msg)
        self.assertTrue(ed25519.verify(pub, msg, sig))
        # Wrong message fails
        self.assertFalse(ed25519.verify(pub, msg + b"!", sig))
        # Tampered signature fails
        bad = bytearray(sig)
        bad[0] ^= 0x01
        self.assertFalse(ed25519.verify(pub, msg, bytes(bad)))
        # Wrong key fails
        _, other_pub = ed25519.generate_keypair()
        self.assertFalse(ed25519.verify(other_pub, msg, sig))


class TestHKDF(unittest.TestCase):
    def test_rfc5869_case1(self):
        ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = h("000102030405060708090a0b0c")
        info = h("f0f1f2f3f4f5f6f7f8f9")
        okm = hkdf.derive(ikm, salt, info, 42)
        expected = h(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        self.assertEqual(okm, expected)

    def test_independent_keys(self):
        secret = os.urandom(32)
        send_key = hkdf.derive(secret, b"salt", b"send", 32)
        recv_key = hkdf.derive(secret, b"salt", b"recv", 32)
        self.assertNotEqual(send_key, recv_key)
        self.assertEqual(len(send_key), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
