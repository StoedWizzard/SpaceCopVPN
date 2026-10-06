"""Tests for the scoring ledger and proof-of-work."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.crypto import ed25519
from spacecop.node import Ledger, meets_difficulty, mine, points_for_bytes
from spacecop.node.scoring import BYTES_PER_POINT
from spacecop.protocol.messages import Receipt


class TestScoring(unittest.TestCase):
    def _receipt(self, client_priv, client_pub, node_pub, seq, byte_count):
        return Receipt(
            client_ed_public=client_pub, node_ed_public=node_pub,
            seq=seq, byte_count=byte_count, timestamp=int(time.time()),
        ).sign(client_priv)

    def test_points_formula(self):
        self.assertEqual(points_for_bytes(0), 0)
        self.assertEqual(points_for_bytes(1), 1)
        self.assertEqual(points_for_bytes(BYTES_PER_POINT), 1)
        self.assertEqual(points_for_bytes(BYTES_PER_POINT + 1), 2)
        self.assertEqual(points_for_bytes(BYTES_PER_POINT * 3), 3)

    def test_record_and_score(self):
        ledger = Ledger()
        client_priv, client_pub = ed25519.generate_keypair()
        _, node_pub = ed25519.generate_keypair()
        self.assertTrue(ledger.record(self._receipt(client_priv, client_pub, node_pub, 1, BYTES_PER_POINT * 2)))
        self.assertEqual(ledger.score(node_pub), 2)

    def test_duplicate_rejected(self):
        ledger = Ledger()
        client_priv, client_pub = ed25519.generate_keypair()
        _, node_pub = ed25519.generate_keypair()
        r = self._receipt(client_priv, client_pub, node_pub, 5, BYTES_PER_POINT)
        self.assertTrue(ledger.record(r))
        self.assertFalse(ledger.record(r))  # same (client, seq) -> duplicate
        self.assertEqual(ledger.duplicates, 1)
        self.assertEqual(ledger.score(node_pub), 1)

    def test_forged_receipt_rejected(self):
        ledger = Ledger()
        client_priv, client_pub = ed25519.generate_keypair()
        _, node_pub = ed25519.generate_keypair()
        r = self._receipt(client_priv, client_pub, node_pub, 1, BYTES_PER_POINT)
        r.byte_count = 10 ** 9  # tamper after signing
        self.assertFalse(ledger.record(r))
        self.assertEqual(ledger.rejected, 1)
        self.assertEqual(ledger.score(node_pub), 0)

    def test_leaderboard_competition(self):
        ledger = Ledger()
        client_priv, client_pub = ed25519.generate_keypair()
        _, node_a = ed25519.generate_keypair()
        _, node_b = ed25519.generate_keypair()
        _, node_c = ed25519.generate_keypair()
        seq = 0
        for node, n in ((node_a, 5), (node_b, 2), (node_c, 9)):
            for _ in range(n):
                seq += 1
                ledger.record(self._receipt(client_priv, client_pub, node, seq, BYTES_PER_POINT))
        board = ledger.leaderboard()
        self.assertEqual(board[0].ed_public, node_c)  # 9 points, top
        self.assertEqual(board[-1].ed_public, node_b)  # 2 points, last
        self.assertEqual(ledger.total_nodes(), 3)


class TestProofOfWork(unittest.TestCase):
    def test_mine_and_verify(self):
        challenge = os.urandom(16)
        pow_result = mine(challenge, difficulty=12)
        self.assertTrue(pow_result.verify())
        self.assertTrue(meets_difficulty(challenge, pow_result.nonce, 12))

    def test_wrong_nonce_fails(self):
        challenge = os.urandom(16)
        self.assertFalse(meets_difficulty(challenge, b"\xff" * 12, 20))


if __name__ == "__main__":
    unittest.main(verbosity=2)
