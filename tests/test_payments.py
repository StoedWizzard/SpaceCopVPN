"""Off-chain escrow (step 0 of the Solana payment model): a client deposits,
nodes claim by presenting client-signed cumulative vouchers.  These tests pin
the exact semantics a Solana program must later reproduce."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.crypto import ed25519  # noqa: E402
from spacecop.pay import OffchainEscrow, Voucher, micros_for_bytes, MICROS_PER_USD  # noqa: E402
from spacecop.pay.escrow import EscrowError  # noqa: E402


def _keypair():
    priv, pub = ed25519.generate_keypair()
    return priv, pub


def _voucher(client_priv, client_pub, node_pub, micros, nonce=1):
    return Voucher(client_pub, node_pub, micros, nonce).sign(client_priv)


class TestPricing(unittest.TestCase):
    def test_micros_for_bytes(self):
        # 1 MB at $0.05/MB = 50_000 micros
        self.assertEqual(micros_for_bytes(1_000_000, 50_000), 50_000)
        # partial MB rounds down, never over-credits
        self.assertEqual(micros_for_bytes(1_499_999, 50_000), 74_999)
        self.assertEqual(micros_for_bytes(0, 50_000), 0)
        with self.assertRaises(ValueError):
            micros_for_bytes(-1, 50_000)


class TestVoucher(unittest.TestCase):
    def test_sign_verify_roundtrip_and_encode(self):
        cpriv, cpub = _keypair()
        _, npub = _keypair()
        v = _voucher(cpriv, cpub, npub, 123_456)
        self.assertTrue(v.verify())
        again = Voucher.decode(v.encode())
        self.assertEqual(again.cumulative_micros, 123_456)
        self.assertTrue(again.verify())

    def test_tampered_amount_rejected(self):
        cpriv, cpub = _keypair()
        _, npub = _keypair()
        v = _voucher(cpriv, cpub, npub, 100)
        v.cumulative_micros = 1_000_000  # try to inflate after signing
        self.assertFalse(v.verify())

    def test_wrong_signer_rejected(self):
        cpriv, cpub = _keypair()
        attacker_priv, _ = _keypair()
        _, npub = _keypair()
        v = Voucher(cpub, npub, 100, 1).sign(attacker_priv)  # not the client's key
        self.assertFalse(v.verify())


class TestEscrow(unittest.TestCase):
    def setUp(self):
        self.esc = OffchainEscrow()
        self.cpriv, self.cpub = _keypair()
        self.n1priv, self.n1 = _keypair()
        self.n2priv, self.n2 = _keypair()
        self.nonce = 42
        self.esc.deposit(self.cpub, self.nonce, 5 * MICROS_PER_USD)  # $5

    def test_single_claim(self):
        v = _voucher(self.cpriv, self.cpub, self.n1, 2 * MICROS_PER_USD, self.nonce)
        self.assertEqual(self.esc.claim(v), 2 * MICROS_PER_USD)
        self.assertEqual(self.esc.balance(self.cpub, self.nonce), 3 * MICROS_PER_USD)
        self.assertEqual(self.esc.paid_to(self.cpub, self.nonce, self.n1), 2 * MICROS_PER_USD)

    def test_cumulative_pays_only_the_increase(self):
        self.esc.claim(_voucher(self.cpriv, self.cpub, self.n1, 1_000_000, self.nonce))
        # a larger cumulative voucher pays only the delta
        paid = self.esc.claim(_voucher(self.cpriv, self.cpub, self.n1, 1_500_000, self.nonce))
        self.assertEqual(paid, 500_000)
        self.assertEqual(self.esc.paid_to(self.cpub, self.nonce, self.n1), 1_500_000)

    def test_duplicate_and_stale_voucher_pay_nothing(self):
        v = _voucher(self.cpriv, self.cpub, self.n1, 1_000_000, self.nonce)
        self.assertEqual(self.esc.claim(v), 1_000_000)
        self.assertEqual(self.esc.claim(v), 0)  # same voucher again
        stale = _voucher(self.cpriv, self.cpub, self.n1, 400_000, self.nonce)
        self.assertEqual(self.esc.claim(stale), 0)  # lower cumulative

    def test_two_nodes_share_one_deposit(self):
        self.assertEqual(self.esc.claim(_voucher(self.cpriv, self.cpub, self.n1, 2 * MICROS_PER_USD, self.nonce)), 2 * MICROS_PER_USD)
        self.assertEqual(self.esc.claim(_voucher(self.cpriv, self.cpub, self.n2, 1 * MICROS_PER_USD, self.nonce)), 1 * MICROS_PER_USD)
        self.assertEqual(self.esc.balance(self.cpub, self.nonce), 2 * MICROS_PER_USD)
        self.assertEqual(self.esc.paid_out(self.cpub, self.nonce), 3 * MICROS_PER_USD)

    def test_overdraft_is_first_come_capped_at_deposit(self):
        # Client dishonestly signs vouchers summing to $8 against a $5 deposit.
        self.assertEqual(self.esc.claim(_voucher(self.cpriv, self.cpub, self.n1, 4 * MICROS_PER_USD, self.nonce)), 4 * MICROS_PER_USD)
        # node 2 signed for $4 too, but only $1 is left
        self.assertEqual(self.esc.claim(_voucher(self.cpriv, self.cpub, self.n2, 4 * MICROS_PER_USD, self.nonce)), 1 * MICROS_PER_USD)
        # nothing can be over-paid
        self.assertEqual(self.esc.balance(self.cpub, self.nonce), 0)
        self.assertEqual(self.esc.paid_out(self.cpub, self.nonce), 5 * MICROS_PER_USD)

    def test_claimable_matches_claim(self):
        v = _voucher(self.cpriv, self.cpub, self.n1, 9 * MICROS_PER_USD, self.nonce)  # more than deposit
        self.assertEqual(self.esc.claimable(v), 5 * MICROS_PER_USD)  # capped at balance
        self.assertEqual(self.esc.claim(v), 5 * MICROS_PER_USD)
        self.assertEqual(self.esc.claimable(v), 0)

    def test_topup_lets_node_claim_the_remainder(self):
        v = _voucher(self.cpriv, self.cpub, self.n1, 8 * MICROS_PER_USD, self.nonce)
        self.assertEqual(self.esc.claim(v), 5 * MICROS_PER_USD)  # only $5 available
        self.esc.deposit(self.cpub, self.nonce, 5 * MICROS_PER_USD)  # client tops up
        self.assertEqual(self.esc.claim(v), 3 * MICROS_PER_USD)  # remaining owed
        self.assertEqual(self.esc.paid_to(self.cpub, self.nonce, self.n1), 8 * MICROS_PER_USD)

    def test_forged_voucher_rejected(self):
        attacker_priv, _ = _keypair()
        v = Voucher(self.cpub, self.n1, 3 * MICROS_PER_USD, self.nonce).sign(attacker_priv)
        with self.assertRaises(EscrowError):
            self.esc.claim(v)

    def test_close_refunds_remainder_and_blocks_claims(self):
        self.esc.claim(_voucher(self.cpriv, self.cpub, self.n1, 2 * MICROS_PER_USD, self.nonce))
        refund = self.esc.close(self.cpub, self.nonce)
        self.assertEqual(refund, 3 * MICROS_PER_USD)
        with self.assertRaises(EscrowError):
            self.esc.claim(_voucher(self.cpriv, self.cpub, self.n2, 1 * MICROS_PER_USD, self.nonce))

    def test_end_to_end_priced_by_traffic(self):
        price = 50_000  # $0.05 per MB
        relayed = 30 * 1_000_000  # 30 MB
        micros = micros_for_bytes(relayed, price)  # $1.50
        self.assertEqual(micros, 1_500_000)
        paid = self.esc.claim(_voucher(self.cpriv, self.cpub, self.n1, micros, self.nonce))
        self.assertEqual(paid, 1_500_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
