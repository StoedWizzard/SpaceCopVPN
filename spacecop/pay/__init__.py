"""Payments (step 0): an off-chain model of the Solana escrow.

The intended production flow is:

* a client deposits, say, 5 USDC into an on-chain escrow it owns;
* as nodes relay its traffic, the client signs a growing *voucher* to each
  node — "cumulatively I owe you N micro-dollars" (the agreed price per MB is
  already folded into that amount, so a node cannot inflate it);
* each node claims from the escrow by presenting its latest voucher; the
  contract verifies the client's Ed25519 signature, pays out the increase
  since that node's last claim, and records it so the same bytes are never
  paid twice.

This package captures exactly that behaviour **without a blockchain**, so the
economics can be tested and the GUI wired up before a single line of Solana
code exists.  :class:`~spacecop.pay.escrow.SettlementBackend` is the seam: the
off-chain :class:`~spacecop.pay.escrow.OffchainEscrow` here, and later a Solana
adapter, implement the same three operations (deposit, claim, balance).

A voucher's signed content is deliberately the shape a Solana program checks:
``client_pubkey || node_pubkey || cumulative_micros || nonce``.
"""

from .voucher import Voucher
from .escrow import EscrowError, OffchainEscrow, SettlementBackend
from .pricing import micros_for_bytes, MICROS_PER_USD

__all__ = [
    "Voucher",
    "EscrowError",
    "OffchainEscrow",
    "SettlementBackend",
    "micros_for_bytes",
    "MICROS_PER_USD",
]
