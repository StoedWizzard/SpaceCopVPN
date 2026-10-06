"""The escrow: a client deposits once, many nodes claim by presenting vouchers.

:class:`SettlementBackend` is the seam between this off-chain model and a future
Solana program — both expose deposit / claim / balance / withdraw with the same
semantics.  :class:`OffchainEscrow` is the pure-Python implementation used for
tests, the GUI prototype, and as the reference the on-chain program must match.

Rules enforced here (identical to what the Solana program must enforce):

* **Authenticated.** A voucher only pays if the client's Ed25519 signature is
  valid over its content.
* **Monotonic, deduplicated.** A node is paid the *increase* over what it was
  already paid for this escrow, so re-presenting an old or equal voucher pays
  nothing and the same bytes are never paid twice.
* **Bounded by the deposit.** Total paid out across all nodes can never exceed
  what the client deposited.  If the client over-signs (vouchers summing to
  more than the deposit), it is first-come: the escrow pays each claim only up
  to the remaining balance.  Nodes bound their own exposure with a credit limit
  (see :meth:`OffchainEscrow.claimable`) and claim often.
* **Refundable.** After the client closes the escrow, it withdraws whatever is
  left.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Dict, Tuple

from .voucher import Voucher


class EscrowError(Exception):
    pass


class SettlementBackend(ABC):
    """Deposit / claim / balance — implemented off-chain here, on Solana later."""

    @abstractmethod
    def deposit(self, client_pub: bytes, nonce: int, micros: int) -> None: ...

    @abstractmethod
    def claim(self, voucher: Voucher) -> int:
        """Pay the node the increase it is owed; return the amount paid."""

    @abstractmethod
    def balance(self, client_pub: bytes, nonce: int) -> int: ...


class OffchainEscrow(SettlementBackend):
    """In-memory escrow. Thread-safe; mirrors the on-chain state machine."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (client_pub, nonce) -> remaining micro-dollars in the vault
        self._balance: Dict[Tuple[bytes, int], int] = {}
        # (client_pub, nonce, node_pub) -> cumulative micros already paid
        self._paid: Dict[Tuple[bytes, int, bytes], int] = {}
        # (client_pub, nonce) -> total ever paid out (for reporting)
        self._paid_out: Dict[Tuple[bytes, int], int] = {}
        self._closed: set = set()

    # -- client side ---------------------------------------------------------
    def deposit(self, client_pub: bytes, nonce: int, micros: int) -> None:
        if micros <= 0:
            raise EscrowError("deposit must be positive")
        key = (bytes(client_pub), nonce)
        with self._lock:
            if key in self._closed:
                raise EscrowError("escrow is closed")
            self._balance[key] = self._balance.get(key, 0) + micros
            self._paid_out.setdefault(key, 0)

    def balance(self, client_pub: bytes, nonce: int) -> int:
        with self._lock:
            return self._balance.get((bytes(client_pub), nonce), 0)

    def paid_out(self, client_pub: bytes, nonce: int) -> int:
        with self._lock:
            return self._paid_out.get((bytes(client_pub), nonce), 0)

    def paid_to(self, client_pub: bytes, nonce: int, node_pub: bytes) -> int:
        with self._lock:
            return self._paid.get((bytes(client_pub), nonce, bytes(node_pub)), 0)

    def close(self, client_pub: bytes, nonce: int) -> int:
        """Close the escrow and refund the remaining balance to the client.

        Returns the refunded amount.  Nodes can no longer claim afterwards.
        """
        key = (bytes(client_pub), nonce)
        with self._lock:
            refund = self._balance.get(key, 0)
            self._balance[key] = 0
            self._closed.add(key)
            return refund

    # -- node side -----------------------------------------------------------
    def claimable(self, voucher: Voucher) -> int:
        """How much this voucher would pay right now (does not mutate state)."""
        key = (bytes(voucher.client_pub), voucher.nonce)
        pkey = (bytes(voucher.client_pub), voucher.nonce, bytes(voucher.node_pub))
        with self._lock:
            already = self._paid.get(pkey, 0)
            owed = voucher.cumulative_micros - already
            if owed <= 0:
                return 0
            return min(owed, self._balance.get(key, 0))

    def claim(self, voucher: Voucher) -> int:
        if not voucher.verify():
            raise EscrowError("voucher signature invalid")
        key = (bytes(voucher.client_pub), voucher.nonce)
        pkey = (bytes(voucher.client_pub), voucher.nonce, bytes(voucher.node_pub))
        with self._lock:
            if key in self._closed:
                raise EscrowError("escrow is closed")
            already = self._paid.get(pkey, 0)
            owed = voucher.cumulative_micros - already
            if owed <= 0:
                return 0  # old or duplicate voucher — nothing new to pay
            balance = self._balance.get(key, 0)
            if balance <= 0:
                return 0  # deposit drained (client over-signed); node gets nothing more
            pay = min(owed, balance)
            self._balance[key] = balance - pay
            # Record only what was actually paid, so the node can re-claim the
            # unpaid remainder later if the client tops the deposit up.
            self._paid[pkey] = already + pay
            self._paid_out[key] = self._paid_out.get(key, 0) + pay
            return pay
