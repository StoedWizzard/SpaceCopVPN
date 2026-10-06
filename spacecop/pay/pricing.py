"""Pricing helpers: convert relayed bytes and a per-MB price into an amount.

Amounts are integer **micro-dollars** (1 USD = 1_000_000 micros), so there is
no floating point anywhere on the money path — the same discipline a Solana
program needs (it works in integer token base units, e.g. USDC has 6 decimals,
which lines up exactly with micro-dollars).
"""

from __future__ import annotations

MICROS_PER_USD = 1_000_000
BYTES_PER_MB = 1_000_000  # decimal MB, matching how bandwidth is usually priced


def micros_for_bytes(byte_count: int, price_micros_per_mb: int) -> int:
    """Cost of ``byte_count`` bytes at ``price_micros_per_mb`` micro-dollars/MB.

    Rounded down: a node is never over-credited for a partial MB.  Integer math
    only, so the client and an on-chain program compute the identical value.
    """
    if byte_count < 0 or price_micros_per_mb < 0:
        raise ValueError("byte_count and price must be non-negative")
    return (byte_count * price_micros_per_mb) // BYTES_PER_MB


def usd(micros: int) -> str:
    """Format micro-dollars as a $ string, for logs and the GUI."""
    return f"${micros / MICROS_PER_USD:.4f}"
