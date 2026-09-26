"""Off-chain walkthrough of the Solana payment model: a client deposits $5,
three nodes relay its traffic and get paid from the escrow by presenting
client-signed cumulative vouchers.

    python examples/pay_demo.py

No blockchain, no real money — this is the reference behaviour the on-chain
program must reproduce.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.crypto import ed25519
from spacecop.pay import OffchainEscrow, Voucher, micros_for_bytes, MICROS_PER_USD
from spacecop.pay.pricing import usd


def main() -> None:
    esc = OffchainEscrow()
    client_priv, client_pub = ed25519.generate_keypair()
    nonce = 1

    nodes = []
    for name, price in (("node-A", 40_000), ("node-B", 55_000), ("node-C", 30_000)):
        priv, pub = ed25519.generate_keypair()
        nodes.append({"name": name, "pub": pub, "price": price, "bytes": 0})

    deposit = 5 * MICROS_PER_USD
    esc.deposit(client_pub, nonce, deposit)
    print(f"client deposits {usd(deposit)} into the escrow\n")

    # The client's running cumulative debt to each node.
    owed = {n["name"]: 0 for n in nodes}

    # Simulate several relay rounds; each round the client signs a fresh,
    # larger voucher to whichever node carried traffic, and the node claims.
    traffic = [
        ("node-A", 20), ("node-B", 5), ("node-C", 50),
        ("node-A", 30), ("node-C", 40), ("node-B", 10),
    ]
    print(f"{'round':6} {'node':7} {'+MB':>5} {'price/MB':>10} {'voucher':>10} {'paid':>9} {'balance':>9}")
    for i, (name, mb) in enumerate(traffic, 1):
        node = next(n for n in nodes if n["name"] == name)
        node["bytes"] += mb * 1_000_000
        owed[name] = micros_for_bytes(node["bytes"], node["price"])
        v = Voucher(client_pub, node["pub"], owed[name], nonce).sign(client_priv)
        paid = esc.claim(v)
        print(f"{i:<6} {name:7} {mb:>5} {usd(node['price']):>10} "
              f"{usd(owed[name]):>10} {usd(paid):>9} {usd(esc.balance(client_pub, nonce)):>9}")

    print("\ntotals per node (claimed from the $5 deposit):")
    for n in nodes:
        got = esc.paid_to(client_pub, nonce, n["pub"])
        print(f"  {n['name']}: {n['bytes'] // 1_000_000:>3} MB  ->  {usd(got)}")

    refund = esc.close(client_pub, nonce)
    print(f"\npaid out: {usd(esc.paid_out(client_pub, nonce))}   refunded to client on close: {usd(refund)}")


if __name__ == "__main__":
    main()
