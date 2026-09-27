"""Benchmark the VPN data-path cipher: native C library vs pure Python.

    python examples/bench_crypto.py            # both backends, 1 MB buffers
    python examples/bench_crypto.py --size 1200 --seconds 2

Prints MB/s for ChaCha20-Poly1305 encrypt+decrypt at the given payload size
(1200 B is one stream chunk on the wire; 20480 B is one fragment; 1 MB shows
raw throughput).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.crypto import aead, native  # noqa: E402


def bench(encrypt, decrypt, size: int, seconds: float) -> float:
    key, nonce, aad = os.urandom(32), os.urandom(12), b"hdr"
    data = os.urandom(size)
    total = 0
    deadline = time.perf_counter() + seconds
    start = time.perf_counter()
    while time.perf_counter() < deadline:
        ct = encrypt(key, nonce, data, aad)
        decrypt(key, nonce, ct, aad)
        total += 2 * size
    return total / (time.perf_counter() - start) / 1e6


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--size", type=int, default=1 << 20, help="payload bytes (default 1 MB)")
    ap.add_argument("--seconds", type=float, default=1.5, help="time per backend")
    args = ap.parse_args()

    print(f"payload {args.size} bytes, {args.seconds:.1f} s per backend")
    if native.available():
        mbs = bench(native.aead_encrypt, native.aead_decrypt, args.size, args.seconds)
        print(f"native C  ({native.path()}): {mbs:8.1f} MB/s")
    else:
        print("native C: not built (run native/build.sh)")
    mbs_py = bench(aead._encrypt_pure, aead._decrypt_pure, args.size, min(args.seconds, 3.0))
    print(f"pure Python                : {mbs_py:8.1f} MB/s")
    print(f"active backend in this process: {aead.backend()}")


if __name__ == "__main__":
    main()
