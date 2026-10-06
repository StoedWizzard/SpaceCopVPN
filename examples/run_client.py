"""Connect to a node and start a local SOCKS5 proxy over the overlay.

    python examples/run_client.py <node_host:port> <node_x25519_hex> [node_ed25519_hex]

Then point an application at socks5://127.0.0.1:1080.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.client import VPNClient
from spacecop.tun.socks_proxy import Socks5Proxy


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    host, _, port = sys.argv[1].rpartition(":")
    node_x = bytes.fromhex(sys.argv[2])
    node_ed = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b""

    client = VPNClient()
    client.start()
    client.connect(node_x, (host, int(port)), expected_node_ed=node_ed)
    print(f"connected to node at {host}:{port}")

    proxy = Socks5Proxy(client, listen_host="127.0.0.1", listen_port=1080)
    proxy.start()
    print("SOCKS5 proxy on 127.0.0.1:1080  (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        proxy.stop()
        client.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
