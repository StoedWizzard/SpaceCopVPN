"""Start a single relay node and print its identity so clients can connect.

    python examples/run_node.py [port]

Copy the printed x25519 and ed25519 keys into run_client.py (or the CLI).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.node import RelayNode


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 51820
    node = RelayNode(bind_host="0.0.0.0", bind_port=port, advertised_host="127.0.0.1")
    node.start()
    host, bound = node.transport.local_addr
    print(f"node listening on udp/{bound}")
    print(f"x25519 (handshake key) : {node.identity.x_public.hex()}")
    print(f"ed25519 (identity)     : {node.identity.ed_public.hex()}")
    print("Ctrl-C to stop")
    try:
        while True:
            time.sleep(5)
            print(f"score={node.score()} requests={node.relayed_requests} "
                  f"sessions={node.active_sessions()}")
    except KeyboardInterrupt:
        node.stop()


if __name__ == "__main__":
    main()
