"""Command-line interface for running nodes, clients, and the SOCKS proxy.

Examples
--------
Run a relay node on UDP port 51820::

    python -m spacecop.cli node --port 51820 --advertise 203.0.113.9

Run a local SOCKS5 proxy that tunnels through a node::

    python -m spacecop.cli proxy --node 203.0.113.9:51820 --node-key <hex> \
        --listen 127.0.0.1:1080

Make a single relayed request (useful for testing)::

    python -m spacecop.cli relay --node 127.0.0.1:51820 --node-key <hex> \
        --dest example.com:80
"""

from __future__ import annotations

import argparse
import sys
import time


def _parse_hostport(value: str):
    host, _, port = value.rpartition(":")
    if not host:
        raise argparse.ArgumentTypeError(f"expected host:port, got {value!r}")
    return host, int(port)


def cmd_node(args) -> int:
    from .node import RelayNode

    node = RelayNode(bind_host=args.bind, bind_port=args.port,
                     advertised_host=args.advertise, exit_enabled=not args.no_exit)
    bootstrap = [_parse_hostport(b) for b in args.bootstrap] if args.bootstrap else None
    node.start(bootstrap=bootstrap)
    host, port = node.transport.local_addr
    print(f"[node] listening on {host}:{port}")
    print(f"[node] identity  (ed25519) : {node.identity.ed_public.hex()}")
    print(f"[node] handshake (x25519)  : {node.identity.x_public.hex()}")
    print(f"[node] exit relay enabled  : {node.exit_enabled}")
    print("[node] running; Ctrl-C to stop")
    try:
        while True:
            time.sleep(5)
            print(f"[node] score={node.score()} "
                  f"relayed_requests={node.relayed_requests} "
                  f"sessions={node.active_sessions()} "
                  f"peers={len(node.directory)}")
    except KeyboardInterrupt:
        print("\n[node] stopping")
        node.stop()
    return 0


def _connect_client(args):
    from .client import VPNClient

    client = VPNClient()
    client.start()
    node_host, node_port = _parse_hostport(args.node)
    node_key = bytes.fromhex(args.node_key)
    expected = bytes.fromhex(args.node_id) if args.node_id else b""
    client.connect(node_key, (node_host, node_port), expected_node_ed=expected)
    return client


def cmd_proxy(args) -> int:
    from .tun.socks_proxy import Socks5Proxy

    client = _connect_client(args)
    listen_host, listen_port = _parse_hostport(args.listen)
    proxy = Socks5Proxy(client, listen_host=listen_host, listen_port=listen_port)
    proxy.start()
    host, port = proxy.address
    print(f"[proxy] SOCKS5 listening on {host}:{port}")
    print(f"[proxy] tunnelling through {args.node}")
    print("[proxy] configure your app to use this SOCKS5 proxy; Ctrl-C to stop")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[proxy] stopping")
        proxy.stop()
        client.stop()
    return 0


def cmd_relay(args) -> int:
    client = _connect_client(args)
    dest_host, dest_port = _parse_hostport(args.dest)
    request = sys.stdin.buffer.read() if args.stdin else (
        f"GET / HTTP/1.0\r\nHost: {dest_host}\r\n\r\n".encode())
    response = client.relay(dest_host, dest_port, request, timeout=args.timeout)
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    client.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spacecop", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_node = sub.add_parser("node", help="run a relay node")
    p_node.add_argument("--bind", default="0.0.0.0")
    p_node.add_argument("--port", type=int, default=0)
    p_node.add_argument("--advertise", default="127.0.0.1",
                        help="host others should use to reach this node")
    p_node.add_argument("--bootstrap", nargs="*", help="peer host:port seeds")
    p_node.add_argument("--no-exit", action="store_true",
                        help="do not act as an exit relay")
    p_node.set_defaults(func=cmd_node)

    def add_client_args(p):
        p.add_argument("--node", required=True, help="node host:port")
        p.add_argument("--node-key", required=True, help="node x25519 public key (hex)")
        p.add_argument("--node-id", default="", help="expected node ed25519 id (hex)")

    p_proxy = sub.add_parser("proxy", help="run a local SOCKS5 proxy over the overlay")
    add_client_args(p_proxy)
    p_proxy.add_argument("--listen", default="127.0.0.1:1080")
    p_proxy.set_defaults(func=cmd_proxy)

    p_relay = sub.add_parser("relay", help="make one relayed request")
    add_client_args(p_relay)
    p_relay.add_argument("--dest", required=True, help="destination host:port")
    p_relay.add_argument("--stdin", action="store_true", help="read request body from stdin")
    p_relay.add_argument("--timeout", type=float, default=15.0)
    p_relay.set_defaults(func=cmd_relay)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
