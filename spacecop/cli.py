"""Command-line interface for running nodes, clients, and the SOCKS proxy.

Examples
--------
Generate (or load) a persistent node identity and print its keys::

    python -m spacecop.cli keygen --identity /etc/spacecop/identity.json

Run a relay node on UDP port 51820 with that identity::

    python -m spacecop.cli node --port 51820 --advertise 203.0.113.9 \
        --identity /etc/spacecop/identity.json

The node prints a connection URI such as
``spacecop://203.0.113.9:51820/<x25519hex>/<ed25519hex>``.  Paste it into the
GUI, or use it directly::

    python -m spacecop.cli proxy --uri spacecop://... --listen 127.0.0.1:1080
    python -m spacecop.cli relay --uri spacecop://... --dest example.com:80
"""

from __future__ import annotations

import argparse
import sys
import time

from .protocol.uri import build_uri, parse_uri


def _parse_hostport(value: str):
    host, _, port = value.rpartition(":")
    if not host:
        raise argparse.ArgumentTypeError(f"expected host:port, got {value!r}")
    return host, int(port)


def _load_identity(path):
    from .protocol import NodeIdentity

    if path:
        return NodeIdentity.load_or_create(path)
    return NodeIdentity.generate()


def cmd_keygen(args) -> int:
    ident = _load_identity(args.identity)
    print(f"identity file        : {args.identity or '(ephemeral, not saved)'}")
    print(f"x25519 (handshake)   : {ident.x_public.hex()}")
    print(f"ed25519 (identity)   : {ident.ed_public.hex()}")
    if args.host:
        print(f"connection uri       : "
              f"{build_uri(args.host, args.port, ident.x_public, ident.ed_public)}")
    return 0


def cmd_uri(args) -> int:
    from .protocol import NodeIdentity

    ident = NodeIdentity.load(args.identity)
    print(build_uri(args.host, args.port, ident.x_public, ident.ed_public))
    return 0


def cmd_node(args) -> int:
    from .node import RelayNode

    ident = _load_identity(args.identity)
    node = RelayNode(identity=ident, bind_host=args.bind, bind_port=args.port,
                     advertised_host=args.advertise, exit_enabled=not args.no_exit)
    bootstrap = [_parse_hostport(b) for b in args.bootstrap] if args.bootstrap else None
    node.start(bootstrap=bootstrap)
    host, port = node.transport.local_addr
    uri = build_uri(args.advertise, port, ident.x_public, ident.ed_public)
    from . import __version__
    from .crypto import aead as _aead
    print(f"[node] SpaceCopVPN {__version__} (streams supported; crypto: {_aead.backend()})")
    print(f"[node] listening on {host}:{port}")
    print(f"[node] identity  (ed25519) : {ident.ed_public.hex()}")
    print(f"[node] handshake (x25519)  : {ident.x_public.hex()}")
    print(f"[node] exit relay enabled  : {node.exit_enabled}")
    print(f"[node] connection uri      : {uri}")
    print("[node] running; Ctrl-C to stop", flush=True)
    try:
        while True:
            time.sleep(args.stats_interval)
            print(f"[node] score={node.score()} "
                  f"relayed_requests={node.relayed_requests} "
                  f"sessions={node.active_sessions()} "
                  f"peers={len(node.directory)}", flush=True)
    except KeyboardInterrupt:
        print("\n[node] stopping")
        node.stop()
    return 0


def _node_targets(args):
    """Resolve --uri and/or --node/--node-key into a list of NodeURI."""
    targets = []
    for text in (args.uri or []):
        targets.append(parse_uri(text))
    if args.node:
        from .protocol.uri import NodeURI

        host, port = _parse_hostport(args.node)
        if not args.node_key:
            raise SystemExit("--node requires --node-key")
        targets.append(NodeURI(host, port, bytes.fromhex(args.node_key),
                               bytes.fromhex(args.node_id) if args.node_id else b""))
    if not targets:
        raise SystemExit("specify at least one --uri (or --node + --node-key)")
    return targets


def _connect_client(args):
    from .client import VPNClient

    client = VPNClient(discovery_enabled=not getattr(args, "no_discover", False),
                       on_event=lambda text: print(f"[client] {text}", flush=True))
    client.start()
    for target in _node_targets(args):
        client.connect(target.x_public, target.address, expected_node_ed=target.ed_public)
        print(f"[client] connected to {target.host}:{target.port}", flush=True)
    return client


def cmd_proxy(args) -> int:
    from .tun.socks_proxy import Socks5Proxy

    client = _connect_client(args)
    listen_host, listen_port = _parse_hostport(args.listen)
    proxy = Socks5Proxy(client, listen_host=listen_host, listen_port=listen_port)
    proxy.start()
    host, port = proxy.address
    print(f"[proxy] SOCKS5 listening on {host}:{port}")
    print("[proxy] configure your app to use this SOCKS5 proxy; Ctrl-C to stop", flush=True)
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


def cmd_ping(args) -> int:
    """Reachability + handshake diagnostics for a node."""
    from .client import RelayTimeout, VPNClient
    from .protocol import HandshakeError

    targets = _node_targets(args) if (args.uri or args.node_key) else None
    if targets is None:
        # --node host:port without a key: reachability only.
        host, port = _parse_hostport(args.node)
        addr = (host, port)
        x_public = None
    else:
        target = targets[0]
        addr, x_public = target.address, target.x_public
        expected = target.ed_public

    client = VPNClient()
    client.start()
    try:
        rtt, version = client.probe(addr, timeout=args.timeout)
        if rtt is None:
            print(f"[ping] {addr[0]}:{addr[1]}  NO REPLY — node not running, or UDP port "
                  f"blocked (provider firewall / security group), or wrong host:port")
            return 1
        from . import __version__
        print(f"[ping] {addr[0]}:{addr[1]}  PONG in {rtt * 1000:.0f} ms — UDP reachable; "
              f"node version: {version or 'OLD (< 0.2.0)'}; client version: {__version__}")
        if not version:
            print("[ping] WARNING: the node runs an outdated build without stream support — "
                  "web sites will not load through it. Update the server: deploy/update_server.sh")
        if x_public is None:
            return 0
        try:
            conn = client.connect(x_public, addr, expected_node_ed=expected, timeout=args.timeout)
            print(f"[handshake] OK — node identity {conn.node_id_hex()}")
            return 0
        except HandshakeError as exc:
            print(f"[handshake] REJECTED — {exc}")
            print("            (check the keys in the URI, and the clocks on both machines)")
            return 2
        except RelayTimeout as exc:
            print(f"[handshake] TIMEOUT — {exc}")
            return 3
    finally:
        client.stop()


def cmd_vpn(args) -> int:
    """Full-system mode (Linux root / Windows Administrator): TUN + routing."""
    from .tun.system import create_system_vpn, is_privileged

    if not is_privileged():
        raise SystemExit("full-system mode needs elevated rights: "
                         "sudo spacecop vpn ... (Linux) or run as Administrator (Windows)")

    def emit(text):
        print(f"[vpn] {text}", flush=True)

    client = _connect_client(args)
    host, _, port = args.dns.rpartition(":")
    try:
        vpn = create_system_vpn(client, dns_server=(host or "1.1.1.1", int(port or 53)), on_event=emit)
        vpn.start()
    except Exception as exc:
        emit(f"failed to start: {exc}")
        try:
            vpn.stop()
        except Exception:
            pass
        client.stop()
        return 1
    emit("READY")
    try:
        vpn.run_forever(status_every=args.status_interval)
    finally:
        client.stop()
        emit("STOPPED")
    return 0


def cmd_peers(args) -> int:
    """Ask a node which peers it knows (gossip diagnostics, no handshake needed)."""
    import socket
    import threading

    from .protocol import constants as c, framing
    from .protocol.messages import NodeAnnounce, PeerList, PeerRequest

    host, port = _parse_hostport(args.node)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    sock.sendto(PeerRequest(max_peers=64).encode(), (host, port))
    peers, announce = None, None
    deadline = time.time() + args.timeout
    while time.time() < deadline and (peers is None or announce is None):
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            break
        try:
            msg_type, body = framing.decode_frame(data)
        except framing.ProtocolError:
            continue
        if msg_type == c.MSG_PEER_LIST:
            peers = PeerList.decode(body)
        elif msg_type == c.MSG_NODE_ANNOUNCE:
            announce = NodeAnnounce.decode(body)
    if peers is None:
        print(f"[peers] {host}:{port}: no PEER_LIST reply (node down, port blocked, or old build)")
        return 1
    if announce is not None:
        print(f"[peers] node {announce.ed_public.hex()[:16]} at {host}:{port} "
              f"(advertises {announce.host}:{announce.port}, score {announce.score})")
    print(f"[peers] knows {len(peers.peers)} other node(s):")
    for p in peers.peers:
        print(f"    {build_uri(p.host, p.port, p.x_public, p.ed_public)}")
    if not peers.peers:
        print("    (none) — other nodes must announce to it: start them with "
              "--bootstrap host:port of this node, or set SPACECOP_BOOTSTRAP")
    return 0


def cmd_gui(args) -> int:
    from .gui.app import main as gui_main

    return gui_main()


def build_parser() -> argparse.ArgumentParser:
    from . import __version__
    parser = argparse.ArgumentParser(prog="spacecop", description=__doc__.splitlines()[0])
    from .crypto import aead as _aead
    parser.add_argument("--version", action="version",
                        version=f"spacecop {__version__} (crypto: {_aead.backend()})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_key = sub.add_parser("keygen", help="create/load a node identity and print its keys")
    p_key.add_argument("--identity", help="path to identity JSON (created if missing)")
    p_key.add_argument("--host", help="advertised host, to also print a connection URI")
    p_key.add_argument("--port", type=int, default=51820)
    p_key.set_defaults(func=cmd_keygen)

    p_uri = sub.add_parser("uri", help="print the connection URI for an identity")
    p_uri.add_argument("--identity", required=True)
    p_uri.add_argument("--host", required=True)
    p_uri.add_argument("--port", type=int, default=51820)
    p_uri.set_defaults(func=cmd_uri)

    p_node = sub.add_parser("node", help="run a relay node")
    p_node.add_argument("--bind", default="0.0.0.0")
    p_node.add_argument("--port", type=int, default=51820)
    p_node.add_argument("--advertise", default="127.0.0.1",
                        help="host others should use to reach this node")
    p_node.add_argument("--identity", help="persistent identity JSON (created if missing)")
    p_node.add_argument("--bootstrap", nargs="*", help="peer host:port seeds")
    p_node.add_argument("--no-exit", action="store_true",
                        help="do not act as an exit relay")
    p_node.add_argument("--stats-interval", type=float, default=30.0)
    p_node.set_defaults(func=cmd_node)

    def add_client_args(p):
        p.add_argument("--uri", action="append",
                       help="node connection URI (repeatable for several nodes)")
        p.add_argument("--node", help="node host:port (alternative to --uri)")
        p.add_argument("--node-key", help="node x25519 public key (hex)")
        p.add_argument("--node-id", default="", help="expected node ed25519 id (hex)")
        p.add_argument("--no-discover", action="store_true",
                       help="do not auto-connect to nodes learned from connected nodes")

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

    p_ping = sub.add_parser("ping", help="check that a node is reachable and accepts handshakes")
    add_client_args(p_ping)
    p_ping.add_argument("--timeout", type=float, default=4.0)
    p_ping.set_defaults(func=cmd_ping)

    p_vpn = sub.add_parser("vpn", help="full-system tunnel (Linux root / Windows admin): TUN + routes")
    add_client_args(p_vpn)
    p_vpn.add_argument("--dns", default="1.1.1.1:53",
                       help="DNS-over-TCP resolver reached through the tunnel")
    p_vpn.add_argument("--status-interval", type=float, default=10.0)
    p_vpn.set_defaults(func=cmd_vpn)

    p_peers = sub.add_parser("peers", help="list the peers a node knows (gossip check)")
    p_peers.add_argument("--node", required=True, help="node host:port")
    p_peers.add_argument("--timeout", type=float, default=4.0)
    p_peers.set_defaults(func=cmd_peers)

    p_gui = sub.add_parser("gui", help="launch the graphical client")
    p_gui.set_defaults(func=cmd_gui)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
