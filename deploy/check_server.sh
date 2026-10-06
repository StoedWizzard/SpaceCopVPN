#!/usr/bin/env bash
# =============================================================================
#  SpaceCopVPN — node health check.  Run on the server:  sudo ./deploy/check_server.sh
#
#  Checks, in order, everything that can make a client say "handshake timed out":
#    1. the systemd service is running (and shows the last log lines if not)
#    2. the process is listening on the UDP port
#    3. the node answers a protocol PING locally
#    4. the local firewall (ufw / firewalld / nftables / iptables) allows the port
#    5. the clock is sane (handshakes are rejected if skew > 5 minutes)
#    6. prints the connection URI to compare with what the client has
# =============================================================================
set -uo pipefail

CONF_DIR=/etc/spacecop
INSTALL_DIR=/opt/spacecop
SERVICE=spacecop-node
ENV_FILE="$CONF_DIR/node.env"
IDENTITY="$CONF_DIR/identity.json"

ok()   { printf '  \033[1;32m[OK]\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
warn() { printf '  \033[1;33m[WARN]\033[0m %s\n' "$*"; }
FAILS=0

PORT=51820; ADVERTISE=""
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  PORT="${SPACECOP_PORT:-$PORT}"; ADVERTISE="${SPACECOP_ADVERTISE:-}"
fi
PY="$(command -v python3 || true)"

echo "SpaceCopVPN node check  (port udp/$PORT)"
echo "----------------------------------------------------------------"

# 1. service
if command -v systemctl >/dev/null; then
  if systemctl is-active --quiet "$SERVICE"; then
    ok "service $SERVICE is active"
  else
    bad "service $SERVICE is not running"
    journalctl -u "$SERVICE" --no-pager -n 15 2>/dev/null | sed 's/^/         /'
  fi
else
  warn "no systemd; make sure the node process is running"
fi

# 2. listening socket
if command -v ss >/dev/null; then
  if ss -ulnp 2>/dev/null | grep -q ":$PORT "; then
    ok "something is listening on udp/$PORT"
  else
    bad "nothing is listening on udp/$PORT"
  fi
fi

# 3. local ping
if [[ -n "$PY" && -f "$INSTALL_DIR/spacecop/cli.py" ]]; then
  if (cd "$INSTALL_DIR" && "$PY" -m spacecop.cli ping --node "127.0.0.1:$PORT" --timeout 3 >/dev/null 2>&1); then
    ok "node answers PING on 127.0.0.1:$PORT"
  else
    bad "node does not answer PING locally (service down or wrong port)"
  fi
fi

# 4. firewall
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  if ufw status | grep -qE "^$PORT/udp\s+ALLOW"; then ok "ufw allows $PORT/udp"; else bad "ufw is active but $PORT/udp is not allowed:  ufw allow $PORT/udp"; fi
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  if firewall-cmd --list-ports | grep -q "$PORT/udp"; then ok "firewalld allows $PORT/udp"; else bad "firewalld is active but $PORT/udp is closed:  firewall-cmd --permanent --add-port=$PORT/udp && firewall-cmd --reload"; fi
elif command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -q "drop"; then
  warn "nftables has drop rules; make sure udp dport $PORT is accepted"
elif command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -q "DROP\|REJECT"; then
  warn "iptables INPUT has DROP/REJECT rules; make sure udp/$PORT is accepted"
else
  ok "no blocking local firewall detected"
fi
warn "cloud/provider firewalls (security groups, VDS panel) are NOT visible from here — open UDP $PORT there too"

# 5. clock
if command -v timedatectl >/dev/null; then
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
    ok "clock is NTP-synchronised ($(date -u +'%Y-%m-%d %H:%M:%S UTC'))"
  else
    warn "clock is NOT NTP-synchronised ($(date -u +'%Y-%m-%d %H:%M:%S UTC')); handshakes fail if skew > 5 min: timedatectl set-ntp true"
  fi
fi

# 5b. exit reachability: can THIS server reach popular destinations?  A node
#     whose network blocks a service cannot relay it, however healthy it is.
if [[ -n "$PY" ]]; then
  "$PY" - <<'EOF'
import socket
targets = [("example.com", 443, "generic HTTPS"),
           ("149.154.167.51", 443, "Telegram DC2"),
           ("149.154.175.53", 443, "Telegram DC4")]
for host, port, label in targets:
    try:
        socket.create_connection((host, port), timeout=5).close()
        print(f"  \033[1;32m[OK]\033[0m   exit can reach {label} ({host}:{port})")
    except OSError as exc:
        print(f"  \033[1;33m[WARN]\033[0m exit CANNOT reach {label} ({host}:{port}): {exc} "
              f"-- clients will fail over to another node for it, if one is configured")
EOF
fi

# 6. URI
if [[ -n "$PY" && -f "$IDENTITY" && -n "$ADVERTISE" ]]; then
  URI="$(cd "$INSTALL_DIR" && "$PY" -m spacecop.cli uri --identity "$IDENTITY" --host "$ADVERTISE" --port "$PORT" 2>/dev/null || true)"
  [[ -n "$URI" ]] && { echo; echo "  Connection URI:"; echo "    $URI"; }
fi

echo "----------------------------------------------------------------"
if [[ $FAILS -eq 0 ]]; then
  echo "All local checks passed. If a client still times out, the UDP port is blocked upstream."
  echo "From the client machine run:  python -m spacecop.cli ping --uri '<URI>'"
else
  echo "$FAILS problem(s) found — fix them, then: systemctl restart $SERVICE"
  exit 1
fi
