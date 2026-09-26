#!/usr/bin/env bash
# =============================================================================
#  SpaceCopVPN — one-shot node (server) installer for any Linux server.
#
#    sudo ./deploy/install_server.sh                      # from a checkout
#    curl -fsSL <raw url of this script> | sudo bash      # standalone (clones repo)
#
#  What it does
#    1. Installs python3 with the distro package manager
#       (apt / dnf / yum / pacman / apk / zypper).
#    2. Copies the project to /opt/spacecop (or clones it if run standalone).
#    3. Creates a dedicated 'spacecop' system user and /etc/spacecop.
#    4. Generates a PERSISTENT node identity (/etc/spacecop/identity.json) —
#       the keys survive restarts, so clients can pin them and the node's
#       score is not orphaned.
#    5. Installs and starts a systemd service (spacecop-node).
#    6. Opens the UDP port in ufw / firewalld if one is active.
#    7. Prints the connection URI to paste into the client.
#
#  Environment overrides (all optional):
#    SPACECOP_PORT=51820        UDP port to listen on
#    SPACECOP_ADVERTISE=1.2.3.4 public IP/host clients should use (auto-detected)
#    SPACECOP_BOOTSTRAP="h1:p1 h2:p2"  other nodes to gossip with
#    SPACECOP_NO_EXIT=1         relay only, do not act as exit
#    SPACECOP_REPO=<git url>    repo to clone when not run from a checkout
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------- arguments
# Flags work under plain `sudo` (which strips environment variables):
#   sudo ./deploy/install_server.sh --bootstrap 1.2.3.4:51820 --port 51820 \
#        --advertise 5.6.7.8 --no-exit
# Environment variables (SPACECOP_*) are still honoured when present, e.g.
#   sudo SPACECOP_BOOTSTRAP=1.2.3.4:51820 ./deploy/install_server.sh
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap) SPACECOP_BOOTSTRAP="${2:-}"; shift 2 ;;
    --port)      SPACECOP_PORT="${2:-}"; shift 2 ;;
    --advertise) SPACECOP_ADVERTISE="${2:-}"; shift 2 ;;
    --no-exit)   SPACECOP_NO_EXIT=1; shift ;;
    --repo)      SPACECOP_REPO="${2:-}"; shift 2 ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

INSTALL_DIR=/opt/spacecop
CONF_DIR=/etc/spacecop
# A re-run keeps the previous settings unless new ones are given.
if [[ -f "$CONF_DIR/node.env" ]]; then
  # shellcheck disable=SC1091
  source "$CONF_DIR/node.env"
  _prev_extra="${SPACECOP_EXTRA_ARGS:-}"
  if [[ -z "${SPACECOP_BOOTSTRAP:-}" && "$_prev_extra" == *"--bootstrap"* ]]; then
    SPACECOP_BOOTSTRAP="$(echo "$_prev_extra" | sed -n 's/.*--bootstrap \(.*\)$/\1/p' | sed 's/ --no-exit//')"
  fi
  if [[ -z "${SPACECOP_NO_EXIT:-}" && "$_prev_extra" == *"--no-exit"* ]]; then
    SPACECOP_NO_EXIT=1
  fi
fi
PORT="${SPACECOP_PORT:-51820}"
IDENTITY="$CONF_DIR/identity.json"
SERVICE=spacecop-node
REPO_URL="${SPACECOP_REPO:-https://github.com/StoedWizzard/SpaceCopVPN.git}"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)."

# ---------------------------------------------------------------- 1. python3
install_python() {
  if command -v python3 >/dev/null 2>&1; then return; fi
  log "Installing python3"
  if   command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf     >/dev/null; then dnf install -y python3
  elif command -v yum     >/dev/null; then yum install -y python3
  elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm python
  elif command -v apk     >/dev/null; then apk add --no-cache python3
  elif command -v zypper  >/dev/null; then zypper --non-interactive install python3
  else die "no supported package manager found; install python3 >= 3.8 manually."
  fi
}
install_python
PY="$(command -v python3)"
"$PY" - <<'EOF' || die "python 3.8 or newer is required"
import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)
EOF

# ---------------------------------------------------------------- 2. sources
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
SRC_ROOT=""
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/../spacecop/cli.py" ]]; then
  SRC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

log "Installing sources to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
if [[ -n "$SRC_ROOT" ]]; then
  # Copy the checkout (excluding VCS/caches).
  if command -v rsync >/dev/null; then
    rsync -a --delete --exclude .git --exclude '__pycache__' "$SRC_ROOT/" "$INSTALL_DIR/"
  else
    (cd "$SRC_ROOT" && tar --exclude=.git --exclude='__pycache__' -cf - .) | tar -C "$INSTALL_DIR" -xf -
  fi
else
  command -v git >/dev/null || {
    log "Installing git"
    if   command -v apt-get >/dev/null; then apt-get install -y -qq git
    elif command -v dnf     >/dev/null; then dnf install -y git
    elif command -v yum     >/dev/null; then yum install -y git
    elif command -v pacman  >/dev/null; then pacman -S --noconfirm git
    elif command -v apk     >/dev/null; then apk add --no-cache git
    elif command -v zypper  >/dev/null; then zypper --non-interactive install git
    fi
  }
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    git -C "$INSTALL_DIR" pull --ff-only
  else
    rm -rf "$INSTALL_DIR" && git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
fi
[[ -f "$INSTALL_DIR/spacecop/cli.py" ]] || die "sources not found in $INSTALL_DIR"

# ---------------------------------------------------------------- native crypto
build_native() {
  # ChaCha20-Poly1305 in C (native/spacecop_crypto.c): 300x faster than the
  # pure-Python fallback. Needs gcc or clang; we try to install gcc, and the
  # node still works (slowly) without it.
  if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
    log "Installing gcc for the native crypto library"
    if   command -v apt-get >/dev/null; then apt-get install -y -qq gcc libc6-dev >/dev/null || true
    elif command -v dnf     >/dev/null; then dnf install -y gcc || true
    elif command -v yum     >/dev/null; then yum install -y gcc || true
    elif command -v pacman  >/dev/null; then pacman -S --noconfirm --needed gcc || true
    elif command -v apk     >/dev/null; then apk add --no-cache gcc musl-dev || true
    elif command -v zypper  >/dev/null; then zypper --non-interactive install gcc || true
    fi
  fi
  local cc=""
  command -v gcc >/dev/null 2>&1 && cc=gcc
  [[ -z "$cc" ]] && command -v cc >/dev/null 2>&1 && cc=cc
  if [[ -n "$cc" ]]; then
    if CC="$cc" bash "$INSTALL_DIR/native/build.sh" >/dev/null 2>&1; then
      log "Native crypto library built ($("$PY" -c "import sys; sys.path.insert(0,'$INSTALL_DIR'); from spacecop.crypto import aead; print(aead.backend())"))"
    else
      log "WARNING: native crypto build failed; the node will use pure Python (slow)."
    fi
  else
    log "WARNING: no C compiler; the node will use pure-Python crypto (slow). Install gcc and re-run."
  fi
}
build_native

# ---------------------------------------------------------------- 3. user/dirs
if ! id -u spacecop >/dev/null 2>&1; then
  log "Creating system user 'spacecop'"
  if command -v useradd >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin spacecop 2>/dev/null \
      || useradd --system --no-create-home --shell /sbin/nologin spacecop
  else
    adduser -S -D -H -s /sbin/nologin spacecop
  fi
fi
mkdir -p "$CONF_DIR"
chown -R spacecop:spacecop "$INSTALL_DIR" "$CONF_DIR"
chmod 750 "$CONF_DIR"

# ---------------------------------------------------------------- 4. identity
if [[ -f "$IDENTITY" ]]; then
  log "Keeping existing identity $IDENTITY"
else
  log "Generating persistent node identity -> $IDENTITY"
fi
(cd "$INSTALL_DIR" && sudo -u spacecop "$PY" -m spacecop.cli keygen --identity "$IDENTITY" >/dev/null)
chmod 600 "$IDENTITY"; chown spacecop:spacecop "$IDENTITY"

# ---------------------------------------------------------------- public IP
detect_ip() {
  local ip=""
  for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip="$(curl -fsS --max-time 4 "$url" 2>/dev/null | tr -d ' \n\r' || true)"
    [[ -n "$ip" ]] && { echo "$ip"; return; }
  done
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [[ -n "$ip" ]] && { echo "$ip"; return; }
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || true)"
  echo "${ip:-127.0.0.1}"
}
ADVERTISE="${SPACECOP_ADVERTISE:-$(detect_ip)}"
log "Advertised address: $ADVERTISE  (override with SPACECOP_ADVERTISE=...)"

# ---------------------------------------------------------------- 5. systemd
EXTRA_ARGS=""
[[ -n "${SPACECOP_BOOTSTRAP:-}" ]] && EXTRA_ARGS+=" --bootstrap $SPACECOP_BOOTSTRAP"
[[ -n "${SPACECOP_NO_EXIT:-}"   ]] && EXTRA_ARGS+=" --no-exit"

cat > "$CONF_DIR/node.env" <<EOF
# Generated by install_server.sh — edit and 'systemctl restart $SERVICE'.
SPACECOP_PORT=$PORT
SPACECOP_ADVERTISE=$ADVERTISE
SPACECOP_EXTRA_ARGS=$EXTRA_ARGS
EOF

if command -v systemctl >/dev/null && [[ -d /etc/systemd/system ]]; then
  log "Installing systemd service $SERVICE"
  cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=SpaceCopVPN relay node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=spacecop
Group=spacecop
EnvironmentFile=$CONF_DIR/node.env
WorkingDirectory=$INSTALL_DIR
# NOTE: \$SPACECOP_EXTRA_ARGS is deliberately WITHOUT braces: systemd passes
# \${VAR} as one argument even when empty (an empty '' argument breaks
# argparse), while \$VAR is word-split and yields no arguments when empty.
ExecStart=$PY -m spacecop.cli node --bind 0.0.0.0 --port \${SPACECOP_PORT} --advertise \${SPACECOP_ADVERTISE} --identity $IDENTITY \$SPACECOP_EXTRA_ARGS
Restart=always
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$CONF_DIR
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  # Verify the node really came up (a bad argument or port clash would
  # otherwise leave systemd restart-looping while we print a success banner).
  ok=0
  for _ in 1 2 3 4 5 6; do
    sleep 1
    if systemctl is-active --quiet "$SERVICE"; then ok=1; fi
  done
  if [[ $ok -eq 1 ]] && systemctl is-active --quiet "$SERVICE"; then
    log "Service $SERVICE is active"
  else
    echo
    warn "service $SERVICE is NOT running. Last log lines:"
    journalctl -u "$SERVICE" --no-pager -n 20 || true
    die "node failed to start; fix the error above and run: systemctl restart $SERVICE"
  fi
  # Local reachability: a protocol PING must get a PONG back through the socket.
  if ! (cd "$INSTALL_DIR" && "$PY" -m spacecop.cli ping --node "127.0.0.1:$PORT" --timeout 3 >/dev/null 2>&1); then
    warn "node did not answer a local PING on udp/$PORT yet (it may still be starting)."
  else
    log "Node answers PING on udp/$PORT"
  fi
else
  warn "systemd not found; start the node manually:"
  warn "  cd $INSTALL_DIR && $PY -m spacecop.cli node --port $PORT --advertise $ADVERTISE --identity $IDENTITY$EXTRA_ARGS"
fi

# ---------------------------------------------------------------- 6. firewall
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  log "Opening udp/$PORT in ufw"; ufw allow "$PORT/udp" >/dev/null || true
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  log "Opening udp/$PORT in firewalld"
  firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null && firewall-cmd --reload >/dev/null || true
else
  warn "no active ufw/firewalld detected; make sure udp/$PORT is reachable (cloud security groups too)."
fi

# ---------------------------------------------------------------- 7. done
URI="$(cd "$INSTALL_DIR" && "$PY" -m spacecop.cli uri --identity "$IDENTITY" --host "$ADVERTISE" --port "$PORT")"
echo
echo "=============================================================================="
echo "  SpaceCopVPN node is running."
echo
echo "  Connection URI (paste into the client / GUI):"
echo
echo "    $URI"
echo
echo "  Bootstrap: ${SPACECOP_BOOTSTRAP:-(none — this node announces to nobody; add --bootstrap host:port)}"
echo "  Service:   systemctl status $SERVICE     journalctl -u $SERVICE -f"
echo "  Identity:  $IDENTITY  (back it up: it IS the node's identity)"
echo "  Settings:  $CONF_DIR/node.env"
echo "=============================================================================="
