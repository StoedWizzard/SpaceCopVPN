#!/usr/bin/env bash
# =============================================================================
#  SpaceCopVPN — update a running node to the latest code and restart it.
#
#    sudo /opt/spacecop/deploy/update_server.sh          # git pull inside /opt/spacecop
#    sudo ./deploy/update_server.sh                      # from any checkout: copies it
#
#  The service runs from /opt/spacecop.  Pulling in some other clone (e.g.
#  ~/SpaceCopVPN) does NOT update the node — this script does, then restarts
#  the service and shows the new version in the log.
# =============================================================================
set -euo pipefail

INSTALL_DIR=/opt/spacecop
SERVICE=spacecop-node
log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run as root (sudo)."
[[ -d "$INSTALL_DIR" ]] || die "$INSTALL_DIR not found; run deploy/install_server.sh first."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SRC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$SRC_ROOT" != "$INSTALL_DIR" && -f "$SRC_ROOT/spacecop/cli.py" ]]; then
  log "Copying $SRC_ROOT -> $INSTALL_DIR"
  if command -v rsync >/dev/null; then
    rsync -a --delete --exclude .git --exclude '__pycache__' "$SRC_ROOT/" "$INSTALL_DIR/"
  else
    (cd "$SRC_ROOT" && tar --exclude=.git --exclude='__pycache__' -cf - .) | tar -C "$INSTALL_DIR" -xf -
  fi
elif [[ -d "$INSTALL_DIR/.git" ]]; then
  log "git pull in $INSTALL_DIR"
  git -C "$INSTALL_DIR" pull --ff-only
else
  die "$INSTALL_DIR is not a git checkout; run this script from an updated clone instead."
fi
find "$INSTALL_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
chown -R spacecop:spacecop "$INSTALL_DIR" 2>/dev/null || true

NEW_VER="$(cd "$INSTALL_DIR" && python3 -c 'import spacecop; print(spacecop.__version__)')"
log "Installed code version: $NEW_VER"

log "Restarting $SERVICE"
systemctl restart "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  log "Service is active (PID $(systemctl show -p MainPID --value "$SERVICE"))"
  journalctl -u "$SERVICE" --no-pager -n 8 | sed 's/^/    /'
else
  journalctl -u "$SERVICE" --no-pager -n 20
  die "service failed to start after update"
fi
