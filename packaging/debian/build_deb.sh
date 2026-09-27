#!/usr/bin/env bash
# Build a Debian/Ubuntu package (.deb) for the SpaceCopVPN client.
#
#   packaging/debian/build_deb.sh            # -> packaging/debian/spacecopvpn_<ver>_<arch>.deb
#   packaging/debian/build_deb.sh --install  # build and install it with apt
#
# The package installs the stdlib-only Python client under /usr/lib/spacecopvpn,
# the compiled native crypto library, /usr/bin launchers, and the app-menu
# entry. It depends on python3, python3-tk and policykit-1 (pkexec).
#
# The last line printed is the path to the built .deb (so other scripts can
# capture it).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

PKG=spacecopvpn
VER="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/pyproject.toml")"
case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  armv7l)  ARCH=armhf ;;
  *)       ARCH="$(dpkg --print-architecture 2>/dev/null || echo all)" ;;
esac

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
DEST="$BUILD/$PKG"

# --- payload: the Python package + its compiled native library ----------------
# Build the native crypto library first so the package copy picks it up from
# spacecop/crypto/lib/ (runtime falls back to pure Python if it is missing).
echo "building native crypto library" >&2
if ! bash "$ROOT/native/build.sh" >&2; then
  echo "WARNING: native build failed; packaging pure-Python only" >&2
fi

LIBDIR="$DEST/usr/lib/spacecopvpn"
mkdir -p "$LIBDIR"
cp -r "$ROOT/spacecop" "$LIBDIR/spacecop"   # includes crypto/lib/ just built
find "$LIBDIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

# --- launchers ----------------------------------------------------------------
mkdir -p "$DEST/usr/bin"
cat > "$DEST/usr/bin/spacecop" <<'EOF'
#!/bin/sh
exec python3 -c "import sys; sys.path.insert(0, '/usr/lib/spacecopvpn'); from spacecop.cli import main; main()" "$@"
EOF
cat > "$DEST/usr/bin/spacecop-gui" <<'EOF'
#!/bin/sh
exec python3 -c "import sys; sys.path.insert(0, '/usr/lib/spacecopvpn'); from spacecop.gui.app import main; main()" "$@"
EOF
chmod 0755 "$DEST/usr/bin/spacecop" "$DEST/usr/bin/spacecop-gui"

# --- desktop entry, docs, license --------------------------------------------
install -Dm644 "$ROOT/packaging/spacecop-gui.desktop" "$DEST/usr/share/applications/spacecop-gui.desktop"
install -Dm644 "$ROOT/README.ru.md" "$DEST/usr/share/doc/$PKG/README.ru.md"
[[ -f "$ROOT/LICENSE" ]] && install -Dm644 "$ROOT/LICENSE" "$DEST/usr/share/doc/$PKG/copyright"

# --- control metadata ---------------------------------------------------------
INSTALLED_KB="$(du -ks "$DEST" | cut -f1)"
mkdir -p "$DEST/DEBIAN"
cat > "$DEST/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.8), python3-tk, policykit-1
Recommends: gcc
Installed-Size: $INSTALLED_KB
Maintainer: SpaceCopVPN contributors <noreply@spacecop.shop>
Description: From-scratch decentralised, incentivised VPN client (GUI + CLI)
 A decentralised VPN with a custom wire protocol, node gossip, per-site exit
 pinning and a driver-free SOCKS5 tunnel, plus a whole-system TUN mode. The
 protocol and cryptography are implemented from scratch on the Python standard
 library, with an optional C ChaCha20-Poly1305 library for full speed.
EOF

# Byte-compile on install and refresh the desktop database.
cat > "$DEST/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
python3 -m compileall -q /usr/lib/spacecopvpn 2>/dev/null || true
update-desktop-database /usr/share/applications 2>/dev/null || true
exit 0
EOF
cat > "$DEST/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
rm -rf /usr/lib/spacecopvpn/spacecop/__pycache__ 2>/dev/null || true
update-desktop-database /usr/share/applications 2>/dev/null || true
exit 0
EOF
chmod 0755 "$DEST/DEBIAN/postinst" "$DEST/DEBIAN/postrm"

OUT="$HERE/${PKG}_${VER}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$DEST" "$OUT" >&2

if [[ "${1:-}" == "--install" ]]; then
  sudo apt-get install -y "$OUT" >&2 || sudo dpkg -i "$OUT" >&2
fi

# Last line: the artifact path (captured by install_client_ubuntu.sh).
echo "$OUT"
