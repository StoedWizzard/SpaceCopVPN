#!/usr/bin/env bash
# Build and (optionally) install the Arch Linux package for SpaceCopVPN.
#
#   packaging/arch/build.sh          # build  -> packaging/arch/spacecopvpn-*.pkg.tar.zst
#   packaging/arch/build.sh --install
#
# Creates the source tarball makepkg expects from the current checkout, so
# whatever is in your working tree is what gets packaged.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PKGNAME=spacecopvpn
PKGVER="$(sed -n 's/^pkgver=\(.*\)$/\1/p' "$HERE/PKGBUILD")"

if ! command -v makepkg >/dev/null 2>&1; then
  echo "makepkg not found: this script is for Arch Linux (install 'base-devel')." >&2
  exit 1
fi

echo "==> Creating source tarball $PKGNAME-$PKGVER.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/$PKGNAME-$PKGVER"
# Copy the project without VCS metadata and build artefacts.
tar -C "$ROOT" \
  --exclude=.git --exclude='__pycache__' --exclude='*.pyc' \
  --exclude=dist --exclude=build --exclude='*.egg-info' \
  --exclude='packaging/arch/*.pkg.tar.*' --exclude='packaging/arch/src' \
  --exclude='packaging/arch/pkg' --exclude='packaging/arch/*.tar.gz' \
  -cf - . | tar -C "$TMP/$PKGNAME-$PKGVER" -xf -
tar -C "$TMP" -czf "$HERE/$PKGNAME-$PKGVER.tar.gz" "$PKGNAME-$PKGVER"

cd "$HERE"
echo "==> Running makepkg"
if [[ "${1:-}" == "--install" ]]; then
  makepkg -sfi --noconfirm
else
  makepkg -sf --noconfirm
  echo
  echo "Package built:"
  ls -1 "$HERE"/*.pkg.tar.* 2>/dev/null || true
  echo "Install with:  sudo pacman -U $HERE/$PKGNAME-$PKGVER-*.pkg.tar.zst"
fi
