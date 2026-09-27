#!/usr/bin/env bash
# Copy the SpaceCopVPN Python package into the Android app's Python source set
# (app/src/main/python), which Chaquopy bundles into the APK.  Run before every
# build; CI does it automatically.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../spacecop"
DST="$HERE/app/src/main/python"
rm -rf "$DST/spacecop"
mkdir -p "$DST"
cp -r "$SRC" "$DST/spacecop"
find "$DST" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
echo "synced $(find "$DST/spacecop" -name '*.py' | wc -l) Python files into $DST/spacecop"
