#!/usr/bin/env bash
# Build the native crypto library for the current platform into
# spacecop/crypto/lib/ (where spacecop.crypto.native looks first).
#
#   native/build.sh            # gcc/clang; output libspacecop_crypto.so / .dylib / .dll
#   CC=clang native/build.sh
#
# Windows: run from a shell where gcc (MinGW-w64) is on PATH, or use build.ps1.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../spacecop/crypto/lib"
mkdir -p "$OUT"
CC="${CC:-gcc}"
case "$(uname -s)" in
  Darwin)                 target="$OUT/libspacecop_crypto.dylib"; extra="-dynamiclib" ;;
  MINGW*|MSYS*|CYGWIN*)   target="$OUT/spacecop_crypto.dll";      extra="-shared" ;;
  *)                      target="$OUT/libspacecop_crypto.so";    extra="-shared -fPIC -fvisibility=hidden" ;;
esac
# shellcheck disable=SC2086
"$CC" -O3 -std=c99 -Wall -Wextra $extra ${CFLAGS:-} -o "$target" "$HERE/spacecop_crypto.c"
echo "built $target"
