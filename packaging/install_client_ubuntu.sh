#!/usr/bin/env bash
# One-command client install on Ubuntu / Debian (and derivatives: Mint, Pop!_OS…).
#
#   ./packaging/install_client_ubuntu.sh            # build a .deb and install it (recommended)
#   ./packaging/install_client_ubuntu.sh --user     # no package: pip --user install + desktop entry
#
# After installation:  spacecop-gui   (or find "SpaceCopVPN" in the app menu)
#
# Installs the graphical client and the CLI, compiles the native ChaCha20-Poly1305
# library (for full speed), and adds the app-menu entry. "Whole system" mode uses
# pkexec (policykit), which is pulled in as a dependency.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found: this installer targets Ubuntu/Debian." >&2
  echo "On other systems run:  pip install --user $ROOT   then  spacecop-gui" >&2
  exit 1
fi

# Build tools + gcc are needed for the native crypto library; python3-tk for the GUI;
# policykit-1 provides pkexec for whole-system mode.
echo "==> Installing system dependencies (python3, tk, gcc, policykit)"
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-tk gcc libc6-dev policykit-1 python3-pip

echo "==> Building the native crypto library"
bash "$ROOT/native/build.sh" || echo "WARNING: native build failed; the client will use pure Python (slower)."

if [[ "${1:-}" == "--user" ]]; then
  echo "==> Installing into your user site-packages (no system package)"
  # Newer pip refuses to touch a system Python without this flag; harmless otherwise.
  python3 -m pip install --user --break-system-packages "$ROOT" 2>/dev/null \
    || python3 -m pip install --user "$ROOT"
  mkdir -p "$HOME/.local/share/applications"
  install -Dm644 "$HERE/spacecop-gui.desktop" "$HOME/.local/share/applications/spacecop-gui.desktop"
  if ! command -v spacecop-gui >/dev/null 2>&1; then
    sed -i "s|^Exec=.*|Exec=$HOME/.local/bin/spacecop-gui|" \
      "$HOME/.local/share/applications/spacecop-gui.desktop"
  fi
  update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
else
  echo "==> Building and installing the .deb package"
  sudo apt-get install -y -qq dpkg-dev
  DEB="$("$HERE/debian/build_deb.sh" | tail -1)"
  echo "==> Installing $DEB"
  sudo apt-get install -y "$DEB" || sudo dpkg -i "$DEB"
fi

echo
echo "Установлено: $(spacecop --version 2>/dev/null || echo 'spacecop не в PATH — откройте новый терминал')"
echo "Готово. Запуск графического клиента:  spacecop-gui   (в левом нижнем углу окна — версия)"
echo "Или из меню приложений: «SpaceCopVPN»."
echo "Вставьте в окно строку подключения вида spacecop://host:port/<ключ>/<id>,"
echo "которую печатает узел (или скрипт deploy/install_server.sh)."
