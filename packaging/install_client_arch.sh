#!/usr/bin/env bash
# One-command client install on Arch Linux (and derivatives: Manjaro, EndeavourOS…).
#
#   ./packaging/install_client_arch.sh            # build the package and install it
#   ./packaging/install_client_arch.sh --user     # no package: pip --user install + desktop entry
#
# After installation:  spacecop-gui   (or find "SpaceCopVPN" in the app menu)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

if ! command -v pacman >/dev/null 2>&1; then
  echo "pacman not found: this installer targets Arch Linux." >&2
  echo "On other systems run:  pip install --user $ROOT   then  spacecop-gui" >&2
  exit 1
fi

echo "==> Installing system dependencies (python, tk)"
sudo pacman -S --needed --noconfirm python tk

if [[ "${1:-}" == "--user" ]]; then
  echo "==> Installing into your user site-packages (no system package)"
  sudo pacman -S --needed --noconfirm python-pip
  python -m pip install --user --break-system-packages "$ROOT"
  mkdir -p "$HOME/.local/share/applications"
  install -Dm644 "$HERE/spacecop-gui.desktop" "$HOME/.local/share/applications/spacecop-gui.desktop"
  # ~/.local/bin must be on PATH for the desktop entry to find spacecop-gui.
  if ! command -v spacecop-gui >/dev/null 2>&1; then
    sed -i "s|^Exec=.*|Exec=$HOME/.local/bin/spacecop-gui|" \
      "$HOME/.local/share/applications/spacecop-gui.desktop"
  fi
  update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
else
  echo "==> Building and installing the Arch package"
  sudo pacman -S --needed --noconfirm base-devel python-build python-installer python-wheel python-setuptools
  "$HERE/arch/build.sh" --install
fi

echo
echo "Установлено: $(spacecop --version 2>/dev/null || echo 'spacecop не в PATH — откройте новый терминал')"
echo "Готово. Запуск графического клиента:  spacecop-gui   (в левом нижнем углу окна — версия)"
echo "Или из меню приложений: «SpaceCopVPN»."
echo "Вставьте в окно строку подключения вида spacecop://host:port/<ключ>/<id>,"
echo "которую печатает узел (или скрипт deploy/install_server.sh)."
