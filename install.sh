#!/usr/bin/env bash
# shard-core installer for Linux / WSL / macOS.
# Installs the `shard-core` command (with SLIP-39 support) in an isolated env.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Installing shard-core (offline secret-sharding tool)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 (>= 3.9) is required. Install Python 3, then re-run this script." >&2
  exit 1
fi

if command -v pipx >/dev/null 2>&1; then
  echo "==> Using pipx (isolated install)"
  pipx install --force '.[slip39]'
  echo "==> If 'shard-core' is not found, run:  pipx ensurepath   (then reopen your shell)"
else
  echo "==> pipx not found; installing into a venv at ~/.shard-core"
  python3 -m venv "$HOME/.shard-core"
  "$HOME/.shard-core/bin/pip" install --quiet --upgrade pip
  "$HOME/.shard-core/bin/pip" install --quiet '.[slip39]'
  mkdir -p "$HOME/.local/bin"
  ln -sf "$HOME/.shard-core/bin/shard-core" "$HOME/.local/bin/shard-core"
  echo "==> Installed to ~/.local/bin/shard-core"
  echo "    Ensure ~/.local/bin is on your PATH (add to ~/.bashrc or ~/.zshrc if needed):"
  echo '        export PATH="$HOME/.local/bin:$PATH"'
fi

echo "==> Verifying"
if command -v shard-core >/dev/null 2>&1; then
  shard-core --version
elif [ -x "$HOME/.local/bin/shard-core" ]; then
  "$HOME/.local/bin/shard-core" --version
fi

echo ""
echo "Done. Start with:  shard-core          # guided, interactive mode"
echo "Or explore:        shard-core --help"
