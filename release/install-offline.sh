#!/usr/bin/env bash
# Installed into the root of a generated Linux x86_64 ceremony bundle.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET=${1:-"$HOME/.shard-core"}

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "this bundle is only for Linux x86_64" >&2
  exit 1
fi

python3 -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null || {
  echo "Python 3.9 or newer is required" >&2
  exit 1
}

if [[ -e "$TARGET" ]]; then
  echo "refusing existing installation target: $TARGET" >&2
  exit 1
fi

(
  cd "$ROOT"
  sha256sum -c SHA256SUMS
)

python3 -m venv "$TARGET"
"$TARGET/bin/python" -m pip install \
  --no-index \
  --find-links "$ROOT/wheels" \
  --require-hashes \
  -r "$ROOT/requirements-linux-x86_64.txt"

"$TARGET/bin/shard-core" --version
printf 'installed offline at %s\n' "$TARGET"
