#!/usr/bin/env bash
# Installed into a manylinux2014 x86_64, CPython 3.9+ ceremony bundle.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET=${1:-"$HOME/.shard-core"}

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "this bundle requires Linux x86_64" >&2
  exit 1
fi
python3 -c '
import platform
import sys

libc_name, libc_version = platform.libc_ver()
version = tuple(int(part) for part in libc_version.split(".")[:2])
if platform.python_implementation() != "CPython" or sys.version_info < (3, 9):
    raise SystemExit("installer requires CPython 3.9 or newer")
if libc_name != "glibc" or version < (2, 17):
    raise SystemExit("installer requires glibc 2.17 or newer")
'

if [[ -e "$TARGET" || -L "$TARGET" ]]; then
  echo "refusing existing installation target: $TARGET" >&2
  exit 1
fi

if find "$ROOT" -type l -print -quit | grep -q .; then
  echo "refusing symlink inside ceremony bundle" >&2
  exit 1
fi
actual_inventory=$(cd "$ROOT" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort)
listed_inventory=$(cd "$ROOT" && awk '{print $2}' SHA256SUMS | LC_ALL=C sort)
if [[ "$actual_inventory" != "$listed_inventory" ]]; then
  echo "bundle file inventory differs from SHA256SUMS" >&2
  diff -u <(printf '%s\n' "$listed_inventory") <(printf '%s\n' "$actual_inventory") >&2 || true
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
