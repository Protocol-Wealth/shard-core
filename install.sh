#!/usr/bin/env bash
# Dispatch to the installer in exactly one previously built offline bundle.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET=${1:-"$HOME/.shard-core"}
DIST="$ROOT/dist"

if [[ -L "$DIST" ]]; then
  echo "refusing symlinked offline bundle directory: $DIST" >&2
  exit 1
fi

shopt -s nullglob
bundles=(
  "$DIST"/shard-core-*-offline-cp39-abi3-manylinux_2_17_x86_64
)

if (( ${#bundles[@]} == 0 )); then
  echo "no offline bundle found under $ROOT/dist" >&2
  echo "build one with scripts/build-offline-bundle.py" >&2
  exit 1
fi
if (( ${#bundles[@]} != 1 )); then
  echo "multiple offline bundles found under $ROOT/dist" >&2
  echo "run the selected bundle's install-offline.sh directly" >&2
  exit 1
fi
if [[ -L "${bundles[0]}" || ! -d "${bundles[0]}" ]]; then
  echo "refusing symlinked or non-directory offline bundle" >&2
  exit 1
fi

installer="${bundles[0]}/install-offline.sh"
if [[ ! -f "$installer" || -L "$installer" || ! -x "$installer" ]]; then
  echo "bundle installer is missing, symlinked, or not executable" >&2
  exit 1
fi

exec "$installer" "$TARGET"
