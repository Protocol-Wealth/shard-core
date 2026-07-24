#!/usr/bin/env bash
# Network-free dispatcher for a generated shard-core ceremony bundle.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
shopt -s nullglob
bundles=("$ROOT"/dist/shard-core-*-offline-linux-x86_64)

if (( ${#bundles[@]} != 1 )); then
  cat >&2 <<'EOF'
No unique offline ceremony bundle was found under dist/.

Build one on a connected packaging host:
  bash scripts/build-offline-bundle.sh

Transfer the resulting dist/shard-core-*-offline-linux-x86_64 directory to the
offline ceremony host, verify SHA256SUMS, and run its install-offline.sh.
This dispatcher never contacts a package index.
EOF
  exit 1
fi

exec "${bundles[0]}/install-offline.sh" "$@"
