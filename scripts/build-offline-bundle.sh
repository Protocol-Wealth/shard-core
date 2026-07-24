#!/usr/bin/env bash
# Build a hash-locked shard-core ceremony bundle on a connected packaging host.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "this builder currently supports Linux x86_64 only" >&2
  exit 1
fi

VERSION=$(PYTHONPATH=src python3 -c 'from shard_core import __version__; print(__version__)')
BUNDLE_NAME="shard-core-${VERSION}-offline-linux-x86_64"
BUNDLE="$ROOT/dist/$BUNDLE_NAME"
PINS="$ROOT/release/ceremony-requirements-linux-x86_64.in"

if [[ -e "$BUNDLE" ]]; then
  echo "refusing existing bundle: $BUNDLE" >&2
  exit 1
fi

mkdir -p "$BUNDLE/wheels"

python3 -m build \
  --wheel \
  --outdir "$BUNDLE/wheels" \
  "$ROOT"

python3 -m pip download \
  --only-binary=:all: \
  --dest "$BUNDLE/wheels" \
  -r "$PINS"

pycryptodome_version=$(sed -n 's/^pycryptodome==//p' "$PINS")
shamir_version=$(sed -n 's/^shamir-mnemonic==//p' "$PINS")
mnemonic_version=$(sed -n 's/^mnemonic==//p' "$PINS")

write_requirement() {
  local requirement_name=$1
  local requirement_version=$2
  local wheel_pattern=$3
  local matches=("$BUNDLE"/wheels/$wheel_pattern)

  if (( ${#matches[@]} != 1 )); then
    echo "expected exactly one wheel matching $wheel_pattern" >&2
    exit 1
  fi

  local digest
  digest=$(sha256sum "${matches[0]}" | awk '{print $1}')
  printf '%s==%s --hash=sha256:%s\n' \
    "$requirement_name" "$requirement_version" "$digest"
}

{
  write_requirement shard-core "$VERSION" "shard_core-${VERSION}-*.whl"
  write_requirement pycryptodome "$pycryptodome_version" \
    "pycryptodome-${pycryptodome_version}-*.whl"
  write_requirement shamir-mnemonic "$shamir_version" \
    "shamir_mnemonic-${shamir_version}-*.whl"
  write_requirement mnemonic "$mnemonic_version" \
    "mnemonic-${mnemonic_version}-*.whl"
} > "$BUNDLE/requirements-linux-x86_64.txt"

cp "$ROOT/release/install-offline.sh" "$BUNDLE/install-offline.sh"
cp "$ROOT/release/VERIFY.md" "$BUNDLE/VERIFY.md"
chmod 0755 "$BUNDLE/install-offline.sh"

cat > "$BUNDLE/SBOM.spdx.json" <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "$BUNDLE_NAME",
  "documentNamespace": "https://github.com/Protocol-Wealth/shard-core/offline/$BUNDLE_NAME",
  "creationInfo": {
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "creators": ["Tool: scripts/build-offline-bundle.sh"]
  },
  "packages": [
    {"name": "shard-core", "SPDXID": "SPDXRef-shard-core", "versionInfo": "$VERSION", "downloadLocation": "NOASSERTION", "filesAnalyzed": false},
    {"name": "pycryptodome", "SPDXID": "SPDXRef-pycryptodome", "versionInfo": "$pycryptodome_version", "downloadLocation": "NOASSERTION", "filesAnalyzed": false},
    {"name": "shamir-mnemonic", "SPDXID": "SPDXRef-shamir-mnemonic", "versionInfo": "$shamir_version", "downloadLocation": "NOASSERTION", "filesAnalyzed": false},
    {"name": "mnemonic", "SPDXID": "SPDXRef-mnemonic", "versionInfo": "$mnemonic_version", "downloadLocation": "NOASSERTION", "filesAnalyzed": false}
  ]
}
EOF

(
  cd "$BUNDLE"
  find wheels -maxdepth 1 -type f -print
  printf '%s\n' \
    requirements-linux-x86_64.txt \
    SBOM.spdx.json \
    install-offline.sh \
    VERIFY.md
) | sort | (
  cd "$BUNDLE"
  xargs sha256sum > SHA256SUMS
)

printf 'built %s\n' "$BUNDLE"
printf 'review every wheel and authenticate SHA256SUMS before transfer\n'
