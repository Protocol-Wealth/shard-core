#!/usr/bin/env bash
# Fail-closed tombstone for the retired host-native release builder.
set -euo pipefail

cat >&2 <<'EOF'
The host-native offline bundle builder is permanently disabled.

It does not implement the isolated rootless Podman build boundary and must not
be used as bundle provenance.

Use the Python 3.11 offline bundle builder:
  python3.11 scripts/build-offline-bundle.py --help
EOF
exit 1
