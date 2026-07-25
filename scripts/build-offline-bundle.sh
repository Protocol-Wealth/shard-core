#!/usr/bin/env bash
# Fail-closed tombstone for the retired host-native release builder.
set -euo pipefail

cat >&2 <<'EOF'
The host-native offline bundle builder is permanently disabled.

It did not implement the reviewed Stage 6 isolation boundary and must not be
used for a ceremony or as release evidence.

Use the Python 3.11 candidate builder with independently approved executable,
configuration, image, lock, and wheelhouse digests:
  python3.11 scripts/build-offline-bundle.py --help

That builder emits an UNAPPROVED-CANDIDATE without an installer. Independent
review, producer authentication, a real Podman smoke test, and an authenticated
promotion process remain mandatory.
EOF
exit 1
