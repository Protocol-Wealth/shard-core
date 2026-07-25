#!/usr/bin/env bash
# The source tree cannot promote or install a ceremony candidate.
set -euo pipefail

cat >&2 <<'EOF'
The source-tree ceremony installer is disabled.

The canonical Stage 6 builder emits an UNAPPROVED-CANDIDATE with no installer.
Do not use a legacy dist/ bundle. A candidate must first pass independent
review, producer authentication, and the separately controlled promotion gate.
This command never contacts a package index.
EOF
exit 1
