#!/usr/bin/env bash
# Produce the runtime ceremony lock on a trusted connected Linux x86_64 host.
# The downloaded wheels are retained for independent inspection.
set -euo pipefail
shopt -s nullglob

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "lock generation requires Linux x86_64" >&2
  exit 1
fi

IN="release/ceremony-requirements-linux-x86_64.in"
OUT="release/ceremony-requirements-linux-x86_64.txt"
if [[ -n "${SHARD_CORE_LOCK_REVIEW_DIR:-}" ]]; then
  REVIEW_DIR=$SHARD_CORE_LOCK_REVIEW_DIR
  if [[ -e "$REVIEW_DIR" || -L "$REVIEW_DIR" ]]; then
    echo "review directory must not already exist: $REVIEW_DIR" >&2
    exit 1
  fi
  mkdir -m 0700 -p "$REVIEW_DIR"
else
  REVIEW_DIR=$(mktemp -d /tmp/shard-core-lock-review.XXXXXX)
fi
LOCK_TMP=$(mktemp "$ROOT/release/.ceremony-lock.XXXXXX")

python3 -m pip download \
  --only-binary=:all: \
  --no-deps \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 39 \
  --abi abi3 \
  --dest "$REVIEW_DIR" \
  -r "$IN"

{
  echo "# Pre-reviewed, hash-locked inputs for the Linux x86_64 ceremony wheelhouse."
  echo "# Generated from ceremony-requirements-linux-x86_64.in after independent"
  echo "# inspection of the upstream wheels. Do not regenerate casually."
  echo "#"

  while read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    name=${line%%==*}
    version=${line#*==}
    wheel_name=${name//-/_}
    matches=("$REVIEW_DIR"/"$wheel_name"-"$version"-*.whl)

    if (( ${#matches[@]} != 1 )); then
      echo "expected exactly one manylinux2014 wheel for $line" >&2
      printf '  %s\n' "${matches[@]}" >&2
      exit 1
    fi

    digest=$(sha256sum "${matches[0]}" | awk '{print $1}')
    printf '%s==%s --hash=sha256:%s\n' "$name" "$version" "$digest"
    printf 'selected %s\n' "$(basename "${matches[0]}")" >&2
  done < "$IN"
} > "$LOCK_TMP"

mv "$LOCK_TMP" "$OUT"
printf 'wrote %s\n' "$OUT"
printf 'review wheels retained at %s; do not commit the lock before independent inspection\n' "$REVIEW_DIR"
