# Reproducible verified offline build

The advanced build path creates an installable, hash-verified offline bundle
without allowing the build containers to access a network. It is intended for
operators whose custody boundary excludes live package-index access.

For ordinary connected installation, use the README quick-install path.

## What reproducible means here

The canonical builder, `scripts/build-offline-bundle.py`, builds the project
twice from the same reviewed inputs in separate network-disabled OCI
containers and compares the results. It fails rather than emitting a candidate
when the compared artifacts differ.

```text
reviewed commit + hash locks + reviewed wheels + pinned tools/image
        -> isolated OCI build A --+
                                  +-> byte comparison
        -> isolated OCI build B --+
                                  -> candidate + provenance + SHA256SUMS
                                  -> offline verification and installation
```

This is reproducibility within the approved input, interpreter, container,
runtime, and platform boundary. It is not a claim that arbitrary hosts or
unapproved toolchains produce identical bytes.

## Supported build boundary

The current candidate profile is:

- Linux x86_64 host;
- dedicated local, rootless Podman ceremony account;
- exactly Python 3.11 for the builder boundary;
- CPython 3.9+, ABI3, manylinux_2_17_x86_64 runtime bundle;
- pre-populated runtime and build wheelhouses verified against committed
  SHA-256 locks;
- exact Git, Python, Podman, crun, conmon, Podman-configuration, image-index,
  platform-manifest, and image-config digests;
- read-only source, wheelhouse, and configuration inputs;
- explicit Podman graph root and run root;
- `--network=none` build containers with no package download.

Hosted CI checks parser, static, and builder-boundary contracts. It does not perform the controlled rootless-Podman two-build ceremony and is not candidate provenance.

## Source and locks

Start from a clean reviewed commit. The canonical locks are:

```text
release/locks/runtime-cp39-abi3-manylinux_2_17_x86_64.txt
release/build-requirements.txt
```

Do not generate or update hashes during the candidate build. Lock changes are
separate review work.

## Fetch the reviewed wheelhouses

Wheel acquisition occurs on the connected preparation host before entering
the network-disabled build boundary. The fetcher requires hashes already
present in the selected lock and refuses to update the lock.

```bash
PYTHON311=/approved/path/python3.11
REVIEWED=/controlled/run/reviewed
mkdir -p "$REVIEWED"

"$PYTHON311" scripts/fetch-reviewed-wheels.py \
  --lock release/locks/runtime-cp39-abi3-manylinux_2_17_x86_64.txt \
  --destination "$REVIEWED/runtime-wheels" \
  --receipt "$REVIEWED/runtime-fetch-receipt.json" \
  --platform manylinux_2_17_x86_64 \
  --python-version 39 \
  --implementation cp \
  --abi abi3

"$PYTHON311" scripts/fetch-reviewed-wheels.py \
  --lock release/build-requirements.txt \
  --destination "$REVIEWED/build-wheels" \
  --receipt "$REVIEWED/build-fetch-receipt.json" \
  --platform manylinux_2_17_x86_64 \
  --python-version 311 \
  --implementation cp \
  --abi none
```

Create only the parent `reviewed/` directory. The fetcher must exclusively
create each wheelhouse and will refuse an existing destination. Never delete or
reuse a prior wheelhouse to make a failed run pass.

## Run the canonical builder

The builder requires every approved boundary input explicitly. Use
`python3.11 scripts/build-offline-bundle.py --help` for the authoritative
argument list. A complete invocation has this shape:

```bash
"$PYTHON311" scripts/build-offline-bundle.py \
  --expected-source-commit "$SOURCE_COMMIT" \
  --expected-runtime-lock-sha256 "$RUNTIME_LOCK_SHA256" \
  --expected-build-lock-sha256 "$BUILD_LOCK_SHA256" \
  --git-path "$GIT_PATH" \
  --expected-git-sha256 "$GIT_SHA256" \
  --python-path "$PYTHON311" \
  --expected-python-sha256 "$PYTHON_SHA256" \
  --podman-path "$PODMAN_PATH" \
  --expected-podman-sha256 "$PODMAN_SHA256" \
  --expected-oci-runtime-sha256 "$CRUN_SHA256" \
  --expected-conmon-sha256 "$CONMON_SHA256" \
  --expected-ceremony-uid "$CEREMONY_UID" \
  --expected-ceremony-user "$CEREMONY_USER" \
  --empty-hooks-dir "$EMPTY_HOOKS_DIR" \
  --podman-config-root "$PODMAN_CONFIG_ROOT" \
  --expected-podman-config-sha256 "$PODMAN_CONFIG_SHA256" \
  --podman-data-root "$PODMAN_DATA_ROOT" \
  --podman-runtime-root "$PODMAN_RUNTIME_ROOT" \
  --build-image "$BUILD_IMAGE" \
  --expected-build-image-digest "$IMAGE_INDEX_DIGEST" \
  --expected-platform-manifest-digest "$PLATFORM_MANIFEST_DIGEST" \
  --expected-image-config-digest "$IMAGE_CONFIG_DIGEST" \
  --runtime-wheelhouse "$REVIEWED/runtime-wheels" \
  --build-wheelhouse "$REVIEWED/build-wheels" \
  --output-parent "$CANDIDATE_PARENT"
```

All uppercase values are approved inputs from the controlled build record, not
values for the builder to discover and trust. Use canonical executable paths.
The ceremony account's current working directory must be its reviewed source
directory, never another user's home directory.

`scripts/build-offline-bundle.sh` is intentionally disabled for candidate
creation. Do not revive it as a parallel release path.

## Verify and install the candidate

The neutral candidate directory is named like:

```text
shard-core-0.3.0-offline-cp39-abi3-manylinux_2_17_x86_64
```

On the offline host:

```bash
cd shard-core-*-offline-cp39-abi3-manylinux_2_17_x86_64
sha256sum -c SHA256SUMS
./install-offline.sh /controlled/path/shard-core-venv
/controlled/path/shard-core-venv/bin/python -m pip check
/controlled/path/shard-core-venv/bin/shard-core --version
```

The installer refuses an existing path or dangling symlink, verifies
`SHA256SUMS`, and invokes pip with `--no-index`, `--find-links`, and
`--require-hashes`.

Follow the candidate's `VERIFY.md` before installation.

## Evidence record

Preserve only sanitized, non-secret evidence:

- source commit and Git tree;
- UTC start and completion times;
- the sanitized smoke-evidence record and candidate `SHA256SUMS` hashes;
- project wheel filename and hash;
- runtime and build lock hashes;
- runtime and build wheelhouse inventory hashes;
- Git, Python, Podman, crun, and conmon executable hashes;
- Podman configuration-tree hash;
- image index, platform manifest, and image config digests;
- candidate install, `pip check`, import-smoke, and CLI-version results;
- host Windows/WSL version, WSL kernel, Linux distribution, Podman cgroup
  manager/version, storage driver, and systemd-user-session availability.

Never include a recovery phrase, shard, wrapping credential, private key,
snapshot contents, or operational credential.

A tested WSL environment may legitimately report `cgroupfs`, cgroup v2, `vfs`,
and no systemd user session. Those characteristics do not weaken the approved
build boundary when the builder still binds and verifies the exact Podman
configuration, graph root, run root, runtime executables, image digests,
read-only inputs, and network-disabled containers. Record the warning and the
reason rather than treating unexplained console output as evidence.

See [release/evidence/README.md](release/evidence/README.md) for the committed
evidence schema and [release/VERIFY.md](release/VERIFY.md) for bundle checks.
