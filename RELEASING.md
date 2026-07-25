# Releasing shard-core

This procedure applies to maintainers publishing a stable GitHub release and,
when configured, the same version to PyPI.

## 1. Prepare the release commit

- Update `pyproject.toml` and `src/shard_core/__init__.py`.
- Update `CHANGELOG.md`, `SECURITY.md`, `README.md`, and bundle-name examples.
- Update version-sensitive tests.
- Confirm the worktree is clean and the release commit is reviewed.

## 2. Validate

Run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -O -m unittest discover -s tests -v
python -m build --no-isolation
```

Inspect both the wheel and source-distribution metadata. The default build
constructs the wheel from the generated source distribution. Install the
wheel into a clean environment and run the CLI, core protect/recover, Fordefi
SHEN, SLIP-39, and `pip check` smoke tests.

Run the controlled rootless-Podman ceremony from the exact merged release
commit. Preserve the sanitized evidence described in `OFFLINE_BUILD.md`.

## 3. Assemble the GitHub release

Enable immutable releases before publication. Create a draft release for the
annotated tag `vX.Y.Z`, then attach every final asset before publishing:

- project wheel;
- source distribution;
- offline bundle archive;
- `SHA256SUMS`;
- SBOM;
- build information;
- sanitized smoke-evidence record.

Never attach phrases, shards, wrapping credentials, snapshots, recovered
keys, or secret-file hashes.

Publish the draft only after asset names and hashes match the release record.
Do not move or reuse a stable tag.

## 4. Publish to PyPI

PyPI publication is optional and separate from the GitHub release. If the
version will be published to PyPI, configure its pending Trusted Publisher
before creating the stable tag. A pending publisher does not reserve the
project name.

The workflow `.github/workflows/publish-pypi.yml` is manual and requires an
exact PyPI Trusted Publisher configuration:

- owner: `Protocol-Wealth`;
- repository: `shard-core`;
- workflow: `publish-pypi.yml`;
- environment: `pypi`.

Run the workflow with the immutable release tag. Do not use a long-lived PyPI
API token. The unprivileged build job transfers both distributions to a
separate OIDC-enabled publish job. Confirm the published version and
installation from a clean environment before changing the README
quick-install command.

If the Trusted Publisher has not been configured, do not run the workflow and
do not document a PyPI installation command. The GitHub release and verified
offline bundle remain valid independently.

## 5. Close out

- Verify the GitHub release and its attestation.
- Verify release asset hashes locally.
- Verify the public project page and repository metadata.
- Confirm CI, CodeQL, and the PyPI workflow are green.
- Return the local checkout to clean, synchronized `main`.
