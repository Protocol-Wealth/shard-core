# Verify and install this ceremony bundle

This directory is a platform-specific, hash-locked transport bundle. It is not
a signature and does not establish who produced or approved the artifacts.

On the offline manylinux2014 x86_64, CPython 3.9+ ceremony host:

```bash
sha256sum -c SHA256SUMS
./install-offline.sh /controlled/path/shard-core-venv
/controlled/path/shard-core-venv/bin/shard-core --version
```

Before production use, independently verify:

- The bundle arrived through the approved custody-transfer path.
- `SHA256SUMS` matches a separately authenticated copy.
- The wheel names and hashes match the reviewed release record.
- `SBOM.spdx.json` identifies runtime dependencies and build tools.
- `BUILD_INFO.txt` records the exact source commit, source-archive digest,
  lock digests, builder Python and pip versions, and target platform.
- `BUILD_TOOLS.txt` matches the independently reviewed build-tool lock.
- The host has no active network path and uses a controlled private directory.
- A synthetic end-to-end ceremony succeeds before real recovery material is
  entered.

The installer rejects symlinks and unlisted files, refuses an existing target,
checks every transferred artifact listed in `SHA256SUMS`, and calls pip with
`--no-index`, `--find-links`, and `--require-hashes`.
