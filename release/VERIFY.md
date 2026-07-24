# Verify and install this ceremony bundle

This directory is a platform-specific, hash-locked transport bundle. It is not
a signature and does not establish who produced or approved the artifacts.

On the offline Linux x86_64 ceremony host:

```bash
sha256sum -c SHA256SUMS
./install-offline.sh /controlled/path/shard-core-venv
/controlled/path/shard-core-venv/bin/shard-core --version
```

Before production use, independently verify:

- The bundle arrived through the approved custody-transfer path.
- `SHA256SUMS` matches a separately authenticated copy.
- The wheel names and hashes match the reviewed release record.
- `SBOM.spdx.json` identifies every bundled wheel.
- The host has no active network path and uses a controlled private directory.
- A synthetic end-to-end ceremony succeeds before real recovery material is
  entered.

The installer refuses an existing target, checks every bundled file, and calls
pip with `--no-index`, `--find-links`, and `--require-hashes`.
