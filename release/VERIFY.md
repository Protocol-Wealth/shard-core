# Verify and install the offline bundle

This directory is a self-contained, hash-locked `shard-core` distribution for
Linux x86_64 with CPython 3.9 or newer and glibc 2.17 or newer.

## Verify

Transfer the complete directory. From its root, verify the recorded inventory:

```bash
sha256sum -c SHA256SUMS
```

Do not install if any file is missing, extra, or has a mismatched digest. The
installer repeats these checks and refuses symlinked files.

`BUNDLE-METADATA.json`, `PROVENANCE.json`, and `SBOM.spdx.json` record the
source revision, pinned build image, dependency locks, tools, and isolated build
configuration. `APPROVED-CANDIDATE.txt` records that the automated bundle
contract completed; it is not a security-audit or warranty statement.

## Install without network access

Choose a new installation path:

```bash
./install-offline.sh /controlled/path/shard-core-venv
/controlled/path/shard-core-venv/bin/shard-core --version
```

The installer verifies `SHA256SUMS`, creates a virtual environment, and invokes
pip only with `--no-index`, the bundled wheelhouse, and `--require-hashes`. It
refuses an existing target, including a dangling symlink.

Keep the bundle, its `SHA256SUMS`, and any non-secret build evidence together if
you need reproducible release records. Never place recovery phrases, shards,
passphrases, wrapping credentials, or other secrets in build evidence.
