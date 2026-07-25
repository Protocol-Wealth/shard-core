# Contributing

Contributions are welcome when they preserve the project's security and
compatibility boundaries.

## Before opening an issue

- Read [README.md](README.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
  [SECURITY.md](SECURITY.md).
- Search existing issues and pull requests.
- Use synthetic material only.
- Never include a real phrase, shard, passphrase, wrapping credential,
  snapshot, private key, or hash of a secret file.
- Report vulnerabilities through GitHub private vulnerability reporting, not
  a public issue.

## Development

Requires Python 3.9 or newer.

```bash
git clone https://github.com/Protocol-Wealth/shard-core.git
cd shard-core
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
```

Run normal and optimized tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -O -m unittest discover -s tests -v
```

Run `git diff --check` before submitting.

## Pull requests

- Keep changes focused and explain the behavioral invariant being changed.
- Add synthetic tests for bug fixes and new behavior.
- Preserve explicit plaintext output, safe overwrite behavior, and symlink
  refusal.
- Preserve SHEN v1/v2 and SHRD v1/v2 read compatibility.
- Do not change SHEN or SHRD wire bytes, cryptographic composition, or
  recovery trust boundaries without a separate design and compatibility
  review.
- Do not add networking, telemetry, update checks, or vendor APIs.
- Update user, operator, threat-model, and release documentation when the
  applicable contract changes.

Tests and review are engineering evidence, not a security audit.
