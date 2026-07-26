# Support

`shard-core` is an open-source project, not a custody service, recovery
provider, or managed ceremony.

## Ordinary questions and bugs

Use the GitHub issue templates:

https://github.com/Protocol-Wealth/shard-core/issues/new/choose

Provide:

- the `shard-core --version` result;
- operating system and Python version;
- the exact command with all secrets removed;
- synthetic reproduction steps;
- non-secret error output.

Do not attach or paste a real phrase, shard, passphrase, wrapping credential,
Fordefi snapshot, recovered private key, or secret-file hash.

## Security vulnerabilities

Use GitHub private vulnerability reporting:

https://github.com/Protocol-Wealth/shard-core/security/advisories/new

Do not report an unpatched vulnerability publicly.

## Custodian and vendor procedures

Questions about artifact acceptance, custody, authentication, authorization,
retention, retrieval, or release are governed by the applicable provider
agreement. The project cannot define Qapture, Nemean, CoinCover, Fordefi,
Station70, or another provider's current operational requirements.

Use [docs/CUSTODY-PATTERNS.md](docs/CUSTODY-PATTERNS.md) to select between a
provider-native workflow, one externally held SHEN artifact, and threshold
SHRD distribution. `shard-core` does not run provider CLIs or upload files.

For Fordefi recovery, use the current official Fordefi documentation in
addition to the repository runbook.

## No warranty

The software is provided under its licenses without warranty. Review the
threat model and complete a synthetic recovery rehearsal before using it with
production material.
