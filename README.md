# shard-core

[![CI](https://github.com/Protocol-Wealth/shard-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Protocol-Wealth/shard-core/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-1f6feb)](https://www.python.org/)
[![License: Apache--2.0 OR MIT--0](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT--0-2ea44f)](LICENSE)

`shard-core` protects sensitive bytes and recovery phrases with authenticated
encryption, threshold recovery, and fail-closed file handling.

> **Security status:** `0.2.0` is the first stable release and has not received
> an independent security audit. Tests and AI-assisted review are not a
> security audit. Use synthetic material for evaluation and rehearse recovery
> before protecting production secrets.

## What it provides

| Capability | Status |
|---|---|
| ChaCha20-Poly1305 authenticated encryption | Included |
| Scrypt passphrase encryption | Included |
| AEAD plus Shamir threshold protection | Included |
| Corrupt-extra-share recovery and ambiguity detection | Included |
| Fordefi Recovery Phrases workflow | Included |
| Optional SLIP-39 support | `.[slip39]` extra |
| Reproducible, hash-verified offline bundle pipeline | [Included](OFFLINE_BUILD.md) |
| Implicit plaintext output or silent overwrite | Refused |

## Architecture

### Protect

```text
plaintext
    |
    | encrypt with random 32-byte data-encryption key (DEK)
    v
ChaCha20-Poly1305 --------------------> authenticated ciphertext C
    ^                                               |
    |                                               |
random DEK -- Shamir split --> K1, K2, ... Kn       |
                              |                      |
                              +--> SHRD i = header + Ki + C
```

Each SHRD artifact contains a unique Shamir key share and the same ciphertext.
That duplication is intentional: every valid threshold subset is self-contained.
The trade-off is additional storage, not weaker confidentiality.

The plaintext itself is never Shamir-split. A wrong key-share combination fails
AEAD authentication instead of returning plausible but incorrect plaintext.

### Recover

```text
supplied SHRD files
    |
    v
parse and group candidate sets
    |
    v
try bounded threshold combinations
    |
    v
reconstruct DEK -> verify AEAD tag -> plaintext
                       |
                       +--> fail closed on corruption or ambiguity
```

See [THREAT_MODEL.md](THREAT_MODEL.md) for the security properties, assumptions,
and non-goals.

## Install

Requires Python 3.9 or newer.

### Quick install

Install the stable release from PyPI:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'shard-core==0.2.0'
shard-core --version
```

To include optional SLIP-39 support:

```bash
python -m pip install 'shard-core[slip39]==0.2.0'
```

To install the same immutable release from source instead:

```bash
git clone --branch v0.2.0 --depth 1 \
  https://github.com/Protocol-Wealth/shard-core.git
cd shard-core
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
shard-core --version
```

For development:

```bash
python -m pip install -e '.[test]'
```

### Advanced verified build

For a hash-locked, network-disabled, rootless Podman build and an installable
offline bundle, follow [OFFLINE_BUILD.md](OFFLINE_BUILD.md). The top-level
`install.sh` only dispatches to an already built offline bundle; it is not the
quick installer.

## Quickstart

### Authenticated threshold shares

```bash
shard-core protect \
  --threshold 2 \
  --shares 3 \
  --input secret.bin \
  --out-dir shares

shard-core verify-set --require-complete \
  shares/share-01.txt \
  shares/share-02.txt \
  shares/share-03.txt

shard-core recover \
  --output recovered.bin \
  shares/share-01.txt \
  shares/share-03.txt
```

### Passphrase encryption

```bash
shard-core encrypt --input secret.bin --output secret.shen
shard-core decrypt --input secret.shen --output recovered.bin
```

The commands prompt without echo. For controlled automation, use a private
regular file with `--passphrase-file`; environment-variable passphrases emit a
warning.

### Fordefi backup choice

Fordefi lets the operator choose among Public Key Upload, Recovery Phrases,
and managed provider or hardware-backed methods.

```text
Fordefi backup method
    |
    +--> Public Key Upload / native CoinCover / Station70 / YubiKey
    |        +--> public-key recovery path; shard-core is not required
    |
    +--> Recovery Phrases
             +--> phrase -> SHEN plus separate credential
             +--> phrase -> threshold SHRD shares
```

For the Recovery Phrases path, direct encryption is:

```bash
shard-core fordefi encrypt --output protocol-phrase.shen
shard-core fordefi decrypt \
  --input protocol-phrase.shen \
  --output protocol-phrase.txt
```

Fordefi phrase entry is hidden and confirmed twice. Standard entry requires 12
lowercase ASCII words; whitespace is canonicalized without changing spelling,
order, or case. `shard-core` does not assume a Fordefi phrase is BIP-39.

Follow [docs/FORDEFI-DISASTER-RECOVERY.md](docs/FORDEFI-DISASTER-RECOVERY.md)
for method selection, `2-of-2` phrase custody, external-custodian role checks,
and the final offline Fordefi recovery boundary.

### SLIP-39

Install `.[slip39]`, then use the explicit `slip39` command family for material
independently confirmed to be compatible:

```bash
shard-core slip39 split \
  --threshold 2 \
  --shares 3 \
  --bip39-file mnemonic.txt \
  --out-dir slip39-shares

shard-core slip39 combine \
  --bip39 \
  --output recovered-mnemonic.txt \
  slip39-shares/share-01.txt \
  slip39-shares/share-03.txt
```

## Safety defaults

- Sensitive recovery and decryption require `--output FILE` or deliberate
  `--stdout`.
- Existing output files are refused unless `--force` is explicit.
- Final-component symlinks are refused even with `--force`.
- Multi-file output is fully preflighted before any share is written.
- New secret files use mode `0600`; new private directories use mode `0700`.
- Identical duplicate shares are reported; conflicting duplicates fail.
- Independent complete sets in one recovery invocation fail as ambiguous.
- Recovery combinations are bounded to prevent uncontrolled work.
- Manifests contain artifact hashes and set metadata, never plaintext hashes.

These controls assume a trusted host and controlled parent directories. See
[THREAT_MODEL.md](THREAT_MODEL.md) and [CEREMONY.md](CEREMONY.md).

## Formats and compatibility

- SHEN v2 stores scrypt parameters, salt, nonce, tag, and ciphertext.
- SHRD v2 stores the authenticated common header, one key share, and ciphertext.
- SHEN v1/v2 and SHRD v1/v2 readers remain supported.
- Display comments and holder labels are not cryptographically authenticated.

Wire-format changes require a separate compatibility and cryptographic review.

## Documentation

- [CEREMONY.md](CEREMONY.md): generic safe operator workflow.
- [docs/FORDEFI-DISASTER-RECOVERY.md](docs/FORDEFI-DISASTER-RECOVERY.md): Fordefi-specific workflow.
- [OFFLINE_BUILD.md](OFFLINE_BUILD.md): reproducible verified bundle build.
- [THREAT_MODEL.md](THREAT_MODEL.md): assets, adversaries, assumptions, and scope.
- [SECURITY.md](SECURITY.md): vulnerability disclosure and support policy.
- [AGENTS.md](AGENTS.md): rules for AI agents assisting a human.
- [CHANGELOG.md](CHANGELOG.md): release history and compatibility notes.
- [CONTRIBUTING.md](CONTRIBUTING.md): development and review workflow.
- [SUPPORT.md](SUPPORT.md): support boundaries and safe issue reporting.
- [RELEASING.md](RELEASING.md): maintainer release procedure.

## Test

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -O -m unittest discover -s tests -v
```

## License

Dual-licensed under Apache-2.0 or MIT-0. See [LICENSE](LICENSE) and [LICENSE-MIT-0](LICENSE-MIT-0).
