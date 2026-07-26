# Changelog

All notable changes to `shard-core` are documented here.

The project follows semantic versioning. SHEN and SHRD wire-format
compatibility is treated separately and remains explicitly versioned.

## [Unreleased]

No changes yet.

## [0.3.0] - 2026-07-26

Second stable open-source release.

### Added

- A guided custody-route selector covering provider-native workflows,
  externally held SHEN artifacts, and SHRD distribution across custodians,
  businesses, or trusted people.
- Vendor-neutral CoinCover, Station70 Bunker, Station70 Custom Upload, Nemean,
  peer-to-peer, tri-party, and nested-provider custody patterns without adding
  vendor APIs or changing SHEN/SHRD formats.

### Changed

- Written-file verification in the guided SHRD flow, exact file-byte
  preservation, Fordefi-specific routing, hidden-input enforcement, and
  non-empty passphrase checks for the expanded custody workflow.
- The guided encryption output default now uses the `.shen` extension.
- Written SHRD and SLIP-39 artifacts are now read back and verified through
  their respective recovery implementations before the wizard recommends
  distribution.
- The generic ceremony and threat model now distinguish offline `shard-core`
  work from provider-required controlled connected environments.
- CLI share guidance now distinguishes below-threshold plaintext
  confidentiality from visible share headers and ciphertext length.

### Compatibility

- SHEN v1 and v2 artifacts remain readable.
- SHRD v1 and v2 artifacts remain readable.
- This release does not change SHEN v2 or SHRD v2 wire bytes.

### Known limitations

- External providers must independently confirm accepted artifact formats,
  release authentication, and retrieval procedures.
- The advanced verified bundle profile remains Linux x86_64, CPython 3.9+
  ABI3, with a reviewed Python 3.11 rootless-Podman builder.
- The project has not received an independent professional security audit.

## [0.2.0] - 2026-07-25

First stable open-source release.

### Added

- ChaCha20-Poly1305 authenticated encryption with scrypt passphrase
  derivation.
- AEAD plus Shamir threshold protection that splits a random data-encryption
  key rather than plaintext.
- Resilient recovery across bounded threshold combinations.
- Detection of conflicting duplicate indices and ambiguous independent sets.
- `verify-set` complete-set authentication and non-secret manifests.
- Safe atomic output, explicit plaintext destinations, overwrite protection,
  symlink refusal, and private file and directory modes.
- Fordefi Recovery Phrases split/combine and direct SHEN encrypt/decrypt
  workflows with hidden double entry and 12-word validation.
- Optional explicit SLIP-39 support for independently confirmed compatible
  material.
- Reproducible, hash-verified, network-disabled Linux x86_64 offline bundle
  pipeline using reviewed rootless Podman inputs.
- Operator, Fordefi, offline-build, threat-model, security, and AI-agent
  documentation.

### Compatibility

- SHEN v1 and v2 artifacts remain readable.
- SHRD v1 and v2 artifacts remain readable.
- The stable release does not change SHEN v2 or SHRD v2 wire bytes from the
  reviewed release candidate.

### Known limitations

- The advanced verified bundle profile currently targets Linux x86_64,
  CPython 3.9+ ABI3, and a reviewed Python 3.11 rootless-Podman builder.
- The project has not received an independent professional security audit.
- Safe output assumes a trusted host and controlled parent directories.
- `shard-core` does not invoke Fordefi's recovery tool or define external
  custodian authentication and release procedures.

[Unreleased]: https://github.com/Protocol-Wealth/shard-core/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Protocol-Wealth/shard-core/releases/tag/v0.3.0
[0.2.0]: https://github.com/Protocol-Wealth/shard-core/releases/tag/v0.2.0
