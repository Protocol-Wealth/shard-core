# Threat model

## Security goals

`shard-core` aims to provide:

- confidentiality of protected plaintext against holders below the configured
  threshold;
- integrity and authenticity of recovered plaintext through AEAD verification;
- availability when a valid threshold subset remains accessible;
- fail-closed handling of corrupt shares, conflicting duplicates, mixed
  independent sets, unsafe output paths, and accidental terminal disclosure;
- verifiable, hash-locked inputs for the advanced offline bundle workflow.

## Assets

- plaintext secrets and Fordefi recovery phrases;
- random data-encryption keys and reconstructed keys;
- passphrases and generated wrapping credentials;
- SHEN ciphertexts and SHRD share files;
- Fordefi encrypted backup snapshots;
- recovered plaintext and Fordefi private-key CSV output;
- manifests, bundle hashes, build locks, and provenance records;
- the integrity of the CLI, dependencies, offline bundle, and recovery host.

SHEN and SHRD files are ciphertext or custody artifacts, not public data. Their
headers and ciphertext lengths expose limited metadata.

## Architecture

### Protection

```text
plaintext -- ChaCha20-Poly1305(random DEK) --> ciphertext C

random DEK -- Shamir --> K1, K2, ... Kn

SHRD 1 = authenticated header + K1 + C
SHRD 2 = authenticated header + K2 + C
...
SHRD n = authenticated header + Kn + C
```

Ciphertext duplication is intentional. Each share remains independently
transportable and every valid threshold subset contains everything needed for
recovery. Storage grows with the number of shares.

### Recovery

```text
SHRD inputs
    -> strict parse and candidate-set grouping
    -> duplicate/conflict checks
    -> bounded threshold combinations
    -> reconstruct candidate DEK
    -> authenticate and decrypt C
    -> one unambiguous plaintext or failure
```

At least one authenticating threshold combination is sufficient for recovery.
Complete-set verification is stricter: every expected threshold combination
must authenticate.

## Adversaries and failures considered

- a holder or transport path that corrupts, truncates, replaces, or reorders an
  artifact;
- an operator who accidentally mixes shares from different protection runs;
- an extra unrelated or corrupt share supplied with a valid threshold subset;
- an attempt to overwrite an existing output or redirect it through a symlink;
- accidental plaintext disclosure through implicit stdout;
- weak or empty passphrase sources and insecure passphrase-file permissions;
- dependency, wheel, executable, configuration, or OCI-image substitution in
  the advanced build path;
- unbounded combination work from an excessive input set;
- metadata collection from manifests, comments, filenames, and headers.

## Trust assumptions

- The operating system, kernel, Python interpreter, terminal, entropy source,
  CPU, memory, and storage firmware on the working host are trusted.
- Parent directories are controlled by the operator. Safe output handling does
  not claim complete resistance when an attacker can race arbitrary parent
  path components.
- PyCryptodome, optional SLIP-39 dependencies, and the reviewed build toolchain
  behave as specified.
- Holders and custodians enforce the agreed authentication, authorization,
  retention, and release procedures.
- The operator verifies software and artifact hashes through an authenticated
  channel and uses current vendor recovery instructions.
- Fordefi's recovery tool and backup snapshot are obtained and verified
  separately; shard-core does not invoke or attest to them.

## Attack surface

- CLI argument parsing, hidden prompts, file and environment secret sources;
- SHEN and SHRD parsers and compatibility readers;
- AEAD, scrypt, Shamir split/combine, and recovery candidate grouping;
- manifests, labels, comments, filenames, and non-secret evidence;
- output preflight, permissions, atomic writes, and explicit stdout;
- optional SLIP-39 parsing and BIP-39 conversion;
- wheel acquisition, locks, Podman configuration, OCI image inspection,
  bundle creation, checksums, and the offline installer;
- operator commands copied from documentation or supplied by an AI assistant.

## Out of scope

- a compromised kernel, hypervisor, firmware, RNG, terminal, or offline host;
- malware, keyloggers, screen capture, cold-boot attacks, and memory forensics;
- physical coercion, insider collusion at or above threshold, and custodian
  contractual failure;
- choosing the right threshold, holders, jurisdictions, or business-continuity
  policy for an organization;
- Fordefi, CoinCover, Qapture, Nemean, Station70, YubiKey, or other vendor
  implementation and service security;
- guaranteed secure deletion on journaling, copy-on-write, virtualized, or SSD
  storage;
- byte-for-byte reproducibility across unapproved platforms or toolchains;
- proving custody, possession, authorization, or identity from a hash or
  manifest;
- protecting plaintext after it is intentionally recovered for use.

## Operational assumptions

- Production ceremonies run on a controlled offline host with private working
  directories and no recording or screen sharing.
- Operators use explicit output paths, verify complete generated sets before
  distribution, and conduct synthetic recovery rehearsals.
- Encrypted artifacts, key shares, and wrapping credentials follow the approved
  separation model and are retrievable during a disaster.
- The latest Fordefi snapshot is retained whenever Fordefi is part of the
  recovery design.
- Secrets are never placed in logs, manifests, hashes, screenshots, shell
  history, issue bodies, pull requests, or AI conversations.
