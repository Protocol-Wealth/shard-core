# Fordefi disaster-recovery operator runbook

This runbook first helps the operator choose a Fordefi backup method. It then
provides the detailed `shard-core` workflow for a Fordefi **Recovery Phrases**
backup with two designated admins and a `2-of-2` Fordefi threshold.

This is an operational guide, not a substitute for Fordefi's current
documentation or a custodian agreement. Perform production phrase handling on
a controlled offline host.

Official references:

- [Fordefi: Backup methods](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys)
- [Fordefi: Use Public Key Upload](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys/backup-private-keys-upload)
- [Fordefi: Use Recovery Phrases](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys/backup-private-keys-phrases)
- [Fordefi: Manage Your Backup](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys/manage-backup)
- [Fordefi: Recover Private Keys](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys/recovery/recover-private-keys)

Check those pages before every production ceremony because vendor screens,
downloads, checksums, and recovery-tool commands can change.

## 1. Choose the Fordefi backup method

Do not create shard-core artifacts until the organization has chosen its
Fordefi backup method.

### Option 1: public-key backup

Choose Fordefi **Public Key Upload** when the backup snapshot should be
encrypted to an RSA-2048 public key while the matching private key remains
under separate custody. For a self-managed backup, generate the key pair on
the approved offline system, keep the private key offline, and upload only the
PEM public key to Fordefi.

The recovery inputs are:

- the current encrypted Fordefi backup snapshot; and
- the private key matching the public key configured in Fordefi.

The Fordefi recovery tool uses its `public-key-recover` path for this method.
`shard-core` is not required. Do not add SHEN or SHRD protection to the RSA
private key unless the organization has documented the extra custody layer
and tested the complete recovery path.

Fordefi also documents managed public-key variants through CoinCover and
Station70 and a hardware-backed YubiKey flow. In Fordefi's native
[CoinCover method](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys/backup-private-keys-coincover),
CoinCover retains the matching private key and Fordefi encrypts the backup to
CoinCover's public key. That differs from asking CoinCover to store a
shard-core `.shen` file.

### Option 2: recovery phrases

Choose Fordefi **Recovery Phrases** when multiple designated administrators
will each hold a unique 12-word phrase and a configured threshold of those
phrases will authorize recovery. In the Protocol Wealth example below,
Fordefi is configured as `2-of-2`, so both independently issued phrases are
required.

The recovery inputs are:

- the current encrypted Fordefi backup snapshot; and
- the configured threshold of Fordefi recovery phrases.

This is the path where `shard-core` can encrypt a phrase as a SHEN artifact or
split it into SHRD shares. Continue with the remaining sections only after
selecting this option.

The backup-method choice is an organizational custody decision, not a
`shard-core` default.

## 2. Understand the Recovery Phrases artifacts

A Recovery Phrases backup has separate components:

| Artifact | Meaning | Secret? |
|---|---|---|
| Fordefi backup snapshot | Encrypted workspace/vault backup, normally a `.json` inside the delivered archive | Treat as sensitive |
| Fordefi phrase P1 | Unique 12-word phrase generated for designated admin 1 | Yes |
| Fordefi phrase P2 | Unique 12-word phrase generated for designated admin 2 | Yes |
| `P1.shen` or `P2.shen` | A phrase encrypted by `shard-core` with scrypt and ChaCha20-Poly1305 | Ciphertext, but still custody-sensitive |
| SHEN wrapping credential | The passphrase or generated credential required to decrypt a `.shen` file | Yes |
| SHRD share | One threshold share produced by `fordefi split` | Custody-sensitive |

For Fordefi `2-of-2`, recovery requires the encrypted backup snapshot and both
Fordefi phrases. Protecting P1 or P2 with SHEN or SHRD does not change
Fordefi's threshold; it changes how your organization stores that phrase.

## 3. Do not mix two different CoinCover models

Fordefi's documented **Use CoinCover** method is a separate backup method. In
that model, CoinCover holds a private RSA key and Fordefi receives the matching
public key.

This runbook instead uses Fordefi **Recovery Phrases**. If CoinCover is asked
to store `P2.shen`, CoinCover is acting as an external storage/custody provider
under your agreement, not through Fordefi's native CoinCover integration.

Before transfer, obtain written answers from every external custodian:

1. Will it accept an opaque Base64 text file such as `P2.shen`?
2. Who stores the separate wrapping credential?
3. What authentication and approval are required to release each artifact?
4. Does the custodian alter filenames, line endings, archives, or file bytes?
5. How will both parties verify the file SHA-256 at deposit and retrieval?

`shard-core` cannot infer or enforce those contractual procedures.

## 4. Choose how each Fordefi phrase is protected

### Option A: direct SHEN encryption

Use this when one custodian will store one encrypted phrase artifact.

```bash
shard-core fordefi encrypt \
  --output /controlled/output/fordefi-admin-1.shen
```

The command:

1. Reads P1 through a hidden prompt.
2. Reads P1 a second time and compares the canonical phrases.
3. Requires exactly 12 lowercase ASCII words unless the operator deliberately
   uses `--allow-nonstandard-phrase`.
4. Reads and confirms a wrapping passphrase through hidden prompts.
5. Writes a SHEN v2 encrypted artifact using a safe atomic write.

The file sent to a storage custodian is
`fordefi-admin-1.shen`. The plaintext phrase is not sent.

SHEN requires a separate wrapping credential. Without it, the `.shen` file
cannot be decrypted. Do not send the `.shen` file and its credential through
the same channel or give both to the same holder unless that concentration is
an explicit design decision.

To generate a high-entropy credential instead of choosing a passphrase:

```bash
shard-core generate-key \
  --bytes 32 \
  --encoding hex \
  --output /controlled/credential/fordefi-admin-1-wrap.key

shard-core fordefi encrypt \
  --passphrase-file /controlled/credential/fordefi-admin-1-wrap.key \
  --output /controlled/output/fordefi-admin-1.shen
```

The phrase is still entered twice through hidden prompts. Transfer the
credential through a separately approved custody path, then remove only the
temporary working copy after confirming custody.

### Option B: SHRD threshold shares

Use this when the phrase itself should require multiple storage holders and you
do not want a separate wrapping passphrase.

Example for one Fordefi phrase:

```bash
shard-core fordefi split \
  --threshold 2 \
  --shares 4 \
  --labels protocol,qapture,nemean,coincover \
  --out-dir /controlled/output/admin-1-shares \
  --manifest /controlled/output/admin-1-shares/manifest.json

shard-core verify-set \
  --require-complete \
  /controlled/output/admin-1-shares/share-*.txt
```

Repeat the procedure independently for P2 if both Fordefi phrases require
threshold protection. A `2-of-4` SHRD policy protects one Fordefi phrase; it
does not replace Fordefi's separate `2-of-2` requirement across P1 and P2.

### Option C: SLIP-39

Do not use SLIP-39 merely because the Fordefi value has 12 words.
`shard-core` does not assume a Fordefi recovery phrase is BIP-39. Use the
advanced SLIP-39 command only after independently confirming the input is
BIP-39 material and intentionally choosing that format.

## 5. Create the Fordefi Recovery Phrases backup

Follow Fordefi's current **Use Recovery Phrases** page. At a high level:

1. In the Fordefi web console, open `Settings`, then `Backup`.
2. Select `Recovery Phrases`.
3. Designate the two admin recovery-key holders and configure the minimum as
   `2-of-2`.
4. Configure the approved backup email or documented manual-download path.
5. Initiate the backup process.
6. On each designated admin's mobile device, open the backup request from
   `Management` > `Inbox`.
7. Each admin creates a key, records their unique 12-word phrase in order, and
   confirms it in the app.
8. Confirm the backup completes and obtain the latest encrypted backup
   snapshot.

Do not paste P1 or P2 into chat, tickets, email, shared documents, shell
history, or command-line arguments.

## 6. Deposit and record non-secret evidence

For each encrypted artifact:

```bash
sha256sum /controlled/output/fordefi-admin-1.shen
```

The custody receipt may record:

- artifact filename
- ciphertext SHA-256
- `SHEN-v2`
- depositing and receiving roles
- UTC deposit time
- release-policy identifier
- confirmation that the wrapping credential followed a separate path

Do not record:

- phrase text or phrase hash
- wrapping credential or credential hint
- SHRD contents
- recovered private keys
- screenshots containing secret material

Hashing the encrypted `.shen` artifact is appropriate for transfer integrity.
Do not hash the plaintext phrase.

## 7. Pre-stage recovery materials

Fordefi recommends retaining access to:

1. The latest encrypted backup snapshot.
2. The required recovery phrases or the protected artifacts needed to rebuild
   them.
3. An offline copy of Fordefi's current recovery tool and recovery guide.
4. Fordefi's published checksum for the exact recovery-tool ZIP.
5. A compatible external offline computer.

Verify the recovery-tool ZIP using Fordefi's currently published checksum
before moving it to the offline host. Do not reuse a checksum from this
runbook.

## 8. Recover P1 and P2 on the offline host

Create a private temporary working directory. On Linux, a controlled `tmpfs`
such as `/dev/shm` may be appropriate:

```bash
install -d -m 0700 /dev/shm/fordefi-recovery
```

Recover direct SHEN artifacts:

```bash
shard-core fordefi decrypt \
  --input /custody/fordefi-admin-1.shen \
  --output /dev/shm/fordefi-recovery/admin-1.txt

shard-core fordefi decrypt \
  --input /custody/fordefi-admin-2.shen \
  --output /dev/shm/fordefi-recovery/admin-2.txt
```

The command reads the wrapping credential through a hidden prompt, authenticates
the SHEN blob, revalidates the recovered Fordefi phrase, and requires an
explicit plaintext destination.

Recover SHRD-protected phrases with the required shares:

```bash
shard-core fordefi combine \
  --output /dev/shm/fordefi-recovery/admin-1.txt \
  /custody/admin-1/share-protocol.txt \
  /custody/admin-1/share-qapture.txt
```

Never use `--stdout` during a production recovery unless terminal disclosure is
an explicitly approved part of the ceremony.

## 9. Run Fordefi's recovery tool separately

`shard-core` deliberately does not invoke Fordefi's recovery tool.

On the offline host:

1. Verify and extract the current Fordefi recovery-tool ZIP.
2. Extract the encrypted backup snapshot archive.
3. Follow the exact command and binary name in Fordefi's current recovery
   guide.
4. Select the Recovery Phrases / `key-share-recover` flow.
5. Provide the snapshot path and an explicit output path on protected offline
   storage. The resulting CSV is unencrypted private-key material.
6. Enter the required phrases only when the Fordefi tool prompts locally.
7. Treat the resulting CSV and every recovered private key as critical secret
   material.

Fordefi currently documents a `--silent-verification` option that validates
snapshot contents without performing a full key recovery or displaying
sensitive input. Prefer that for routine snapshot verification when it meets
the test objective.

Fordefi's recovery CSV contains unencrypted private-key material. Write it only to an explicit path on protected offline storage; the output file is not encrypted by `shard-core`.

## 10. Close the recovery workspace

1. Confirm the intended recovery or migration result.
2. Move recovered keys only through the approved destination workflow.
3. Remove temporary plaintext phrase files and private-key outputs from the
   working filesystem.
4. End the offline session and follow the organization's media sanitization
   policy.
5. Preserve only non-secret evidence such as tool/archive hashes, artifact
   ciphertext hashes, timestamps, command versions, and PASS/FAIL results.
6. Never claim that a synthetic smoke test proves custody availability. Test
   each custodian's release procedure under its contract.

## 11. AI-guided ceremony protocol

An AI may guide the human, but it must not receive secrets.

The AI should:

1. State the current numbered step and its non-secret expected result.
2. Give one command at a time.
3. Tell the human when a local hidden prompt will appear.
4. Ask the human to reply only with `PASS`, an error message with secrets
   removed, a filename, or an approved ciphertext, tool, archive, or release-artifact SHA-256 value; never a phrase or secret-file hash.
5. Stop on unexpected files, symlinks, overwrites, hash mismatches, phrase
   validation failures, or custody-role ambiguity.

The AI must never ask the human to paste P1, P2, a SHRD share, a SHEN wrapping
credential, snapshot contents, or recovered private keys.
