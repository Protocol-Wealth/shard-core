# Custodian, peer, and multi-party custody patterns

`shard-core` can protect any file as one passphrase-encrypted SHEN artifact or
as threshold SHRD artifacts. It does not connect to a custodian, upload files,
or replace a provider's native encryption tool.

Choose the custody route before opening a secret:

| Route | What `shard-core` creates | Recovery requires |
|---|---|---|
| Provider-native workflow | Nothing | Provider artifacts, provider release process, and every provider-required credential or device |
| One encrypted artifact | One SHEN file | SHEN file plus its separately held wrapping credential |
| Threshold distribution | Two or more SHRD files | Any configured threshold of matching SHRD files |

Do not combine routes merely to add layers. Every extra tool, credential, and
holder is also another recovery dependency.

## Provider-native workflows

Use this route when the custodian requires its own CLI to read the original
plaintext file, its own browser-based encryption, or a wallet-provider
integration. Provider-native workflows have their own artifacts,
authentication factors, approval policies, and recovery tools.

### CoinCover Key Vault CLI

CoinCover's Key Vault CLI reads the original key file, encrypts it locally,
and uploads only ciphertext. Cancel any `shard-core` encryption prompt and
follow the current official
[CoinCover CLI integration guide](https://developer.coincover.com/institutional-recovery/cli-integration-guide).
Do not create a `.shen` or SHRD file for that route unless CoinCover has
confirmed in writing that the selected product accepts that artifact and the
complete nested recovery has been rehearsed.

`shard-core` deliberately does not:

- request or store a CoinCover API key, control identifier, or other provider
  credential;
- select CoinCover's RSA or envelope mode or reproduce changeable size
  cutoffs;
- run the CoinCover CLI, inspect its receipt directory, or upload a backup.

Treat the current provider guide and the applicable agreement as authoritative
for commands, limits, receipt locations, authentication, and release.

### Station70 Bunker

[Station70](https://www.station70.com/) describes Bunker as an institutional
backup and recovery service with direct integrations for Fordefi, Fireblocks,
and Utila. It also documents a separate Custom Upload path and a SWAT
(Secure Wallet Account Transfer) capability. Its public architecture summary
says backup decryption material is split between customer-controlled hardware
and Station70 HSMs so Station70 cannot decrypt a backup by itself; confirm the
exact allocation and recovery dependencies for the selected product and plan.

These are distinct routes:

| Station70 route | Current documented behavior | `shard-core` role |
|---|---|---|
| Native Fordefi/Bunker integration | Station70 supplies a PEM public key for Fordefi Public Key Upload; Fordefi encrypts the backup, which is enrolled into a Station70 recovery policy | None |
| Bunker Custom Upload | The operator enters text or attaches a file; the Bunker browser encrypts it before ciphertext upload | None by default |
| SWAT | Coordinates supported provider-to-provider continuity into a linked standby wallet; it is not a backup-file transfer | None |
| Station70 holds SHEN or one SHRD file | Possible only if the selected Station70 service and agreement explicitly accept that exact artifact | Existing SHEN or SHRD creation only |

For the native Fordefi route, follow Fordefi's current
[Use Station70](https://docs.fordefi.com/user-guide/backup-and-recover-private-keys/backup-private-keys-station70)
page and Station70's current
[Fordefi backup instructions](https://kb.station70.com/requesting-your-fordefi-backup).
Fordefi describes Station70 as generating the public/private backup-key pair,
delivering the PEM public key for upload, and governing release of the
matching private-key material through Bunker. Station70 documents recovery
policies and YubiKey-authenticated approvals. `shard-core` is not part of this
public-key path.

[Bunker Custom Upload](https://kb.station70.com/custom-upload-overview) is
general-purpose: Station70 says the Bunker console accepts text or an attached
file, encrypts it in the browser, and uploads ciphertext. Its documented use
cases include private keys, seed phrases, enterprise secrets, and wallet
backups. The current description says a backup-encryption key is generated in
a Nitro Enclave and split into customer, cloud, and HSM shares, with customer
cryptographic participation required during recovery. If the original
plaintext is supplied to Custom Upload, do not pre-encrypt it with
`shard-core` unless a deliberately nested design has been approved and
rehearsed.

Custom Upload moves the browser, connected host, Station70 console, recovery
policy, customer share, and authentication hardware into the trust and
availability boundary. That is different from `shard-core`'s controlled
offline-host ceremony. Station70's
[recovery overview](https://kb.station70.com/how-to-recover-your-backup)
currently describes policy approvals and YubiKey verification; exact
passphrases, devices, quorum, download formats, and release steps must be
confirmed during onboarding and before every production ceremony.

[SWAT](https://kb.station70.com/what-is-swat) is a provider-to-provider
business-continuity route, not a file-encryption format. Supported source
wallets, standby wallets, asset types, account linking, subscription level,
and recovery behavior can change. Use the current Station70 documentation and
agreement rather than treating SWAT as SHEN or SHRD recovery.

## One encrypted artifact for an external holder

Use SHEN when a provider, business, or trusted person has confirmed that it
will preserve and return an opaque Base64 text file byte-for-byte:

```bash
shard-core encrypt \
  --input /controlled/input/report.txt \
  --output /controlled/output/report.shen
```

The passphrase is entered twice at local hidden prompts. Send only
`report.shen` to the artifact holder. Assign the wrapping credential to a
different approved custody path unless concentration is intentional.

[Nemean's public site](https://nemeanservices.co.uk/) says it stores MPC
shards, seed-phrase fragments, and encrypted backups, but that does not
establish that a particular service accepts SHEN or SHRD bytes. Obtain written
confirmation of the accepted file format, maximum size, byte-preservation
behavior, custody role, release authentication, and retrieval procedure before
transfer.

Station70 Custom Upload publicly documents attached-file input, but that alone
does not prove that a recovered SHEN file will be returned byte-for-byte in
the form expected by `shard-core`. Confirm the output format and complete the
nested synthetic recovery before using Station70 as the SHEN artifact holder.

## Threshold distribution across custodians or peers

Use SHRD when two or more independently controlled holders should cooperate.
The holders can be providers, businesses, directors, advisers, trusted
friends, or a deliberate mix:

```bash
shard-core protect \
  --threshold 2 \
  --shares 3 \
  --labels protocol,station70,trusted-friend \
  --input /controlled/input/report.txt \
  --out-dir /controlled/output/report-shares \
  --manifest /controlled/output/report-shares/manifest.json

shard-core verify-set --require-complete \
  /controlled/output/report-shares/share-protocol.txt \
  /controlled/output/report-shares/share-station70.txt \
  /controlled/output/report-shares/share-trusted-friend.txt
```

Each SHRD file contains one key share and a copy of the authenticated
ciphertext. A below-threshold holder cannot decrypt the file, and any valid
threshold can recover it. Holder labels are operational comments and are not
cryptographically authenticated.

Common policies have different availability properties:

| Policy | Cooperation | Availability consequence |
|---|---|---|
| `2-of-2` | Both holders | Either unavailable holder blocks recovery |
| `2-of-3` | Any two holders | One holder may be unavailable |
| `3-of-5` | Any three holders | Two holders may be unavailable |

Threshold choice is an organizational risk decision. It must consider
collusion, loss, jurisdiction, succession, release time, and retrievability.

## A provider protecting one SHRD share

A provider-native CLI may be able to encrypt and store one SHRD file as an
opaque input. That creates nested protection:

```text
provider release and decrypt
        -> one SHRD file
        -> threshold of matching SHRD files
        -> original plaintext
```

Use this hybrid only when the provider confirms that the product accepts the
SHRD file rather than requiring the original key material. Record the nested
recovery order and rehearse it with synthetic material. A provider release is
then only one share; it does not recover the original file by itself.

For Station70, Custom Upload may provide the general attached-file route, but
the organization must still confirm that it accepts a SHRD file, preserves the
recovered bytes, and returns the file through a tested release process. For
CoinCover, confirm that the selected product accepts an SHRD artifact rather
than requiring original key material. For Nemean or another custodian, the
same questions are contractual inputs.

## Contract checks for every external holder

Before deposit, confirm:

1. The exact accepted artifact: original plaintext, SHEN, SHRD, or another
   provider-defined format.
2. Whether filenames, line endings, archives, or bytes are transformed.
3. Who holds every separate wrapping or provider credential.
4. Authentication, authorization, quorum, timing, escalation, and succession
   for release.
5. How ciphertext or share SHA-256 values are compared at deposit and
   retrieval.
6. How a complete synthetic recovery will be rehearsed through the real
   release process.

Never send a provider credential, phrase, shard, passphrase, recovered key, or
secret-file hash to an AI assistant or include it in a plan or manifest.
