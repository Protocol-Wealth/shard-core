# shard-core

**Local, offline encryption + Shamir n-of-m secret sharing. No network, ever.**

Split a passphrase, seed phrase, or any secret into `n` shards where any `k` reconstruct it — and encrypt/decrypt data with a passphrase. Runs entirely offline on Linux, WSL, or macOS. Clone it, run it on an airgapped machine, distribute the shards (one to a hardware backup, one to a password manager, one to a custody vendor). Standalone and dependency-light — not tied to any product.

> **Not audited.** Provided as-is (see the license). For high-value key material, run it on an airgapped machine and cross-check reconstruction before you rely on it.

## Why an AEAD layer on top of Shamir?

Shamir's Secret Sharing is **information-theoretically secure for confidentiality** — with fewer than the threshold number of shards you learn *nothing* about the secret. You do **not** need more encryption for secrecy.

What Shamir does **not** give you is **integrity**: it can't tell a corrupted or malicious shard from a good one, so you can silently reconstruct the *wrong* secret. `shard-core` therefore encrypts the payload with an authenticated cipher (**ChaCha20-Poly1305**) and Shamir-splits only the 32-byte data key. Reconstruction is then **authenticated** — a wrong or tampered shard makes decryption fail loudly instead of returning a bad secret. This is the same reason SLIP-39 carries a digest. One AEAD layer is the right amount; don't add a third.

Cryptography is delegated to the well-reviewed [`pycryptodome`](https://pypi.org/project/pycryptodome/) library — this project only composes it. No hand-rolled crypto.

## Install (WSL / macOS / Linux)

One command from a clone — installs the `shard-core` command with SLIP-39 support:

```bash
git clone https://github.com/Protocol-Wealth/shard-core.git
cd shard-core
./install.sh
```

Then just run it:

```bash
shard-core            # guided, interactive mode — no flags to remember
```

Prefer to do it by hand? `pipx install '.[slip39]'` (or `pip install '.[slip39]'`), or run without installing via `PYTHONPATH=src python3 -m shard_core --help`. Requires Python 3.9+.

## Guided mode

Running `shard-core` with **no arguments** (or `shard-core wizard`) starts an interactive wizard that walks you through the common tasks with plain prompts — split a recovery phrase into shares (e.g. one each for you, Adam, Jason, and Coincover), recover it, and encrypt/decrypt a file. Ideal to hand to someone who doesn't use the command line. Everything below is the underlying flag-driven interface.

## Commands

| Command | What it does |
|---|---|
| `encrypt` / `decrypt` | Passphrase-based AEAD (one ciphertext blob) |
| `protect` / `recover` | Encrypt, then Shamir-split the key into `n` shards (`k` reconstruct) |
| `info` | Show a shard's header (threshold/index) without reconstructing |
| `fordefi split` / `fordefi combine` | Guided flow for a Fordefi recovery phrase |
| `slip39 split` / `slip39 combine` | SLIP-39 word-list shares (needs the `slip39` extra) |

## Quickstart

### Shard a secret (2-of-3)

```bash
printf 'my recovery phrase' > secret.txt
shard-core protect -t 2 -n 3 -i secret.txt -o shards/
#   -> shards/share-01.txt  share-02.txt  share-03.txt   (mode 0600)
```

Each shard is **self-contained** (it carries the ciphertext) and reveals nothing on its own. Put them in different places. Reconstruct with any two:

```bash
shard-core recover -o recovered.txt shards/share-01.txt shards/share-03.txt
```

Inspect a shard without reconstructing:

```bash
shard-core info shards/share-02.txt
#   mode=protect version=1 threshold=2 shares=3 index=2 ciphertext_bytes=...
```

### Encrypt with a passphrase (no sharding)

```bash
shard-core encrypt -i secret.txt -o secret.enc          # prompts for a passphrase
shard-core decrypt -i secret.enc -o secret.txt
# non-interactive: --passphrase-env VAR  or  --passphrase-file FILE
```

### Fordefi recovery-phrase mode

Shard a Fordefi dedicated-admin recovery phrase into labeled shards:

```bash
shard-core fordefi split -t 2 -n 3 --phrase-file phrase.txt -o fordefi-shards/
#   -> share-coincover.txt  share-bitwarden.txt  share-offline.txt
```

Distribute one shard per location. Recover later (offline), then feed the phrase to Fordefi's recovery-tool:

```bash
shard-core fordefi combine -o phrase.txt \
  fordefi-shards/share-coincover.txt fordefi-shards/share-offline.txt
```

### SLIP-39 word-list shares

For human-readable, checksummed shares that interoperate with any SLIP-39 tool or hardware wallet, use SLIP-39. Install the extra (Trezor reference libraries):

```bash
pip install 'shard-core[slip39]'
```

Split a 16/32-byte secret or a BIP-39 recovery phrase into SLIP-39 word shares:

```bash
shard-core slip39 split -t 2 -n 3 --bip39-file phrase.txt -o slip39-shares/
#   each share is a checksummed word list, e.g.:
#   spirit thorn academic acid coding slavery hormone famous museum zero ...

shard-core slip39 combine --bip39 slip39-shares/share-01.txt slip39-shares/share-03.txt
```

Or drive it straight from the Fordefi flow:

```bash
shard-core fordefi split   -t 2 -n 3 --phrase-file phrase.txt --slip39 -o fordefi-shards/
shard-core fordefi combine --slip39 fordefi-shards/share-coincover.txt fordefi-shards/share-offline.txt
```

**When to use which:** SLIP-39 (`slip39` / `--slip39`) is best for *seeds* — word lists you can write on steel or type into a hardware wallet, and it needs a 16/20/24/28/32-byte secret or a valid BIP-39 phrase. For an **arbitrary-length** secret (or non-BIP-39 data), use `protect` (AEAD + Shamir, base64 shards). Both give n-of-m recovery; SLIP-39 trades generality for interoperability and readable shares. An optional SLIP-39 passphrase is supported via `--passphrase-env` / `--passphrase-file`.

## Format

Each `protect` shard is a text file: a `#` comment line plus one base64 line. The base64 decodes to `magic("SHRD") | version | threshold | total | index | nonce | tag | key_share_a | key_share_b | ct_len | ciphertext`. All shards from one `protect` carry the same ciphertext; only the key-share and index differ.

## Security notes

- **Offline only.** No code path opens a socket. Run key operations on an airgapped machine.
- **Confidentiality** is information-theoretic (Shamir); **integrity** is authenticated (ChaCha20-Poly1305).
- **Passphrase KDF** is scrypt (default cost `N = 2**17`).
- Recovered secrets are written `0600`; passphrases are read via prompt / env / file, never a CLI argument.
- Python cannot reliably zero secrets in memory — treat the host as trusted for the duration of an operation.
- Keep **fewer than the threshold** number of shards in any single place. A shard is safe to store with a storage-only custodian (e.g. Coincover) because it cannot decrypt below threshold.

## Related / alternatives

- [Trezor `shamir-mnemonic`](https://pypi.org/project/shamir-mnemonic/) — the SLIP-39 reference (word-list shares); ideal when you want human-readable, checksummed *seed* shares. A future `shard-core` mode may emit SLIP-39 shares.
- [`dsprenkels/sss-cli`](https://github.com/dsprenkels/sss-cli) — constant-time generic SSS (Rust/C).
- [`age`](https://age-encryption.org) — modern file encryption (no sharding).

## License

Dual-licensed under **Apache-2.0 OR MIT-0** — use whichever you prefer. See `LICENSE` and `LICENSE-MIT-0`.
