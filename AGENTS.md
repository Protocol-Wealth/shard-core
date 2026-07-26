# shard-core agent instructions

These instructions apply to the entire repository. They are written for AI
agents helping a human operate, review, or modify `shard-core`.

## Canonical documentation

Read these in order:

1. `README.md` for the public overview and stable command examples.
2. `THREAT_MODEL.md` for assets, adversaries, assumptions, and non-goals.
3. `SECURITY.md` for disclosure, audit, and version-support policy.
4. `CEREMONY.md` for the generic human-operated custody workflow.
5. `docs/CUSTODY-PATTERNS.md` for provider-native, external-custodian,
   peer-to-peer, and multi-party patterns.
6. `docs/FORDEFI-DISASTER-RECOVERY.md` for the Fordefi workflow.
7. `OFFLINE_BUILD.md` for the verified offline build boundary.
8. `RELEASING.md` for the stable release and Trusted Publishing procedure.
9. `release/VERIFY.md` when handling a generated offline bundle.
10. Current vendor documentation linked from the applicable runbook.

Do not rely on an old chat transcript when repository or vendor documentation
is available. `AGENTS.md` is the AI guidance entry point; a duplicate
`AGENTS.txt` or `LLMS.txt` is unnecessary.

## Human walkthrough rules

When guiding an operator:

- Start by identifying the protection or vendor backup method. For Fordefi,
  ask whether the operator selected Public Key Upload, Recovery Phrases, or a
  managed provider/hardware flow. Do not assume Recovery Phrases and do not
  apply `shard-core` to a public-key backup without a documented reason.
- When Station70 is mentioned, identify whether the operator means its native
  Fordefi/Bunker integration, Bunker Custom Upload, SWAT, or an independently
  agreed role holding SHEN or one SHRD artifact. These are different recovery
  paths and must not be combined implicitly.
- Work one numbered step at a time and wait for the operator to confirm only
  non-secret results such as `PASS`, filenames, or approved ciphertext, tool,
  archive, and release-artifact SHA-256 values.
- Never request or share a hash of a phrase, plaintext, wrapping credential,
  recovered private key, or any other secret file.
- Never ask the operator to paste a recovery phrase, shard, passphrase,
  wrapping credential, recovered private key, or backup contents into chat.
- Tell the operator to enter phrases and passphrases only into local hidden
  prompts on the controlled offline host.
- Use synthetic phrases and credentials in examples and automated tests.
- Never place secrets in command-line arguments, environment variables,
  manifests, logs, screenshots, issue bodies, or pull-request comments.
- Prefer `--output FILE`; use `--stdout` only when the human explicitly accepts
  terminal disclosure.
- Stop if an output path already exists, is a symlink, or is outside the
  controlled workspace. Do not suggest bypassing safe-write checks.
- Do not invoke Fordefi's recovery tool from `shard-core` or automate the final
  private-key recovery. Guide the human through Fordefi's current official
  instructions as a separate offline step.
- Do not assume a Fordefi phrase is BIP-39 and do not silently select SLIP-39.
- Do not invent Qapture, Nemean, CoinCover, Station70, or other custodian
  requirements. Treat their accepted file format, custody role, authentication
  factors, quorum, and key-release procedure as contractual inputs the human
  must confirm against current official documentation.

## Cryptographic and compatibility boundaries

- Do not change SHRD v1/v2 or SHEN v1/v2 wire bytes without a separate design
  review and compatibility plan.
- Keep ChaCha20-Poly1305, scrypt, random data-key generation, and the existing
  AEAD plus Shamir composition intact unless a separate cryptographic review
  explicitly approves a change.
- Never add a plaintext phrase fingerprint, phrase hash, passphrase hint, or
  complete-secret metadata to a manifest or evidence record.
- Preserve v1 read compatibility and v2 associated-data authentication.
- Recovery must remain fail-closed for ambiguity and conflicting duplicates.

## Repository work

- Use Python 3.11 for Stage 6 builder-boundary tests.
- Run normal and optimized tests for security-sensitive changes:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -O -m unittest discover -s tests -v
```

- Treat hosted CI as test evidence, not offline-bundle provenance.
- The canonical bundle builder is `scripts/build-offline-bundle.py`; the
  host-native shell builder is intentionally disabled.
- Do not add networking, telemetry, update checks, cloud APIs, or vendor APIs.
- Do not claim that tests or an AI review constitute a security audit.
- Do not publish, tag, or release unless the human explicitly requests it.

## Safe walkthrough opening

An AI agent should start an operator session with:

> I will guide you one step at a time. Do not paste any phrase, passphrase,
> shard, wrapping credential, snapshot contents, or recovered key into chat.
> Enter secrets only at local hidden prompts. Reply only with non-secret status
> or approved hashes of ciphertext, tools, archives, and release artifacts.
