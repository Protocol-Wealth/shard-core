# Generic custody ceremony

This guide is vendor-neutral. For Fordefi-specific method selection and
recovery, continue with
[docs/FORDEFI-DISASTER-RECOVERY.md](docs/FORDEFI-DISASTER-RECOVERY.md).

## 1. Select the protection model

Choose one model before handling a secret:

| Model | Use when | Recovery dependency |
|---|---|---|
| SHEN passphrase encryption | One holder stores ciphertext | SHEN file plus separate wrapping credential |
| SHRD threshold protection | Multiple holders must cooperate | Any valid threshold of SHRD files |
| SLIP-39 | Human-readable shares are required for independently confirmed compatible material | Valid SLIP-39 threshold plus optional passphrase |

Do not layer mechanisms without stating which risk the added layer addresses.
Every additional credential or holder can also create a new availability risk.

## 2. Define the ceremony record

Record only non-secret operational facts:

- software version and verified distribution hashes;
- ceremony identifier, date, threshold, declared share count, and holder labels;
- approved output filenames and artifact SHA-256 values;
- successful `verify-set` result and tested combinations;
- transfer receipts and later retrieval-test results.

Never record or hash the plaintext, phrase, passphrase, wrapping credential,
recovered key, or other secret file. A hash of low-entropy phrase material can
become an offline guessing target.

## 3. Prepare the controlled host

- Use a trusted offline host and controlled private working directory.
- Disable recording, screen sharing, clipboard synchronization, and shell
  tracing.
- Install through the verified bundle path in [OFFLINE_BUILD.md](OFFLINE_BUILD.md)
  when required by the custody model.
- Confirm the host clock, expected software version, available storage, and
  approved output paths without displaying secret contents.
- Refuse unexpected existing files, symlinks, or uncontrolled parent paths.

## 4. Rehearse with synthetic material

Run the complete creation, distribution simulation, recovery, and cleanup flow
with synthetic data. Confirm every intended threshold subset works and that
below-threshold, corrupt, conflicting, and mixed-set cases fail as expected.

Do not substitute a successful unit-test run for this operator rehearsal.

## 5. Create and verify artifacts

For a 2-of-3 SHRD example:

```bash
shard-core protect \
  --threshold 2 \
  --shares 3 \
  --labels primary,custodian-a,custodian-b \
  --input /controlled/input/secret.bin \
  --out-dir /controlled/output/shares \
  --manifest /controlled/output/shares/manifest.json

shard-core verify-set --require-complete \
  /controlled/output/shares/share-primary.txt \
  /controlled/output/shares/share-custodian-a.txt \
  /controlled/output/shares/share-custodian-b.txt
```

The split command self-tests generated combinations before writing. The
separate `verify-set --require-complete` ceremony step confirms the files that
will actually be distributed.

## 6. Distribute and acknowledge

- Transfer each approved artifact through its assigned path.
- Compare its artifact SHA-256 at deposit and receipt.
- Confirm the custodian does not alter bytes, line endings, filenames, or
  archive structure.
- Confirm release authentication, authorization, expected timing, and contact
  escalation from the actual custody agreement.
- Do not send a SHEN artifact and its wrapping credential through the same path
  unless concentration is an explicit design decision.

A successful hash comparison proves byte equality, not identity, custody,
authority, or future availability.

## 7. Conduct a retrieval drill

Retrieve the required artifacts through the real release process. Work in a
new private offline directory and recover only synthetic material during
routine drills.

```text
retrieved artifacts
    -> verify expected hashes and set metadata
    -> recover to an explicit file
    -> compare with the synthetic expected result
    -> record PASS without recording the secret
```

For SHRD:

```bash
shard-core recover \
  --output /controlled/recovery/recovered.bin \
  /controlled/recovery/share-primary.txt \
  /controlled/recovery/share-custodian-a.txt
```

For SHEN:

```bash
shard-core decrypt \
  --input /controlled/recovery/secret.shen \
  --output /controlled/recovery/recovered.bin
```

Never use `--stdout` during a production recovery unless terminal disclosure
is explicitly accepted and controlled.

## 8. Close the workspace

- Confirm required custody copies and non-secret evidence are complete.
- Remove temporary plaintext according to the storage technology and approved
  media-handling procedure.
- Remember that ordinary deletion is not guaranteed secure erasure on SSD,
  copy-on-write, journaling, snapshotting, or virtualized storage.
- End the offline session and return media and devices to their approved state.

## AI-assisted walkthrough

An AI assistant must follow [AGENTS.md](AGENTS.md). It should present one step
at a time, never request secret material, and accept only non-secret statuses
or approved hashes of ciphertext, tools, archives, and release artifacts.
