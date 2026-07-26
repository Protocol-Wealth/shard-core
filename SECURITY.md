# Security policy

## Report a vulnerability

Use GitHub's private vulnerability-reporting form:

https://github.com/Protocol-Wealth/shard-core/security/advisories/new

Do not disclose an unpatched vulnerability in a public issue, discussion,
pull request, or chat transcript. Include affected versions, impact,
reproduction steps using synthetic data, and any proposed mitigation. Never
include a real recovery phrase, shard, passphrase, wrapping credential,
Fordefi snapshot, or recovered private key.

For ordinary bugs that do not expose sensitive material or weaken a security
boundary, use the public issue tracker.

## Supported versions

Security fixes are applied to the latest `main` branch and the current `0.3.x`
stable line. Older commits, copied scripts, and previously generated offline
bundles are not independently maintained.

| Version | Security fixes |
|---|---|
| latest `main` / current `0.3.x` stable release | Supported |
| `0.2.x` | Not supported |
| older commits and bundles | Not supported |
| `0.1.x` | Not supported |

An offline bundle is tied to its recorded source commit and inputs. Rebuild it
after a relevant security fix rather than replacing individual files inside it.

## Audit status

`shard-core` has not received an independent professional security audit.
Automated tests, optimized-mode tests, code review, and adversarial AI review
are engineering evidence, not an audit or a guarantee of fitness for custody.

The project composes PyCryptodome primitives rather than implementing its own
cipher. That reduces implementation surface but does not remove risks in the
composition, dependency chain, host, or operating procedure.

## Secure-use policy

- Read [THREAT_MODEL.md](THREAT_MODEL.md) before selecting a custody design.
- Rehearse [CEREMONY.md](CEREMONY.md) with synthetic material.
- Use [OFFLINE_BUILD.md](OFFLINE_BUILD.md) when package-index trust is outside
  the accepted boundary.
- Verify the complete threshold set before distribution.
- Keep encrypted artifacts and their wrapping credentials on separately
  approved custody paths when separation is part of the design.
- Treat Fordefi's recovery-tool output as unencrypted private-key material.
- Do not treat an artifact hash as proof of custody or authorization.
