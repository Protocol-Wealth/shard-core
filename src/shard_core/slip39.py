"""SLIP-39 (Trezor) word-list shares — optional feature.

Requires the ``slip39`` extra::

    pip install 'shard-core[slip39]'

which pulls the reference libraries ``shamir-mnemonic`` (SLIP-39) and
``mnemonic`` (BIP-39). SLIP-39 splits a 16-32 byte master secret into
checksummed word-list shares. For a standard BIP-39 recovery phrase we convert
phrase <-> entropy and SLIP-39 the entropy, so the resulting shares interoperate
with any SLIP-39 tool or hardware wallet.

SLIP-39 only applies to 16/20/24/28/32-byte secrets (or a BIP-39 phrase). For an
arbitrary-length secret, use ``protect`` (AEAD + generic Shamir) instead.
"""

from __future__ import annotations

_MISSING = (
    "SLIP-39 support needs the optional extra:\n"
    "    pip install 'shard-core[slip39]'\n"
    "(installs the Trezor shamir-mnemonic + mnemonic libraries)."
)

VALID_LENGTHS = (16, 20, 24, 28, 32)


def available() -> bool:
    try:
        import mnemonic  # noqa: F401
        import shamir_mnemonic  # noqa: F401

        return True
    except ImportError:
        return False


def _require():
    try:
        import shamir_mnemonic
        from mnemonic import Mnemonic

        return shamir_mnemonic, Mnemonic
    except ImportError as exc:  # pragma: no cover - exercised via CLI
        raise SystemExit(_MISSING) from exc


def split_master_secret(
    secret: bytes, threshold: int, shares: int, passphrase: bytes = b""
) -> list[str]:
    """Split a 16/20/24/28/32-byte master secret into SLIP-39 word shares."""
    if not (2 <= threshold <= shares):
        raise ValueError(
            "require 2 <= threshold <= shares (a single share must never reconstruct)"
        )
    if len(secret) not in VALID_LENGTHS:
        raise ValueError(
            f"SLIP-39 master secret must be one of {VALID_LENGTHS} bytes, got {len(secret)}"
        )
    sm, _ = _require()
    groups = sm.generate_mnemonics(
        group_threshold=1,
        groups=[(threshold, shares)],
        master_secret=secret,
        passphrase=passphrase,
        extendable=True,
        iteration_exponent=1,
    )
    return list(groups[0])


def combine(mnemonics: list[str], passphrase: bytes = b"") -> bytes:
    """Reconstruct the master secret / entropy from >= threshold word shares."""
    sm, _ = _require()
    return sm.combine_mnemonics(mnemonics, passphrase=passphrase)


def bip39_to_entropy(phrase: str) -> bytes:
    """BIP-39 phrase -> entropy bytes (validates the BIP-39 checksum)."""
    _, Mnemonic = _require()
    return bytes(Mnemonic("english").to_entropy(phrase.strip()))


def entropy_to_bip39(entropy: bytes) -> str:
    """Entropy bytes -> BIP-39 phrase."""
    _, Mnemonic = _require()
    return Mnemonic("english").to_mnemonic(entropy)


def split_bip39(
    phrase: str, threshold: int, shares: int, passphrase: bytes = b""
) -> list[str]:
    """Split a BIP-39 recovery phrase into SLIP-39 word shares (via its entropy)."""
    return split_master_secret(bip39_to_entropy(phrase), threshold, shares, passphrase)
