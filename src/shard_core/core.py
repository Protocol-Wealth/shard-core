"""shard-core core: local AEAD encryption + Shamir n-of-m sharding.

No networking anywhere in this module. Cryptography is delegated to the
well-reviewed ``pycryptodome`` library — this module only composes it:

* AEAD: ChaCha20-Poly1305 (authenticated; tamper is detected on decrypt).
* Passphrase KDF: scrypt.
* Secret sharing: Shamir over GF(2^128) (``Crypto.Protocol.SecretSharing``),
  applied to the 32-byte data key as two 16-byte halves.

Two top-level flows:

* ``encrypt`` / ``decrypt`` — passphrase-based AEAD, one ciphertext blob.
* ``protect`` / ``recover`` — encrypt under a random data key, then split that
  key into ``n`` shards (any ``k`` reconstruct). Each shard is self-contained
  (it carries the ciphertext), so shards can be stored in different places.
"""

from __future__ import annotations

import base64
import struct

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

MAGIC_PROTECT = b"SHRD"
MAGIC_ENCRYPT = b"SHEN"
FORMAT_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)
KDF_SCRYPT = 1

# scrypt cost defaults (N = 2**17 ~= 128 MiB): strong for interactive use.
DEFAULT_SCRYPT_N_LOG2 = 17
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


# --------------------------------------------------------------------------- #
# AEAD
# --------------------------------------------------------------------------- #
def _aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, tag, ct


def _aead_decrypt(key: bytes, nonce: bytes, tag: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    if aad:
        cipher.update(aad)
    # Raises ValueError if the key is wrong, the header was edited, or the
    # ciphertext was tampered with.
    return cipher.decrypt_and_verify(ct, tag)


# --------------------------------------------------------------------------- #
# Associated data (format v2): the header is authenticated, not just carried
# --------------------------------------------------------------------------- #
def _protect_aad(version: int, threshold: int, shares: int) -> bytes:
    """AEAD associated data for a ``protect`` shard header.

    Deliberately excludes the share index: every shard of one ``protect`` run
    carries the same ciphertext and tag, so the AAD must be identical across
    them. Binding threshold/shares stops an edited header from turning a
    tampered shard set into a misleading "need >= k shards" error.
    """
    return MAGIC_PROTECT + bytes([version, threshold, shares])


def _encrypt_aad(version: int, kdf_id: int, n_log2: int, r: int, p: int, salt: bytes) -> bytes:
    """AEAD associated data for an ``encrypt`` blob header (KDF params + salt)."""
    return MAGIC_ENCRYPT + bytes([version, kdf_id, n_log2, r, p]) + salt


# --------------------------------------------------------------------------- #
# Shamir over a 32-byte key (two 16-byte halves, paired by share index)
# --------------------------------------------------------------------------- #
def _split_key(k: int, n: int, key32: bytes) -> list[tuple[int, bytes, bytes]]:
    a = Shamir.split(k, n, key32[:16])
    b = Shamir.split(k, n, key32[16:])
    out: list[tuple[int, bytes, bytes]] = []
    for (ia, sa), (ib, sb) in zip(a, b):
        assert ia == ib  # both splits enumerate indices 1..n in the same order
        out.append((ia, sa, sb))
    return out


def _combine_key(parts: list[tuple[int, bytes, bytes]]) -> bytes:
    half_a = [(idx, sa) for (idx, sa, _sb) in parts]
    half_b = [(idx, sb) for (idx, _sa, sb) in parts]
    return Shamir.combine(half_a) + Shamir.combine(half_b)


# --------------------------------------------------------------------------- #
# Passphrase KDF
# --------------------------------------------------------------------------- #
def _derive(passphrase: bytes, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
    return scrypt(passphrase, salt, key_len=32, N=1 << n_log2, r=r, p=p)


# --------------------------------------------------------------------------- #
# protect / recover  (encrypt + shard the key)
# --------------------------------------------------------------------------- #
def protect(secret: bytes, threshold: int, shares: int) -> list[str]:
    """Encrypt ``secret`` and split the key into ``shares`` shards (``threshold``
    of which reconstruct it). Returns a list of base64 shard strings."""
    if not (2 <= threshold <= shares <= 255):
        raise ValueError(
            "require 2 <= threshold <= shares <= 255 "
            "(a single share must never reconstruct the secret)"
        )
    key = get_random_bytes(32)
    nonce, tag, ct = _aead_encrypt(key, secret, _protect_aad(FORMAT_VERSION, threshold, shares))
    out = []
    for idx, sa, sb in _split_key(threshold, shares, key):
        header = (
            MAGIC_PROTECT
            + bytes([FORMAT_VERSION, threshold, shares, idx])
            + nonce
            + tag
            + sa
            + sb
            + struct.pack(">I", len(ct))
        )
        out.append(base64.b64encode(header + ct).decode("ascii"))
    return out


def parse_shard(shard_b64: str) -> dict:
    """Parse a protect shard's header without reconstructing the secret."""
    blob = base64.b64decode(shard_b64)
    if blob[:4] != MAGIC_PROTECT:
        raise ValueError("not a shard-core protect shard")
    ver, k, n, idx = blob[4], blob[5], blob[6], blob[7]
    off = 8
    nonce = blob[off : off + 12]; off += 12
    tag = blob[off : off + 16]; off += 16
    sa = blob[off : off + 16]; off += 16
    sb = blob[off : off + 16]; off += 16
    (ctlen,) = struct.unpack(">I", blob[off : off + 4]); off += 4
    ct = blob[off : off + ctlen]
    return {
        "version": ver, "threshold": k, "shares": n, "index": idx,
        "nonce": nonce, "tag": tag, "share_a": sa, "share_b": sb, "ciphertext": ct,
    }


def recover(shard_b64_list: list[str]) -> bytes:
    """Reconstruct the secret from >= threshold shards."""
    parsed = [parse_shard(s) for s in shard_b64_list]
    if not parsed:
        raise ValueError("no shards provided")
    threshold = parsed[0]["threshold"]
    # Deduplicate by share index; all shards carry the same ciphertext.
    by_index: dict[int, dict] = {}
    for p in parsed:
        by_index[p["index"]] = p
    if len(by_index) < threshold:
        raise ValueError(
            f"need >= {threshold} distinct shards, got {len(by_index)}"
        )
    chosen = list(by_index.values())[:threshold]
    key = _combine_key([(p["index"], p["share_a"], p["share_b"]) for p in chosen])
    ref = parsed[0]
    return _aead_decrypt(
        key, ref["nonce"], ref["tag"], ref["ciphertext"],
        _shard_aad(ref["version"], ref["threshold"], ref["shares"]),
    )


def _shard_aad(version: int, threshold: int, shares: int) -> bytes:
    """AAD for a parsed shard: v1 headers were unauthenticated, v2 are bound."""
    if version == 1:
        return b""
    if version == 2:
        return _protect_aad(version, threshold, shares)
    raise ValueError(f"unsupported shard-core format version {version}")


# --------------------------------------------------------------------------- #
# encrypt / decrypt  (passphrase, no sharding)
# --------------------------------------------------------------------------- #
def encrypt(
    secret: bytes,
    passphrase: bytes,
    n_log2: int = DEFAULT_SCRYPT_N_LOG2,
    r: int = DEFAULT_SCRYPT_R,
    p: int = DEFAULT_SCRYPT_P,
) -> str:
    salt = get_random_bytes(16)
    key = _derive(passphrase, salt, n_log2, r, p)
    aad = _encrypt_aad(FORMAT_VERSION, KDF_SCRYPT, n_log2, r, p, salt)
    nonce, tag, ct = _aead_encrypt(key, secret, aad)
    header = (
        MAGIC_ENCRYPT + bytes([FORMAT_VERSION, KDF_SCRYPT, n_log2, r, p]) + salt + nonce + tag
    )
    return base64.b64encode(header + ct).decode("ascii")


def normalize_labels(labels, count: int) -> list[str]:
    """Return exactly ``count`` share labels, robustly (never fails):

    - no labels        -> numbered ``01``..``0N``
    - a single label   -> ``label-1``..``label-N``
    - fewer than count -> keep the given ones, pad the rest with numbers
    - more than count  -> truncate to ``count``
    """
    cleaned = [str(x).strip() for x in (labels or []) if str(x).strip()]
    if not cleaned:
        return [f"{i:02d}" for i in range(1, count + 1)]
    if len(cleaned) == 1 and count > 1:
        return [f"{cleaned[0]}-{i}" for i in range(1, count + 1)]
    if len(cleaned) >= count:
        return cleaned[:count]
    return cleaned + [f"{i:02d}" for i in range(len(cleaned) + 1, count + 1)]


def decrypt(blob_b64: str, passphrase: bytes) -> bytes:
    blob = base64.b64decode(blob_b64)
    if blob[:4] != MAGIC_ENCRYPT:
        raise ValueError("not a shard-core encrypt blob")
    ver, kdf, n_log2, r, p = blob[4], blob[5], blob[6], blob[7], blob[8]
    if ver not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported shard-core format version {ver}")
    if kdf != KDF_SCRYPT:
        raise ValueError(f"unsupported KDF id {kdf}")
    off = 9
    salt = blob[off : off + 16]; off += 16
    nonce = blob[off : off + 12]; off += 12
    tag = blob[off : off + 16]; off += 16
    ct = blob[off:]
    # v1 headers were carried but unauthenticated; v2 binds them as AAD.
    aad = b"" if ver == 1 else _encrypt_aad(ver, kdf, n_log2, r, p, salt)
    key = _derive(passphrase, salt, n_log2, r, p)
    return _aead_decrypt(key, nonce, tag, ct, aad)
