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
import binascii
import hashlib
import re
import struct
from dataclasses import dataclass
from itertools import combinations
from math import comb
from typing import Optional, Sequence, Tuple

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

MAGIC_PROTECT = b"SHRD"
MAGIC_ENCRYPT = b"SHEN"
FORMAT_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)
KDF_SCRYPT = 1

# Fixed-size prefix of a protect shard:
#   magic(4) | version+threshold+shares+index(4) | nonce(12) | tag(16)
#   | share_a(16) | share_b(16) | ct_len(4)
HEADER_LEN = 4 + 4 + 12 + 16 + 16 + 16 + 4  # 72
# Fixed-size prefix of an encrypt blob:
#   magic(4) | version+kdf+n_log2+r+p(5) | salt(16) | nonce(12) | tag(16)
ENC_HEADER_LEN = 4 + 5 + 16 + 12 + 16  # 53

# scrypt cost defaults (N = 2**17 ~= 128 MiB): strong for interactive use.
DEFAULT_SCRYPT_N_LOG2 = 17
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

# Upper bound on the scrypt working set. The cost parameters of an encrypt
# blob are attacker-controlled header bytes, and scrypt allocates
# 128 * N * r bytes: an unbounded n_log2/r would let a hostile blob turn
# `decrypt` into an out-of-memory kill instead of a clean ValueError.
# 8 GiB is far above anything reachable through the CLI, whose only cost knob
# is --scrypt-n (r is fixed at 8, so the default is 128 MiB and even
# --scrypt-n 23 stays inside the bound).
MAX_SCRYPT_N_LOG2 = 31
MAX_SCRYPT_MEMORY = 8 * (1 << 30)  # 8 GiB
MAX_RECOVERY_COMBINATIONS = 10_000


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
    """Split both halves of ``key32`` and pair them by share index.

    Pairing is explicit rather than positional: an assert would be stripped
    under ``python -O``, and mispaired halves would silently reconstruct the
    wrong key.
    """
    a = dict(Shamir.split(k, n, key32[:16]))
    b = dict(Shamir.split(k, n, key32[16:]))
    if a.keys() != b.keys():
        raise RuntimeError("internal error: Shamir half-share index mismatch")
    return [(idx, a[idx], b[idx]) for idx in sorted(a)]


def _combine_key(parts: list[tuple[int, bytes, bytes]]) -> bytes:
    half_a = [(idx, sa) for (idx, sa, _sb) in parts]
    half_b = [(idx, sb) for (idx, _sa, sb) in parts]
    return Shamir.combine(half_a) + Shamir.combine(half_b)


# --------------------------------------------------------------------------- #
# Passphrase KDF
# --------------------------------------------------------------------------- #
def _check_scrypt_params(n_log2: int, r: int, p: int) -> None:
    """Reject cost parameters before they reach scrypt.

    Applied on both sides so the two stay symmetric: nothing that ``encrypt``
    accepts can be rejected by ``decrypt``, and vice versa.
    """
    if not (1 <= n_log2 <= MAX_SCRYPT_N_LOG2):
        raise ValueError(
            f"invalid scrypt cost: n_log2 must be 1..{MAX_SCRYPT_N_LOG2}, got {n_log2}"
        )
    if r < 1 or p < 1:
        raise ValueError(f"invalid scrypt cost: r and p must be >= 1, got r={r} p={p}")
    memory = 128 * (1 << n_log2) * r
    if memory > MAX_SCRYPT_MEMORY:
        raise ValueError(
            f"scrypt cost too large: n_log2={n_log2} r={r} would need "
            f"{memory >> 30} GiB (limit {MAX_SCRYPT_MEMORY >> 30} GiB)"
        )


def _derive(passphrase: bytes, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
    _check_scrypt_params(n_log2, r, p)
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
    """Parse a protect shard's header without reconstructing the secret.

    Every malformed input is reported as ``ValueError``; no ``binascii.Error``,
    ``struct.error`` or ``IndexError`` reaches the caller.
    """
    try:
        blob = base64.b64decode(shard_b64, validate=True)
    except binascii.Error as exc:
        raise ValueError("shard is not valid base64") from exc
    if len(blob) < HEADER_LEN:
        raise ValueError(
            f"shard truncated: expected at least {HEADER_LEN} bytes, got {len(blob)}"
        )
    if blob[:4] != MAGIC_PROTECT:
        raise ValueError("not a shard-core protect shard")
    ver, k, n, idx = blob[4], blob[5], blob[6], blob[7]
    if ver not in SUPPORTED_VERSIONS:
        raise ValueError(f"unsupported shard-core format version {ver}")
    if not (2 <= k <= n <= 255):
        raise ValueError(
            f"shard header is invalid: require 2 <= threshold <= shares <= 255, "
            f"got threshold={k} shares={n}"
        )
    if not (1 <= idx <= n):
        raise ValueError(
            f"shard header is invalid: index {idx} is out of range for {n} shares"
        )
    off = 8
    nonce = blob[off : off + 12]; off += 12
    tag = blob[off : off + 16]; off += 16
    sa = blob[off : off + 16]; off += 16
    sb = blob[off : off + 16]; off += 16
    (ctlen,) = struct.unpack(">I", blob[off : off + 4]); off += 4
    present = len(blob) - HEADER_LEN
    if present < ctlen:
        raise ValueError(
            f"shard truncated: header claims {ctlen} ciphertext bytes, {present} present"
        )
    if present > ctlen:
        raise ValueError("shard has trailing garbage")
    ct = blob[off:]
    return {
        "version": ver, "threshold": k, "shares": n, "index": idx,
        "nonce": nonce, "tag": tag, "share_a": sa, "share_b": sb, "ciphertext": ct,
    }


# Fields every shard of one protect run must agree on. The index is the only
# thing that legitimately varies.
_SHARED_FIELDS = ("version", "threshold", "shares", "nonce", "tag", "ciphertext")


class RecoveryError(ValueError):
    """No unambiguous authenticated recovery result could be produced."""


class RecoveryAmbiguityError(RecoveryError):
    """More than one independent shard set authenticated."""


class RecoveryCombinationLimitError(RecoveryError):
    """Recovery was refused before cryptographic work due to its search size."""


class _NoAuthenticatingCombination(RecoveryError):
    """Internal signal: a candidate group had no authenticating subset."""


@dataclass(frozen=True)
class RecoveryMetadata:
    selected_set_id: str
    threshold: int
    declared_total: int
    supplied_indices: Tuple[int, ...]
    duplicate_indices: Tuple[int, ...]
    authenticating_combinations: Tuple[Tuple[int, ...], ...]
    failed_combinations: Tuple[Tuple[int, ...], ...]
    suspect_indices: Tuple[int, ...]
    rejected_set_ids: Tuple[str, ...]


@dataclass(frozen=True)
class VerificationMetadata:
    set_id: str
    threshold: int
    declared_total: int
    supplied_indices: Tuple[int, ...]
    successful_combinations: Tuple[Tuple[int, ...], ...]
    failed_combinations: Tuple[Tuple[int, ...], ...]

    @property
    def ok(self) -> bool:
        return not self.failed_combinations


def _shared_key(parsed: dict) -> tuple:
    return tuple(parsed[field] for field in _SHARED_FIELDS)


def protect_set_id(parsed: dict) -> str:
    """Derive a stable, non-secret identifier from a protect run's shared fields."""
    ciphertext = parsed["ciphertext"]
    digest = hashlib.sha256()
    digest.update(b"shard-core/protect-set-id/v1\x00")
    digest.update(
        bytes([
            parsed["version"],
            parsed["threshold"],
            parsed["shares"],
        ])
    )
    digest.update(parsed["nonce"])
    digest.update(parsed["tag"])
    digest.update(struct.pack(">I", len(ciphertext)))
    digest.update(ciphertext)
    return digest.hexdigest()


def _dedupe_group(
    group: list[dict],
) -> tuple[dict[int, dict], Tuple[int, ...]]:
    by_index: dict[int, dict] = {}
    duplicates: set[int] = set()

    for shard in group:
        index = shard["index"]
        previous = by_index.get(index)
        if previous is None:
            by_index[index] = shard
            continue

        same_share = (
            previous["share_a"] == shard["share_a"]
            and previous["share_b"] == shard["share_b"]
        )
        if not same_share:
            raise RecoveryError(
                f"conflicting payloads for share index {index}"
            )
        duplicates.add(index)

    return by_index, tuple(sorted(duplicates))


def _recover_group(
    reference: dict,
    by_index: dict[int, dict],
    *,
    max_combinations: int,
) -> tuple[
    bytes,
    Tuple[Tuple[int, ...], ...],
    Tuple[Tuple[int, ...], ...],
]:
    threshold = reference["threshold"]
    indices = tuple(sorted(by_index))
    combination_count = comb(len(indices), threshold)
    if combination_count > max_combinations:
        raise RecoveryCombinationLimitError(
            f"recovery would require {combination_count} combinations; "
            f"limit is {max_combinations}"
        )

    recovered: Optional[bytes] = None
    successful: list[Tuple[int, ...]] = []
    failed: list[Tuple[int, ...]] = []

    for selected_indices in combinations(indices, threshold):
        selected = [by_index[index] for index in selected_indices]
        key = _combine_key([
            (
                shard["index"],
                shard["share_a"],
                shard["share_b"],
            )
            for shard in selected
        ])
        try:
            candidate = _aead_decrypt(
                key,
                reference["nonce"],
                reference["tag"],
                reference["ciphertext"],
                _shard_aad(
                    reference["version"],
                    reference["threshold"],
                    reference["shares"],
                ),
            )
        except ValueError:
            failed.append(selected_indices)
            continue

        if recovered is None:
            recovered = candidate
        elif recovered != candidate:
            raise RecoveryAmbiguityError(
                "ambiguous authenticated plaintext across shard combinations"
            )
        successful.append(selected_indices)

    if recovered is None:
        raise _NoAuthenticatingCombination(
            "no threshold-sized combination authenticated"
        )

    return recovered, tuple(successful), tuple(failed)


def _raise_no_candidate(
    parsed: list[dict],
    groups: dict[tuple, list[dict]],
    prepared: dict[str, tuple[dict[int, dict], Tuple[int, ...]]],
) -> None:
    if len(groups) > 1:
        reference = parsed[0]
        for position, shard in enumerate(parsed[1:], start=2):
            for field in _SHARED_FIELDS:
                if shard[field] != reference[field]:
                    raise RecoveryError(
                        f"shard {position} (index={shard['index']}) does not "
                        f"match shard 1: differing {field} — shards are from "
                        "different protect runs"
                    )

    reference = parsed[0]
    set_id = protect_set_id(reference)
    by_index, duplicates = prepared[set_id]
    detail = (
        f" (duplicate indices supplied: "
        f"{', '.join(str(index) for index in duplicates)})"
        if duplicates
        else ""
    )
    raise RecoveryError(
        f"need >= {reference['threshold']} distinct shards, "
        f"got {len(by_index)}{detail}"
    )


def recover_with_report(
    shard_b64_list: Sequence[str],
    *,
    max_combinations: int = MAX_RECOVERY_COMBINATIONS,
) -> tuple[bytes, RecoveryMetadata]:
    """Recover from one unambiguous authenticating shard set.

    Candidate sets are grouped by their shared authenticated fields. Every
    threshold-sized subset is tried within a bounded, invocation-wide search
    budget. Structurally invalid input and conflicting duplicate indices are
    fatal; unrelated or damaged redundant groups can be rejected while one
    authenticating set succeeds.
    """
    if not shard_b64_list:
        raise RecoveryError("no shards provided")
    if max_combinations < 1:
        raise RecoveryCombinationLimitError(
            f"max_combinations must be >= 1, got {max_combinations}"
        )

    parsed = [parse_shard(s) for s in shard_b64_list]
    groups: dict[tuple, list[dict]] = {}
    for shard in parsed:
        groups.setdefault(_shared_key(shard), []).append(shard)

    prepared: dict[str, tuple[dict[int, dict], Tuple[int, ...]]] = {}
    candidates: list[
        tuple[str, dict, dict[int, dict], Tuple[int, ...], int]
    ] = []
    rejected_set_ids: set[str] = set()
    total_combinations = 0

    # Dedupe every group before attempting recovery. A conflicting duplicate
    # is structural input ambiguity and must never be hidden by another group.
    for group in groups.values():
        reference = group[0]
        set_id = protect_set_id(reference)
        by_index, duplicates = _dedupe_group(group)
        prepared[set_id] = (by_index, duplicates)
        threshold = reference["threshold"]
        if len(by_index) < threshold:
            rejected_set_ids.add(set_id)
            continue

        count = comb(len(by_index), threshold)
        total_combinations += count
        candidates.append((set_id, reference, by_index, duplicates, count))

    if not candidates:
        _raise_no_candidate(parsed, groups, prepared)

    # Enforce one aggregate budget before any Shamir combination or AEAD work.
    if total_combinations > max_combinations:
        raise RecoveryCombinationLimitError(
            f"recovery would require {total_combinations} combinations; "
            f"limit is {max_combinations}"
        )

    successful_sets: list[
        tuple[
            str,
            bytes,
            dict,
            dict[int, dict],
            Tuple[int, ...],
            Tuple[Tuple[int, ...], ...],
            Tuple[Tuple[int, ...], ...],
        ]
    ] = []
    for set_id, reference, by_index, duplicates, _count in candidates:
        try:
            recovered, successful, failed = _recover_group(
                reference,
                by_index,
                max_combinations=max_combinations,
            )
        except _NoAuthenticatingCombination:
            rejected_set_ids.add(set_id)
            continue
        successful_sets.append(
            (
                set_id,
                recovered,
                reference,
                by_index,
                duplicates,
                successful,
                failed,
            )
        )

    if not successful_sets:
        raise RecoveryError("no candidate shard set authenticated")
    if len(successful_sets) > 1:
        set_ids = ", ".join(sorted(item[0] for item in successful_sets))
        raise RecoveryAmbiguityError(
            f"multiple independent shard sets authenticated: {set_ids}"
        )

    (
        selected_set_id,
        recovered,
        reference,
        by_index,
        duplicates,
        successful,
        failed,
    ) = successful_sets[0]

    selected_indices = set(by_index)
    successful_indices = {
        index
        for selected in successful
        for index in selected
    }
    outside_indices = {
        shard["index"]
        for group in groups.values()
        if protect_set_id(group[0]) != selected_set_id
        for shard in group
    }
    suspect_indices = (
        (selected_indices - successful_indices)
        | (outside_indices - selected_indices)
    )
    rejected_set_ids.discard(selected_set_id)

    metadata = RecoveryMetadata(
        selected_set_id=selected_set_id,
        threshold=reference["threshold"],
        declared_total=reference["shares"],
        supplied_indices=tuple(sorted({shard["index"] for shard in parsed})),
        duplicate_indices=duplicates,
        authenticating_combinations=successful,
        failed_combinations=failed,
        suspect_indices=tuple(sorted(suspect_indices)),
        rejected_set_ids=tuple(sorted(rejected_set_ids)),
    )
    return recovered, metadata


def recover(shard_b64_list: list[str]) -> bytes:
    """Compatibility wrapper returning only the recovered plaintext."""
    recovered, _metadata = recover_with_report(shard_b64_list)
    return recovered


def verify_complete_set(
    shard_b64_list: Sequence[str],
    *,
    max_combinations: int = MAX_RECOVERY_COMBINATIONS,
) -> VerificationMetadata:
    """Authenticate every threshold-sized combination in one supplied set."""
    if not shard_b64_list:
        raise RecoveryError("no shards provided")
    if max_combinations < 1:
        raise RecoveryCombinationLimitError(
            f"max_combinations must be >= 1, got {max_combinations}"
        )

    parsed = [parse_shard(shard) for shard in shard_b64_list]
    groups: dict[tuple, list[dict]] = {}
    for shard in parsed:
        groups.setdefault(_shared_key(shard), []).append(shard)
    if len(groups) != 1:
        raise RecoveryError(
            "complete-set verification requires exactly one protect set"
        )

    group = next(iter(groups.values()))
    reference = group[0]
    by_index, _duplicates = _dedupe_group(group)
    threshold = reference["threshold"]
    indices = tuple(sorted(by_index))
    if len(indices) < threshold:
        raise RecoveryError(
            f"need >= {threshold} distinct shards, got {len(indices)}"
        )

    combination_count = comb(len(indices), threshold)
    if combination_count > max_combinations:
        raise RecoveryCombinationLimitError(
            f"verification would require {combination_count} combinations; "
            f"limit is {max_combinations}"
        )

    recovered: Optional[bytes] = None
    successful: list[Tuple[int, ...]] = []
    failed: list[Tuple[int, ...]] = []
    for selected_indices in combinations(indices, threshold):
        selected = [by_index[index] for index in selected_indices]
        key = _combine_key([
            (
                shard["index"],
                shard["share_a"],
                shard["share_b"],
            )
            for shard in selected
        ])
        try:
            candidate = _aead_decrypt(
                key,
                reference["nonce"],
                reference["tag"],
                reference["ciphertext"],
                _shard_aad(
                    reference["version"],
                    reference["threshold"],
                    reference["shares"],
                ),
            )
        except ValueError:
            failed.append(selected_indices)
            continue

        if recovered is None:
            recovered = candidate
        elif recovered != candidate:
            raise RecoveryAmbiguityError(
                "ambiguous authenticated plaintext across shard combinations"
            )
        successful.append(selected_indices)

    return VerificationMetadata(
        set_id=protect_set_id(reference),
        threshold=threshold,
        declared_total=reference["shares"],
        supplied_indices=indices,
        successful_combinations=tuple(successful),
        failed_combinations=tuple(failed),
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


_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
MAX_LABEL_LEN = 64


def _sanitize_label(raw: str) -> str:
    """Reduce a label to one safe filename component (may return ``""``).

    Labels reach the filesystem as ``share-<label>.txt``, so a label must not
    be able to steer the write anywhere: path separators and every other
    unexpected character become ``_``, and ``..`` is collapsed so no traversal
    survives anywhere in the name.
    """
    safe = _LABEL_UNSAFE.sub("_", raw)
    while ".." in safe:
        safe = safe.replace("..", ".")
    return safe.lstrip(".-")[:MAX_LABEL_LEN]


def normalize_labels(labels, count: int) -> list[str]:
    """Return exactly ``count`` safe share labels, robustly (never fails):

    - no labels        -> numbered ``01``..``0N``
    - a single label   -> ``label-1``..``label-N``
    - fewer than count -> keep the given ones, pad the rest with numbers
    - more than count  -> truncate to ``count``

    Every label is sanitized first, so derived labels (``label-1``) are clean
    too. A label with nothing safe left in it falls back to its number.
    """
    cleaned = [_sanitize_label(str(x).strip()) for x in (labels or []) if str(x).strip()]
    if not any(cleaned):
        return [f"{i:02d}" for i in range(1, count + 1)]
    if len(cleaned) == 1 and count > 1:
        return [f"{cleaned[0]}-{i}" for i in range(1, count + 1)]
    cleaned = [c or f"{i:02d}" for i, c in enumerate(cleaned, start=1)]
    if len(cleaned) >= count:
        return cleaned[:count]
    return cleaned + [f"{i:02d}" for i in range(len(cleaned) + 1, count + 1)]


def decrypt(blob_b64: str, passphrase: bytes) -> bytes:
    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except binascii.Error as exc:
        raise ValueError("encrypted blob is not valid base64") from exc
    if len(blob) < ENC_HEADER_LEN:
        raise ValueError(
            f"encrypted blob truncated: expected at least {ENC_HEADER_LEN} bytes, "
            f"got {len(blob)}"
        )
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
