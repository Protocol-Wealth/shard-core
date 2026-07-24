"""Fordefi-specific recovery phrase validation and controlled file input."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Union

from . import safeio

WORD = re.compile(r"^[a-z]+$")
MAX_FORDEFI_PHRASE_BYTES = 1024


def canonicalize_recovery_phrase(
    raw: Union[str, bytes],
    *,
    allow_nonstandard: bool = False,
) -> bytes:
    """Canonicalize whitespace without changing word spelling or case."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_FORDEFI_PHRASE_BYTES:
            raise ValueError("Fordefi recovery phrase is too large")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Fordefi recovery phrase must contain ASCII words"
            ) from exc
    else:
        encoded = raw.encode("utf-8")
        if len(encoded) > MAX_FORDEFI_PHRASE_BYTES:
            raise ValueError("Fordefi recovery phrase is too large")
        try:
            text = encoded.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Fordefi recovery phrase must contain ASCII words"
            ) from exc

    if "\x00" in text:
        raise ValueError("Fordefi recovery phrase contains NUL")
    for character in text:
        if ord(character) < 32 and not character.isspace():
            raise ValueError(
                "Fordefi recovery phrase contains a control character"
            )

    words = text.split()
    if not words:
        raise ValueError("empty Fordefi recovery phrase")
    if not allow_nonstandard:
        if len(words) != 12:
            raise ValueError(
                "Fordefi recovery phrase must contain "
                f"12 words; got {len(words)}"
            )
        if any(not WORD.fullmatch(word) for word in words):
            raise ValueError(
                "Fordefi recovery phrase words must be lowercase ASCII letters"
            )

    return " ".join(words).encode("ascii")


def read_recovery_phrase_file(
    path: Union[str, os.PathLike],
    *,
    allow_nonstandard: bool = False,
    allow_insecure: bool = False,
) -> bytes:
    """Read a small regular phrase file, private by default."""
    target = Path(path)
    if not allow_insecure:
        metadata = os.lstat(target)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"refusing symlink Fordefi phrase file: {target}")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Fordefi phrase file is not regular: {target}")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(
                f"Fordefi phrase file is group/world accessible: {target}; "
                "use chmod 600 or --allow-insecure-phrase-file"
            )

    raw = safeio.read_limited_bytes(
        target,
        max_bytes=MAX_FORDEFI_PHRASE_BYTES,
        allow_symlink=allow_insecure,
    )
    return canonicalize_recovery_phrase(
        raw,
        allow_nonstandard=allow_nonstandard,
    )
