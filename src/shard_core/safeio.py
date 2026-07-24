"""Conservative local file I/O for secret ceremony material.

These helpers protect the final output component and publish complete files
without following output symlinks. They do not defend against an attacker who
can replace arbitrary parent-directory components during an operation. The
ceremony boundary is therefore a trusted offline host and a controlled output
directory.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Iterable, Union

PathLike = Union[str, os.PathLike]


class UnsafeInputPath(ValueError):
    """Input destination is unsafe for secret material."""


class UnsafeOutputPath(ValueError):
    """Output destination is unsafe for secret material."""


def read_limited_bytes(
    path: PathLike,
    *,
    max_bytes: int,
    allow_symlink: bool = False,
) -> bytes:
    """Read at most ``max_bytes`` from a regular file.

    Final-component symlinks are refused unless the caller explicitly opts
    into compatibility behavior.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")

    target = Path(path)
    if not allow_symlink and target.is_symlink():
        raise UnsafeInputPath(f"refusing symlink input: {target}")

    flags = os.O_RDONLY
    if not allow_symlink and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(target, flags)
    except OSError as exc:
        if not allow_symlink and target.is_symlink():
            raise UnsafeInputPath(f"refusing symlink input: {target}") from exc
        raise

    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafeInputPath(f"refusing non-regular input: {target}")
        if metadata.st_size > max_bytes:
            raise ValueError(
                f"input is too large: {target} exceeds {max_bytes} bytes"
            )

        with os.fdopen(fd, "rb", closefd=True) as stream:
            fd = -1
            data = stream.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)

    if len(data) > max_bytes:
        raise ValueError(f"input is too large: {target} exceeds {max_bytes} bytes")
    return data


def ensure_private_dir(path: PathLike) -> Path:
    """Return a real directory, creating the final directory with mode 0700."""
    target = Path(path)

    # Path.exists() is false for a broken symlink, so test this first.
    if target.is_symlink():
        raise UnsafeOutputPath(f"refusing symlink directory: {target}")

    if not target.exists():
        target.mkdir(parents=True, mode=0o700)

    if target.is_symlink() or not target.is_dir():
        raise UnsafeOutputPath(f"not a real directory: {target}")

    return target


def _validate_target(path: Path, *, force: bool) -> None:
    if path.is_symlink():
        raise UnsafeOutputPath(f"refusing symlink output: {path}")

    if not path.exists():
        return

    if not path.is_file():
        raise UnsafeOutputPath(f"refusing non-regular output: {path}")

    if not force:
        raise FileExistsError(f"output already exists: {path}")


def preflight_output_paths(
    paths: Iterable[PathLike],
    *,
    force: bool = False,
) -> list[Path]:
    """Validate every output destination before a multi-file write begins."""
    normalized = [Path(path) for path in paths]
    identities = [os.path.abspath(os.fspath(path)) for path in normalized]

    if len(set(identities)) != len(identities):
        raise ValueError("duplicate output destination")

    for path in normalized:
        ensure_private_dir(path.parent)
        _validate_target(path, force=force)

    return normalized


def _write_temporary(path: Path, data: bytes, mode: int) -> str:
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=str(path.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary_name
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        # Some supported filesystems do not implement directory fsync.
        pass
    finally:
        os.close(fd)


def atomic_write_bytes(
    path: PathLike,
    data: bytes,
    *,
    force: bool = False,
    mode: int = 0o600,
) -> None:
    """Atomically publish a complete regular file without following symlinks."""
    target = Path(path)
    ensure_private_dir(target.parent)
    _validate_target(target, force=force)
    temporary_name = _write_temporary(target, data, mode)

    try:
        # Re-check immediately before publication.
        _validate_target(target, force=force)

        if force:
            # os.replace replaces a symlink itself; it never writes through it.
            os.replace(temporary_name, target)
            temporary_name = ""
        else:
            # A same-filesystem hard link is an atomic no-replace publication:
            # link() fails if any final component already exists.
            try:
                os.link(
                    temporary_name,
                    target,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                if target.is_symlink():
                    raise UnsafeOutputPath(
                        f"refusing symlink output: {target}"
                    ) from exc
                raise FileExistsError(f"output already exists: {target}") from exc
            os.unlink(temporary_name)
            temporary_name = ""

        _fsync_directory(target.parent)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def atomic_write_text(
    path: PathLike,
    text: str,
    *,
    force: bool = False,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(
        path,
        text.encode("utf-8"),
        force=force,
        mode=mode,
    )
