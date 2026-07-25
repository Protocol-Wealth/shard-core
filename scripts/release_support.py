"""Shared, dependency-free release lock and wheel inspection helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import zipfile
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable, Sequence


LOCK_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"==(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_LOCK_BYTES = 1024 * 1024


class ReleaseInputError(ValueError):
    """A release input is malformed, unsafe, or inconsistent."""


@dataclass(frozen=True)
class LockedRequirement:
    name: str
    version: str
    hashes: tuple[str, ...]

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)


@dataclass(frozen=True)
class WheelTarget:
    implementation: str
    python_version: str
    abi: str
    platform: str

    @property
    def python_digits(self) -> str:
        digits = self.python_version.replace(".", "")
        if not digits.isdigit() or len(digits) not in (2, 3):
            raise ReleaseInputError(
                f"invalid target Python version: {self.python_version}"
            )
        return digits

    @property
    def python_tag(self) -> str:
        return f"{self.implementation}{self.python_digits}"

    def as_dict(self) -> dict[str, str]:
        return {
            "implementation": self.implementation,
            "python_version": self.python_version,
            "python_tag": self.python_tag,
            "abi": self.abi,
            "platform": self.platform,
        }


@dataclass(frozen=True)
class WheelRecord:
    path: Path
    name: str
    version: str
    sha256: str
    tags: tuple[str, ...]
    requires_python: str | None
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)

    def as_dict(self) -> dict[str, object]:
        return {
            "filename": self.path.name,
            "name": self.name,
            "normalized_name": self.normalized_name,
            "version": self.version,
            "sha256": self.sha256,
            "tags": list(self.tags),
            "requires_python": self.requires_python,
            "requires_dist": list(self.requires_dist),
            "provides_extra": list(self.provides_extra),
        }


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_regular_file(path: Path, *, description: str) -> Path:
    if path.is_symlink():
        raise ReleaseInputError(f"refusing symlink {description}: {path}")
    try:
        mode = path.stat().st_mode
    except FileNotFoundError as exc:
        raise ReleaseInputError(f"missing {description}: {path}") from exc
    if not stat.S_ISREG(mode):
        raise ReleaseInputError(f"not a regular {description}: {path}")
    return path


def require_real_directory(path: Path, *, description: str) -> Path:
    if path.is_symlink():
        raise ReleaseInputError(f"refusing symlink {description}: {path}")
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ReleaseInputError(f"missing {description}: {path}") from exc
    absolute = Path(os.path.abspath(path))
    if resolved != absolute or not resolved.is_dir():
        raise ReleaseInputError(
            f"{description} must be a real, non-symlink directory: {path}"
        )
    return resolved


def read_hash_lock(path: Path) -> tuple[LockedRequirement, ...]:
    path = require_regular_file(path, description="hash lock")
    if path.stat().st_size > MAX_LOCK_BYTES:
        raise ReleaseInputError(f"hash lock is too large: {path}")

    requirements: list[LockedRequirement] = []
    seen: set[str] = set()

    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        tokens = shlex.split(raw_line, comments=True)
        if not tokens:
            continue

        match = LOCK_LINE.fullmatch(tokens[0])
        if match is None:
            raise ReleaseInputError(
                f"{path}:{line_number}: requirement must be an exact "
                "name==version pin"
            )

        hashes: list[str] = []
        for token in tokens[1:]:
            prefix = "--hash=sha256:"
            if not token.startswith(prefix):
                raise ReleaseInputError(
                    f"{path}:{line_number}: unsupported lock token: {token}"
                )
            digest = token[len(prefix) :]
            if SHA256.fullmatch(digest) is None:
                raise ReleaseInputError(
                    f"{path}:{line_number}: invalid SHA-256 digest"
                )
            hashes.append(digest)

        if not hashes:
            raise ReleaseInputError(
                f"{path}:{line_number}: requirement has no SHA-256 hash"
            )

        requirement = LockedRequirement(
            name=match.group("name"),
            version=match.group("version"),
            hashes=tuple(sorted(set(hashes))),
        )
        if requirement.normalized_name in seen:
            raise ReleaseInputError(
                f"{path}:{line_number}: duplicate locked project: "
                f"{requirement.name}"
            )
        seen.add(requirement.normalized_name)
        requirements.append(requirement)

    if not requirements:
        raise ReleaseInputError(f"hash lock contains no requirements: {path}")

    return tuple(requirements)


def inspect_wheel(path: Path) -> WheelRecord:
    path = require_regular_file(path, description="wheel")
    if path.suffix != ".whl":
        raise ReleaseInputError(f"not a wheel filename: {path.name}")

    (
        filename_tags,
        filename_name,
        filename_version,
        filename_build,
    ) = _wheel_filename(path.name)
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_names = [
                name
                for name in archive.namelist()
                if len(Path(name).parts) == 2
                and name.endswith(".dist-info/METADATA")
            ]
            wheel_names = [
                name
                for name in archive.namelist()
                if len(Path(name).parts) == 2
                and name.endswith(".dist-info/WHEEL")
            ]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise ReleaseInputError(
                    f"wheel must contain exactly one METADATA and WHEEL: "
                    f"{path.name}"
                )
            if metadata_names[0].rsplit("/", 1)[0] != wheel_names[0].rsplit(
                "/", 1
            )[0]:
                raise ReleaseInputError(
                    f"wheel metadata directories disagree: {path.name}"
                )
            dist_info_directory = metadata_names[0].rsplit("/", 1)[0]

            metadata = BytesParser(policy=policy.compat32).parsebytes(
                archive.read(metadata_names[0])
            )
            wheel_metadata = BytesParser(policy=policy.compat32).parsebytes(
                archive.read(wheel_names[0])
            )
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise ReleaseInputError(f"invalid wheel archive: {path.name}") from exc

    name = metadata.get("Name")
    version = metadata.get("Version")
    tags = tuple(sorted(set(wheel_metadata.get_all("Tag", []))))
    if not name or not version or not tags:
        raise ReleaseInputError(
            f"wheel is missing Name, Version, or Tag metadata: {path.name}"
        )
    expanded_metadata_tags = _expand_tags(tags)
    if expanded_metadata_tags != filename_tags:
        raise ReleaseInputError(
            f"wheel filename tags disagree with WHEEL metadata: {path.name}"
        )
    if normalize_name(name) != normalize_name(filename_name):
        raise ReleaseInputError(
            f"wheel filename name disagrees with METADATA: {path.name}"
        )
    if filename_version != version.replace("-", "_"):
        raise ReleaseInputError(
            f"wheel filename version disagrees with METADATA: {path.name}"
        )
    if not dist_info_directory.endswith(".dist-info"):
        raise ReleaseInputError(
            f"invalid wheel metadata directory: {path.name}"
        )
    dist_info_identity = dist_info_directory[: -len(".dist-info")]
    if "-" not in dist_info_identity:
        raise ReleaseInputError(
            f"invalid wheel metadata directory identity: {path.name}"
        )
    dist_info_name, dist_info_version = dist_info_identity.rsplit("-", 1)
    if (
        normalize_name(dist_info_name) != normalize_name(name)
        or dist_info_version != version.replace("-", "_")
    ):
        raise ReleaseInputError(
            f".dist-info identity disagrees with wheel identity: {path.name}"
        )
    wheel_build = wheel_metadata.get("Build")
    if (wheel_build or None) != filename_build:
        raise ReleaseInputError(
            f"wheel build tag disagrees with WHEEL metadata: {path.name}"
        )

    return WheelRecord(
        path=path,
        name=name,
        version=version,
        sha256=sha256_file(path),
        tags=tuple(sorted(expanded_metadata_tags)),
        requires_python=metadata.get("Requires-Python"),
        requires_dist=tuple(metadata.get_all("Requires-Dist", [])),
        provides_extra=tuple(metadata.get_all("Provides-Extra", [])),
    )


def _wheel_filename(
    filename: str,
) -> tuple[set[str], str, str, str | None]:
    if (
        not filename.endswith(".whl")
        or re.fullmatch(r"[A-Za-z0-9_.+!-]+\.whl", filename) is None
    ):
        raise ReleaseInputError(
            f"wheel filename is not restrictive ASCII PEP 427 form: "
            f"{filename!r}"
        )

    parts = filename[:-4].split("-")
    build_tag: str | None = None
    if len(parts) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = parts
    elif len(parts) == 6:
        (
            distribution,
            version,
            build_tag,
            python_tag,
            abi_tag,
            platform_tag,
        ) = parts
        if re.fullmatch(r"[0-9][A-Za-z0-9_.]*", build_tag) is None:
            raise ReleaseInputError(
                f"invalid wheel build tag: {filename}"
            )
    else:
        raise ReleaseInputError(f"invalid wheel filename fields: {filename}")

    if re.fullmatch(r"[A-Za-z0-9_]+", distribution) is None:
        raise ReleaseInputError(
            f"invalid wheel distribution field: {filename}"
        )
    if re.fullmatch(r"[A-Za-z0-9_.+!]+", version) is None:
        raise ReleaseInputError(f"invalid wheel version field: {filename}")
    for field in (python_tag, abi_tag, platform_tag):
        if re.fullmatch(r"[A-Za-z0-9_.]+", field) is None:
            raise ReleaseInputError(
                f"invalid wheel compatibility field: {filename}"
            )

    tags = {
        f"{python_value}-{abi_value}-{platform_value}"
        for python_value in python_tag.split(".")
        for abi_value in abi_tag.split(".")
        for platform_value in platform_tag.split(".")
    }
    return tags, distribution, version, build_tag


def _expand_tags(tags: Sequence[str]) -> set[str]:
    expanded: set[str] = set()
    for tag in tags:
        fields = tag.split("-", 2)
        if len(fields) != 3:
            raise ReleaseInputError(
                f"wheel contains an invalid compatibility tag: {tag}"
            )
        python_field, abi_field, platform_field = fields
        expanded.update(
            f"{python_value}-{abi_value}-{platform_value}"
            for python_value in python_field.split(".")
            for abi_value in abi_field.split(".")
            for platform_value in platform_field.split(".")
        )
    return expanded


def wheel_supports_target(record: WheelRecord, target: WheelTarget) -> bool:
    target_digits = target.python_digits
    target_major = int(target_digits[0])
    target_minor = int(target_digits[1:])

    for tag in record.tags:
        python_field, abi_field, platform_field = tag.split("-", 2)
        platforms = set(platform_field.split("."))
        if "any" not in platforms and target.platform not in platforms:
            continue

        abis = set(abi_field.split("."))
        for python_tag in python_field.split("."):
            if python_tag in {f"py{target_major}", f"py{target_digits}"}:
                if "none" in abis:
                    return True
                continue

            if python_tag == target.python_tag:
                if "none" in abis or "abi3" in abis or target.abi in abis:
                    return True
                continue

            if (
                python_tag.startswith("cp")
                and "abi3" in abis
                and python_tag[2:].isdigit()
            ):
                wheel_digits = python_tag[2:]
                wheel_major = int(wheel_digits[0])
                wheel_minor = int(wheel_digits[1:])
                if (
                    wheel_major == target_major
                    and wheel_minor <= target_minor
                ):
                    return True

    return False


def verify_wheelhouse(
    lock_path: Path,
    wheelhouse: Path,
    *,
    target: WheelTarget,
) -> tuple[WheelRecord, ...]:
    requirements = read_hash_lock(lock_path)
    wheelhouse = require_real_directory(
        wheelhouse,
        description="wheelhouse",
    )

    entries = sorted(wheelhouse.iterdir(), key=lambda item: item.name)
    if not entries:
        raise ReleaseInputError(f"wheelhouse is empty: {wheelhouse}")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".whl":
            raise ReleaseInputError(
                f"wheelhouse contains a non-wheel entry: {entry.name}"
            )

    records = tuple(inspect_wheel(entry) for entry in entries)
    by_name: dict[str, list[WheelRecord]] = {}
    for record in records:
        by_name.setdefault(record.normalized_name, []).append(record)

    locked_names = {requirement.normalized_name for requirement in requirements}
    found_names = set(by_name)
    if found_names != locked_names:
        missing = sorted(locked_names - found_names)
        extra = sorted(found_names - locked_names)
        raise ReleaseInputError(
            f"wheelhouse inventory differs from lock; missing={missing}, "
            f"extra={extra}"
        )

    verified: list[WheelRecord] = []
    for requirement in requirements:
        matches = by_name[requirement.normalized_name]
        if len(matches) != 1:
            raise ReleaseInputError(
                f"expected exactly one wheel for {requirement.name}; "
                f"found {len(matches)}"
            )
        record = matches[0]
        if record.version != requirement.version:
            raise ReleaseInputError(
                f"version mismatch for {requirement.name}: "
                f"locked={requirement.version}, wheel={record.version}"
            )
        if record.sha256 not in requirement.hashes:
            raise ReleaseInputError(
                f"unapproved wheel hash for {record.path.name}"
            )
        if not wheel_supports_target(record, target):
            raise ReleaseInputError(
                f"wheel is incompatible with target "
                f"{target.python_tag}-{target.abi}-{target.platform}: "
                f"{record.path.name}"
            )
        verified.append(record)

    return tuple(sorted(verified, key=lambda record: record.normalized_name))


def render_hashed_requirements(records: Sequence[WheelRecord]) -> str:
    validate_unique_inventory(records)
    lines = [
        f"{record.name}=={record.version} "
        f"--hash=sha256:{record.sha256}"
        for record in sorted(
            records,
            key=lambda item: item.normalized_name,
        )
    ]
    return "\n".join(lines) + "\n"


def validate_unique_inventory(records: Sequence[WheelRecord]) -> None:
    names: set[str] = set()
    filenames: set[str] = set()
    for record in records:
        if record.normalized_name in names:
            raise ReleaseInputError(
                f"duplicate wheel project identity: {record.name}"
            )
        if record.path.name in filenames:
            raise ReleaseInputError(
                f"duplicate wheel filename: {record.path.name}"
            )
        names.add(record.normalized_name)
        filenames.add(record.path.name)


def atomic_write_json(path: Path, value: object) -> None:
    data = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def inventory_document(
    records: Iterable[WheelRecord],
    *,
    schema: str,
    target: WheelTarget,
) -> dict[str, object]:
    return {
        "schema": schema,
        "target": target.as_dict(),
        "wheels": [
            record.as_dict()
            for record in sorted(
                records,
                key=lambda item: item.normalized_name,
            )
        ],
    }
