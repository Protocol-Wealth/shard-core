#!/usr/bin/env python3
"""Build a deterministic candidate bundle from reviewed offline inputs."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import tomllib
from pathlib import Path, PurePosixPath

from release_support import (
    ReleaseInputError,
    WheelRecord,
    WheelTarget,
    inspect_wheel,
    inventory_document,
    render_hashed_requirements,
    require_real_directory,
    sha256_bytes,
    sha256_file,
    validate_unique_inventory,
    verify_wheelhouse,
    wheel_supports_target,
)


ROOT = Path(__file__).resolve().parents[1]
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
REGISTRY_COMPONENT = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
REGISTRY_HOST = (
    rf"(?:localhost|{REGISTRY_COMPONENT}(?:\.{REGISTRY_COMPONENT})+)"
)
REPOSITORY_COMPONENT = (
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
)
IMAGE = re.compile(
    rf"^(?P<repository>{REGISTRY_HOST}(?::[0-9]{{1,5}})?"
    rf"/{REPOSITORY_COMPONENT}"
    rf"(?:/{REPOSITORY_COMPONENT})*)"
    rf"@sha256:(?P<digest>[0-9a-f]{{64}})$"
)
RUNTIME_LOCK_RELATIVE = Path(
    "release/locks/runtime-cp39-abi3-manylinux_2_17_x86_64.txt"
)
BUILD_LOCK_RELATIVE = Path("release/build-requirements.txt")
RUNTIME_TARGET = WheelTarget(
    implementation="cp",
    python_version="3.9",
    abi="abi3",
    platform="manylinux_2_17_x86_64",
)
BUILD_TARGET = WheelTarget(
    implementation="cp",
    python_version="3.11",
    abi="none",
    platform="manylinux_2_17_x86_64",
)
DETERMINISTIC_ENVIRONMENT = {
    "PYTHONHASHSEED": "0",
    "TZ": "UTC",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build twice from a reviewed commit using pre-populated, "
            "hash-verified wheelhouses. This command does not download."
        )
    )
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-runtime-lock-sha256", required=True)
    parser.add_argument("--expected-build-lock-sha256", required=True)
    parser.add_argument("--git-path", required=True, type=Path)
    parser.add_argument("--expected-git-sha256", required=True)
    parser.add_argument("--python-path", required=True, type=Path)
    parser.add_argument("--expected-python-sha256", required=True)
    parser.add_argument("--podman-path", required=True, type=Path)
    parser.add_argument("--expected-podman-sha256", required=True)
    parser.add_argument("--expected-oci-runtime-sha256", required=True)
    parser.add_argument("--expected-conmon-sha256", required=True)
    parser.add_argument("--expected-ceremony-uid", required=True, type=int)
    parser.add_argument("--expected-ceremony-user", required=True)
    parser.add_argument("--empty-hooks-dir", required=True, type=Path)
    parser.add_argument("--podman-config-root", required=True, type=Path)
    parser.add_argument("--expected-podman-config-sha256", required=True)
    parser.add_argument("--podman-data-root", required=True, type=Path)
    parser.add_argument("--podman-runtime-root", required=True, type=Path)
    parser.add_argument("--build-image", required=True)
    parser.add_argument("--expected-build-image-digest", required=True)
    parser.add_argument("--expected-platform-manifest-digest", required=True)
    parser.add_argument("--expected-image-config-digest", required=True)
    parser.add_argument("--runtime-wheelhouse", required=True, type=Path)
    parser.add_argument("--build-wheelhouse", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    return parser


def _git_text(git_path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        [str(git_path), *arguments],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _source_identity(
    git_path: Path,
    expected_commit: str,
) -> dict[str, str]:
    if COMMIT.fullmatch(expected_commit) is None:
        raise ReleaseInputError(
            "--expected-source-commit must be a lowercase 40-character SHA"
        )
    head = _git_text(git_path, "rev-parse", "--verify", "HEAD")
    if head != expected_commit:
        raise ReleaseInputError(
            f"reviewed source mismatch: expected={expected_commit}, HEAD={head}"
        )
    status = _git_text(
        git_path,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status:
        raise ReleaseInputError(
            "working tree contains tracked, staged, or untracked changes"
        )
    return {
        "repository": _git_text(
            git_path,
            "config",
            "--get",
            "remote.origin.url",
        ),
        "commit": head,
        "tree": _git_text(git_path, "rev-parse", f"{head}^{{tree}}"),
        "commit_timestamp": _git_text(
            git_path,
            "show",
            "-s",
            "--format=%ct",
            head,
        ),
    }


def _approved_digest(value: str, *, description: str) -> str:
    if DIGEST.fullmatch(value) is None:
        raise ReleaseInputError(
            f"{description} must be a lowercase 64-character SHA-256"
        )
    return value


def _git_archive(git_path: Path, commit: str) -> bytes:
    completed = subprocess.run(
        [str(git_path), "archive", "--format=tar", commit],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def _extract_archive(archive_bytes: bytes, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if (
                member_path.is_absolute()
                or ".." in member_path.parts
                or not member_path.parts
            ):
                raise ReleaseInputError(
                    f"unsafe path in source archive: {member.name}"
                )
            output = destination.joinpath(*member_path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            if not member.isfile():
                raise ReleaseInputError(
                    f"unsupported non-regular source member: {member.name}"
                )
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            source = archive.extractfile(member)
            if source is None:
                raise ReleaseInputError(
                    f"could not read source member: {member.name}"
                )
            with source, output.open("xb") as stream:
                shutil.copyfileobj(source, stream)
            output.chmod(member.mode & 0o777)


def _copy_exclusive(source: Path, destination: Path) -> None:
    source_flags = os.O_RDONLY
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        destination_flags |= os.O_NOFOLLOW

    source_fd = os.open(source, source_flags)
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ReleaseInputError(
                f"not a regular wheel input: {source}"
            )
        destination_fd = os.open(destination, destination_flags, 0o600)
        try:
            with (
                os.fdopen(source_fd, "rb", closefd=False) as input_stream,
                os.fdopen(
                    destination_fd,
                    "wb",
                    closefd=False,
                ) as output_stream,
            ):
                shutil.copyfileobj(input_stream, output_stream)
                output_stream.flush()
                os.fsync(output_stream.fileno())
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def _snapshot_wheelhouse(source: Path, destination: Path) -> Path:
    destination.mkdir(mode=0o700)
    entries = sorted(source.iterdir(), key=lambda path: path.name)
    if not entries:
        raise ReleaseInputError(f"wheelhouse is empty: {source}")
    for entry in entries:
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".whl":
            raise ReleaseInputError(
                f"wheelhouse contains a non-wheel entry: {entry.name}"
            )
        _copy_exclusive(entry, destination / entry.name)
    return destination


def _record_identity(
    records: tuple[WheelRecord, ...],
) -> set[tuple[str, str, str]]:
    return {
        (record.normalized_name, record.version, record.sha256)
        for record in records
    }


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root)):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReleaseInputError(
                f"source snapshot contains a symlink: {relative}"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReleaseInputError(
                f"source snapshot contains a non-regular entry: {relative}"
            )
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(stat.S_IMODE(path.stat().st_mode)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\x00")
    return digest.hexdigest()


def _podman_environment(
    *,
    config_files: dict[str, Path],
    config_root: Path,
    data_root: Path,
    runtime_root: Path,
    home: Path,
    user: str,
) -> dict[str, str]:
    return {
        "CONTAINERS_CONF": str(config_files["containers.conf"]),
        "CONTAINERS_REGISTRIES_CONF": str(
            config_files["registries.conf"]
        ),
        "CONTAINERS_STORAGE_CONF": str(config_files["storage.conf"]),
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": user,
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PODMAN_NO_PAUSE_PROCESS": "1",
        "TMPDIR": str(runtime_root),
        "TZ": "UTC",
        "USER": user,
        "XDG_CONFIG_HOME": str(config_root),
        "XDG_DATA_HOME": str(data_root),
        "XDG_RUNTIME_DIR": str(runtime_root),
    }


def _podman_command(
    podman_path: Path,
    hooks_directory: Path,
    data_root: Path,
    runtime_root: Path,
) -> list[str]:
    return [
        str(podman_path),
        "--root",
        str(data_root),
        "--runroot",
        str(runtime_root),
        "--remote=false",
        "--hooks-dir",
        str(hooks_directory),
    ]


def _approved_executable(
    path: Path,
    expected_digest: str,
    *,
    description: str,
) -> Path:
    if not path.is_absolute():
        raise ReleaseInputError(f"{description} path must be absolute")
    if (
        path.is_symlink()
        or not path.is_file()
        or path.resolve(strict=True) != path
    ):
        raise ReleaseInputError(
            f"{description} and its path must contain no symlinks: {path}"
        )
    file_stat = path.stat()
    if file_stat.st_uid != 0 or stat.S_IMODE(file_stat.st_mode) & 0o022:
        raise ReleaseInputError(
            f"{description} must be root-owned and not group/world-writable"
        )
    for parent in path.parents:
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise ReleaseInputError(
                f"{description} parent is not root-controlled: {parent}"
            )
    if not os.access(path, os.X_OK):
        raise ReleaseInputError(f"{description} is not executable: {path}")
    if sha256_file(path) != expected_digest:
        raise ReleaseInputError(f"{description} digest is not approved")
    return path


def _approved_private_directory(
    path: Path,
    *,
    expected_uid: int,
    description: str,
) -> Path:
    directory = require_real_directory(path, description=description)
    if not directory.is_absolute() or directory.resolve(strict=True) != directory:
        raise ReleaseInputError(
            f"{description} must be an absolute path without symlinks"
        )
    directory_stat = directory.stat()
    if (
        directory_stat.st_uid != expected_uid
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
    ):
        raise ReleaseInputError(
            f"{description} must be ceremony-owned and mode 0700"
        )
    return directory


def _approved_podman_config(
    root: Path,
    expected_digest: str,
) -> tuple[Path, dict[str, Path]]:
    config_root = require_real_directory(
        root,
        description="Podman configuration root",
    )
    if (
        not config_root.is_absolute()
        or config_root.resolve(strict=True) != config_root
    ):
        raise ReleaseInputError(
            "Podman configuration root must be absolute without symlinks"
        )
    for component in (config_root, *config_root.parents):
        component_stat = component.stat()
        if (
            component_stat.st_uid != 0
            or stat.S_IMODE(component_stat.st_mode) & 0o022
        ):
            raise ReleaseInputError(
                "Podman configuration root must be root-controlled"
            )

    relative_files = {
        "containers.conf": Path("containers/containers.conf"),
        "mounts.conf": Path("containers/mounts.conf"),
        "registries.conf": Path("containers/registries.conf"),
        "storage.conf": Path("containers/storage.conf"),
    }
    actual_files: set[Path] = set()
    for entry in config_root.rglob("*"):
        relative = entry.relative_to(config_root)
        if entry.is_symlink():
            raise ReleaseInputError(
                f"Podman configuration contains a symlink: {relative}"
            )
        if entry.is_dir():
            entry_stat = entry.stat()
            if (
                entry_stat.st_uid != 0
                or stat.S_IMODE(entry_stat.st_mode) & 0o022
            ):
                raise ReleaseInputError(
                    "Podman configuration directory is not root-controlled: "
                    f"{relative}"
                )
            continue
        if not entry.is_file():
            raise ReleaseInputError(
                f"Podman configuration has a non-regular entry: {relative}"
            )
        entry_stat = entry.stat()
        if (
            entry_stat.st_uid != 0
            or stat.S_IMODE(entry_stat.st_mode) & 0o022
        ):
            raise ReleaseInputError(
                "Podman configuration file is not root-controlled: "
                f"{relative}"
            )
        actual_files.add(relative)

    expected_files = set(relative_files.values())
    if actual_files != expected_files:
        raise ReleaseInputError(
            "Podman configuration inventory differs from the approved "
            f"four-file layout: {sorted(str(path) for path in actual_files)}"
        )
    resolved = {
        name: config_root / relative
        for name, relative in relative_files.items()
    }
    if resolved["mounts.conf"].read_bytes():
        raise ReleaseInputError(
            "approved rootless mounts.conf must be empty"
        )
    if _tree_digest(config_root) != expected_digest:
        raise ReleaseInputError(
            "Podman configuration tree digest is not approved"
        )
    return config_root, resolved


def _inspected_digest(value: object, *, description: str) -> str:
    if not isinstance(value, str):
        raise ReleaseInputError(f"{description} is not a string")
    digest = value.removeprefix("sha256:")
    if DIGEST.fullmatch(digest) is None:
        raise ReleaseInputError(f"{description} is not a SHA-256 digest")
    return digest


def _canonical_image_match(value: str) -> re.Match[str] | None:
    match = IMAGE.fullmatch(value)
    if match is None:
        return None
    registry = match.group("repository").split("/", 1)[0]
    if ":" in registry:
        port = int(registry.rsplit(":", 1)[1])
        if port < 1 or port > 65535:
            return None
    return match


def _validate_image_inspection(
    image_record: object,
    image_reference: str,
    *,
    expected_repository_digest: str,
    expected_platform_manifest_digest: str,
    expected_image_config_digest: str,
    description: str,
) -> dict[str, object]:
    match = _canonical_image_match(image_reference)
    if match is None:
        raise ReleaseInputError(
            f"{description} reference is not a canonical digest reference"
        )
    if not isinstance(image_record, dict):
        raise ReleaseInputError(
            f"{description} inspection record is not an object"
        )

    raw_repo_digests = image_record.get("RepoDigests")
    if (
        not isinstance(raw_repo_digests, (list, tuple))
        or any(not isinstance(value, str) for value in raw_repo_digests)
    ):
        raise ReleaseInputError(
            f"{description} repository digests are invalid"
        )
    repository_digests = tuple(raw_repo_digests)
    if (
        len(set(repository_digests)) != len(repository_digests)
        or any(
            _canonical_image_match(value) is None
            for value in repository_digests
        )
    ):
        raise ReleaseInputError(
            f"{description} repository digests are invalid"
        )
    repository = match.group("repository")
    required_references = {
        f"{repository}@sha256:{expected_repository_digest}",
        f"{repository}@sha256:{expected_platform_manifest_digest}",
    }
    if not required_references.issubset(repository_digests):
        raise ReleaseInputError(
            f"{description} does not carry both approved repository "
            "and platform digest references"
        )

    reported_digest = _inspected_digest(
        image_record.get("Digest"),
        description=f"{description} reported digest",
    )
    if reported_digest not in {
        expected_repository_digest,
        expected_platform_manifest_digest,
    }:
        raise ReleaseInputError(
            f"{description} reported digest is not approved"
        )

    image_config = _inspected_digest(
        image_record.get("Id") or image_record.get("ID"),
        description=f"{description} image-config digest",
    )
    if image_config != expected_image_config_digest:
        raise ReleaseInputError(
            f"{description} image-config digest is not approved"
        )

    image_os = image_record.get("Os")
    image_architecture = image_record.get("Architecture")
    if image_os != "linux" or image_architecture != "amd64":
        raise ReleaseInputError(
            f"{description} must resolve to Linux amd64"
        )

    return {
        "repository": repository,
        "repository_digests": list(repository_digests),
        "reported_digest": reported_digest,
        "image_config_digest": image_config,
        "image_os": image_os,
        "image_architecture": image_architecture,
    }


def _assert_image_inspection_identity_unchanged(
    build_environment: dict[str, object],
    current_inspection: dict[str, object],
) -> None:
    if (
        current_inspection["reported_digest"]
        != build_environment["observed_image_digest"]
    ):
        raise ReleaseInputError(
            "build image reported digest changed during ceremony"
        )
    if set(current_inspection["repository_digests"]) != set(
        build_environment["repository_digests"]
    ):
        raise ReleaseInputError(
            "build image repository digests changed during ceremony"
        )


def _approved_hooks_directory(path: Path) -> Path:
    hooks = require_real_directory(path, description="empty OCI hooks directory")
    if not hooks.is_absolute() or hooks.resolve(strict=True) != hooks:
        raise ReleaseInputError(
            "OCI hooks directory must be absolute without symlinks"
        )
    for component in (hooks, *hooks.parents):
        component_stat = component.stat()
        if (
            component_stat.st_uid != 0
            or stat.S_IMODE(component_stat.st_mode) & 0o022
        ):
            raise ReleaseInputError(
                "OCI hooks directory parent chain must be root-controlled: "
                f"{component}"
            )
    if any(hooks.iterdir()):
        raise ReleaseInputError("OCI hooks directory must be empty")
    return hooks


def _inspect_build_environment(
    podman_path: Path,
    hooks_directory: Path,
    image: str,
    *,
    expected_podman_digest: str,
    expected_oci_runtime_digest: str,
    expected_conmon_digest: str,
    expected_repository_digest: str,
    expected_platform_manifest_digest: str,
    expected_image_config_digest: str,
    expected_uid: int,
    expected_user: str,
    podman_config_root: Path,
    expected_podman_config_digest: str,
    podman_data_root: Path,
    podman_runtime_root: Path,
) -> tuple[dict[str, object], dict[str, str]]:
    if os.geteuid() == 0:
        raise ReleaseInputError("the ceremony builder must not run as root")
    if os.getuid() != expected_uid or os.geteuid() != expected_uid:
        raise ReleaseInputError(
            "current UID differs from the approved ceremony UID"
        )
    try:
        account = pwd.getpwuid(expected_uid)
    except KeyError as exc:
        raise ReleaseInputError("approved ceremony UID has no account") from exc
    if account.pw_name != expected_user:
        raise ReleaseInputError(
            "current account differs from the approved ceremony account"
        )

    podman = _approved_executable(
        podman_path,
        expected_podman_digest,
        description="Podman client",
    )
    hooks = _approved_hooks_directory(hooks_directory)
    config_root, config_files = _approved_podman_config(
        podman_config_root,
        expected_podman_config_digest,
    )
    data_root = _approved_private_directory(
        podman_data_root,
        expected_uid=expected_uid,
        description="Podman data root",
    )
    runtime_root = _approved_private_directory(
        podman_runtime_root,
        expected_uid=expected_uid,
        description="Podman runtime root",
    )
    environment = _podman_environment(
        config_files=config_files,
        config_root=config_root,
        data_root=data_root,
        runtime_root=runtime_root,
        home=Path(account.pw_dir),
        user=expected_user,
    )
    match = _canonical_image_match(image)
    if match is None:
        raise ReleaseInputError(
            "--build-image must be a repository reference pinned by sha256"
        )
    if match.group("digest") != expected_repository_digest:
        raise ReleaseInputError(
            "build image digest differs from the approved digest"
        )

    info_result = subprocess.run(
        [
            *_podman_command(
                podman,
                hooks,
                data_root,
                runtime_root,
            ),
            "info",
            "--format",
            "json",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        info = json.loads(info_result.stdout)
        host = info["host"]
        store = info["store"]
        security = host["security"]
        oci_runtime_path = Path(host["ociRuntime"]["path"])
        conmon_path = Path(host["conmon"]["path"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ReleaseInputError(
            "Podman returned incomplete local-host information"
        ) from exc
    if host.get("serviceIsRemote") is not False:
        raise ReleaseInputError("remote Podman service is forbidden")
    if security.get("rootless") is not True:
        raise ReleaseInputError("Podman must operate rootlessly")
    if security.get("seccompEnabled") is not True:
        raise ReleaseInputError("Podman seccomp must be enabled")
    if host.get("os") != "linux" or host.get("arch") != "amd64":
        raise ReleaseInputError("Podman host must be Linux amd64")
    try:
        effective_graph_root = Path(store["graphRoot"]).resolve(strict=True)
        effective_run_root = Path(store["runRoot"]).resolve(strict=True)
    except (KeyError, TypeError, OSError) as exc:
        raise ReleaseInputError(
            "Podman returned invalid effective storage roots"
        ) from exc
    if effective_graph_root != data_root:
        raise ReleaseInputError(
            "Podman graphRoot differs from --podman-data-root"
        )
    if effective_run_root != runtime_root:
        raise ReleaseInputError(
            "Podman runRoot differs from --podman-runtime-root"
        )

    oci_runtime = _approved_executable(
        oci_runtime_path,
        expected_oci_runtime_digest,
        description="OCI runtime",
    )
    conmon = _approved_executable(
        conmon_path,
        expected_conmon_digest,
        description="conmon",
    )

    completed = subprocess.run(
        [
            *_podman_command(
                podman,
                hooks,
                data_root,
                runtime_root,
            ),
            "image",
            "inspect",
            image,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    try:
        inspected = json.loads(completed.stdout)
        image_record = inspected[0]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ReleaseInputError(
            "OCI runtime returned invalid image inspection data"
        ) from exc
    image_inspection = _validate_image_inspection(
        image_record,
        image,
        expected_repository_digest=expected_repository_digest,
        expected_platform_manifest_digest=(
            expected_platform_manifest_digest
        ),
        expected_image_config_digest=expected_image_config_digest,
        description="approved build image",
    )

    version = subprocess.run(
        [
            *_podman_command(
                podman,
                hooks,
                data_root,
                runtime_root,
            ),
            "--version",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    ).stdout.strip()
    return {
        "ceremony_account": {
            "uid": expected_uid,
            "user": expected_user,
        },
        "podman": {
            "path": str(podman),
            "sha256": expected_podman_digest,
            "version": version,
            "rootless": True,
            "service_is_remote": False,
        },
        "oci_runtime": {
            "path": str(oci_runtime),
            "sha256": expected_oci_runtime_digest,
            "version": host["ociRuntime"].get("version"),
        },
        "conmon": {
            "path": str(conmon),
            "sha256": expected_conmon_digest,
            "version": host["conmon"].get("version"),
        },
        "hooks_directory": {
            "path": str(hooks),
            "empty": True,
            "owner_uid": 0,
            "mode": f"{stat.S_IMODE(hooks.stat().st_mode):04o}",
        },
        "podman_configuration": {
            "root": str(config_root),
            "sha256": expected_podman_config_digest,
            "files": {
                name: str(path)
                for name, path in sorted(config_files.items())
            },
            "mounts_conf_empty": True,
        },
        "podman_storage": {
            "data_root": str(data_root),
            "runtime_root": str(runtime_root),
            "effective_graph_root": str(effective_graph_root),
            "effective_run_root": str(effective_run_root),
            "owner_uid": expected_uid,
            "mode": "0700",
        },
        "image_reference": image,
        "image_repository": image_inspection["repository"],
        "repository_digest": expected_repository_digest,
        "platform_manifest_digest": expected_platform_manifest_digest,
        "image_config_digest": expected_image_config_digest,
        "observed_image_digest": image_inspection["reported_digest"],
        "image_os": image_inspection["image_os"],
        "image_architecture": image_inspection["image_architecture"],
        "repository_digests": image_inspection["repository_digests"],
    }, environment


def _assert_build_environment_unchanged(
    build_environment: dict[str, object],
    podman_environment: dict[str, str],
) -> None:
    for component in ("git", "python", "podman", "oci_runtime", "conmon"):
        record = build_environment[component]
        if not isinstance(record, dict):
            raise ReleaseInputError(
                f"invalid recorded build component: {component}"
            )
        path = Path(str(record["path"]))
        expected = str(record["sha256"])
        _approved_executable(
            path,
            expected,
            description=component,
        )
    hooks_record = build_environment["hooks_directory"]
    if not isinstance(hooks_record, dict):
        raise ReleaseInputError("invalid recorded hooks directory")
    hooks = Path(str(hooks_record["path"]))
    _approved_hooks_directory(hooks)
    config_record = build_environment["podman_configuration"]
    storage_record = build_environment["podman_storage"]
    account_record = build_environment["ceremony_account"]
    if not all(
        isinstance(record, dict)
        for record in (config_record, storage_record, account_record)
    ):
        raise ReleaseInputError(
            "invalid recorded Podman configuration or storage"
        )
    _approved_podman_config(
        Path(str(config_record["root"])),
        str(config_record["sha256"]),
    )
    _approved_private_directory(
        Path(str(storage_record["data_root"])),
        expected_uid=int(account_record["uid"]),
        description="Podman data root",
    )
    _approved_private_directory(
        Path(str(storage_record["runtime_root"])),
        expected_uid=int(account_record["uid"]),
        description="Podman runtime root",
    )

    podman_record = build_environment["podman"]
    if not isinstance(podman_record, dict):
        raise ReleaseInputError("invalid recorded Podman client")
    image = str(build_environment["image_reference"])
    data_root = Path(str(storage_record["data_root"]))
    runtime_root = Path(str(storage_record["runtime_root"]))
    info_result = subprocess.run(
        [
            *_podman_command(
                Path(str(podman_record["path"])),
                hooks,
                data_root,
                runtime_root,
            ),
            "info",
            "--format",
            "json",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=podman_environment,
    )
    try:
        effective_store = json.loads(info_result.stdout)["store"]
        current_graph_root = Path(
            effective_store["graphRoot"]
        ).resolve(strict=True)
        current_run_root = Path(
            effective_store["runRoot"]
        ).resolve(strict=True)
    except (KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise ReleaseInputError(
            "post-build Podman storage inspection is invalid"
        ) from exc
    if (
        current_graph_root != data_root
        or current_run_root != runtime_root
    ):
        raise ReleaseInputError(
            "effective Podman storage roots changed during ceremony"
        )
    inspected_result = subprocess.run(
        [
            *_podman_command(
                Path(str(podman_record["path"])),
                hooks,
                data_root,
                runtime_root,
            ),
            "image",
            "inspect",
            image,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=podman_environment,
    )
    try:
        inspected_image = json.loads(inspected_result.stdout)[0]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ReleaseInputError(
            "post-build image inspection is invalid"
        ) from exc
    current_inspection = _validate_image_inspection(
        inspected_image,
        image,
        expected_repository_digest=str(
            build_environment["repository_digest"]
        ),
        expected_platform_manifest_digest=str(
            build_environment["platform_manifest_digest"]
        ),
        expected_image_config_digest=str(
            build_environment["image_config_digest"]
        ),
        description="post-build image",
    )
    _assert_image_inspection_identity_unchanged(
        build_environment,
        current_inspection,
    )


def _acquire_ceremony_lock(output_parent: Path) -> int:
    lock_path = output_parent / ".shard-core-ceremony.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise ReleaseInputError(
            "another ceremony build holds the output lock"
        ) from exc
    return descriptor


CONTAINER_BOOTSTRAP = textwrap.dedent(
    r"""
    import hashlib
    import os
    import shutil
    import stat
    import sys
    from pathlib import Path

    expected = sys.argv[1]
    source = Path("/inputs/source")
    private_source = Path("/work/source")
    shutil.copytree(source, private_source)
    digest = hashlib.sha256()
    for path in sorted(
        private_source.rglob("*"),
        key=lambda item: item.relative_to(private_source),
    ):
        relative = path.relative_to(private_source).as_posix()
        if path.is_symlink():
            raise SystemExit(f"source copy contains symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SystemExit(f"source copy has non-regular entry: {relative}")
        file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(stat.S_IMODE(path.stat().st_mode)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\x00")
    if digest.hexdigest() != expected:
        raise SystemExit("private source copy has an unapproved tree digest")
    script = private_source / "scripts" / "container-build-wheel.py"
    os.execv(
        sys.executable,
        [
            sys.executable,
            str(script),
            "--source",
            str(private_source),
            *sys.argv[2:],
        ],
    )
    """
).strip()


def _bind_archived_lock(
    source_one: Path,
    source_two: Path,
    relative_path: Path,
    expected_digest: str,
) -> tuple[Path, Path]:
    lock_one = source_one / relative_path
    lock_two = source_two / relative_path
    if (
        lock_one.is_symlink()
        or lock_two.is_symlink()
        or not lock_one.is_file()
        or not lock_two.is_file()
    ):
        raise ReleaseInputError(
            f"canonical reviewed lock is missing: {relative_path}"
        )
    first_digest = sha256_file(lock_one)
    second_digest = sha256_file(lock_two)
    if first_digest != second_digest:
        raise ReleaseInputError(
            f"canonical lock differs across source archives: {relative_path}"
        )
    if first_digest != expected_digest:
        raise ReleaseInputError(
            f"canonical lock digest is not operator-approved: {relative_path}"
        )
    return lock_one, lock_two


def _build_once(
    source: Path,
    work: Path,
    *,
    podman_path: Path,
    podman_environment: dict[str, str],
    oci_runtime_path: Path,
    conmon_path: Path,
    hooks_directory: Path,
    podman_data_root: Path,
    podman_runtime_root: Path,
    build_image: str,
    build_lock: Path,
    runtime_lock: Path,
    build_wheelhouse: Path,
    runtime_wheelhouse: Path,
    expected_build_lock: str,
    expected_runtime_lock: str,
    expected_source_tree: str,
    source_date_epoch: str,
) -> tuple[Path, str]:
    output = work / "wheel"
    output.mkdir(parents=True, mode=0o700)
    for mounted_path in (
        source,
        build_lock,
        runtime_lock,
        build_wheelhouse,
        runtime_wheelhouse,
        output,
    ):
        if "," in str(mounted_path):
            raise ReleaseInputError(
                f"OCI mount path contains a comma: {mounted_path}"
            )

    completed = subprocess.run(
        [
            *_podman_command(
                podman_path,
                hooks_directory,
                podman_data_root,
                podman_runtime_root,
            ),
            "--runtime",
            str(oci_runtime_path),
            "--conmon",
            str(conmon_path),
            "run",
            "--rm",
            "--pull=never",
            "--platform=linux/amd64",
            "--network=none",
            "--read-only",
            "--userns=keep-id",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--mount",
            (
                f"type=bind,src={source},dst=/inputs/source,"
                "readonly,relabel=private"
            ),
            "--mount",
            (
                f"type=bind,src={build_lock},"
                "dst=/inputs/build-lock.txt,readonly,relabel=private"
            ),
            "--mount",
            (
                f"type=bind,src={runtime_lock},"
                "dst=/inputs/runtime-lock.txt,readonly,relabel=private"
            ),
            "--mount",
            (
                f"type=bind,src={build_wheelhouse},"
                "dst=/inputs/build-wheels,readonly,relabel=private"
            ),
            "--mount",
            (
                f"type=bind,src={runtime_wheelhouse},"
                "dst=/inputs/runtime-wheels,readonly,relabel=private"
            ),
            "--mount",
            (
                f"type=bind,src={output},dst=/output,"
                "relabel=private"
            ),
            "--tmpfs",
            "/work:rw,nosuid,nodev,exec,mode=1777",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,exec,mode=1777",
            "--env",
            f"SOURCE_DATE_EPOCH={source_date_epoch}",
            "--env",
            "PYTHONHASHSEED=0",
            "--env",
            "TZ=UTC",
            "--env",
            "LC_ALL=C.UTF-8",
            "--env",
            "LANG=C.UTF-8",
            "--entrypoint",
            "python3.11",
            build_image,
            "-c",
            CONTAINER_BOOTSTRAP,
            expected_source_tree,
            "--build-lock",
            "/inputs/build-lock.txt",
            "--runtime-lock",
            "/inputs/runtime-lock.txt",
            "--build-wheelhouse",
            "/inputs/build-wheels",
            "--runtime-wheelhouse",
            "/inputs/runtime-wheels",
            "--output",
            "/output",
            "--source-date-epoch",
            source_date_epoch,
            "--expected-build-lock-sha256",
            expected_build_lock,
            "--expected-runtime-lock-sha256",
            expected_runtime_lock,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=podman_environment,
    )

    result_lines = [
        line.removeprefix("SHARD_CORE_BUILD_RESULT=")
        for line in completed.stdout.splitlines()
        if line.startswith("SHARD_CORE_BUILD_RESULT=")
    ]
    if len(result_lines) != 1:
        raise ReleaseInputError(
            "isolated build emitted no unique container-reported result"
        )
    try:
        build_result = json.loads(result_lines[0])
        expected_filename = build_result["filename"]
        container_digest = build_result["sha256"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ReleaseInputError(
            "isolated build result is malformed"
        ) from exc
    if (
        not isinstance(expected_filename, str)
        or DIGEST.fullmatch(container_digest) is None
    ):
        raise ReleaseInputError("isolated build result fields are invalid")

    wheels = sorted(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ReleaseInputError(
            f"expected one project wheel, found {len(wheels)}"
        )
    if wheels[0].name != expected_filename:
        raise ReleaseInputError(
            "exported wheel filename differs from container result"
        )
    if sha256_file(wheels[0]) != container_digest:
        raise ReleaseInputError(
            "exported wheel digest differs from container result"
        )
    return wheels[0], container_digest


def _load_project(source: Path) -> tuple[str, str]:
    pyproject = tomllib.loads(
        (source / "pyproject.toml").read_text(encoding="utf-8")
    )
    try:
        project = pyproject["project"]
        return str(project["name"]), str(project["version"])
    except (KeyError, TypeError) as exc:
        raise ReleaseInputError(
            "pyproject.toml has no static project name and version"
        ) from exc


def _write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def _write_json(path: Path, value: object) -> None:
    _write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    )


def _checksums(bundle: Path) -> str:
    entries = [
        path
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    return "".join(
        f"{sha256_file(path)}  {path.relative_to(bundle).as_posix()}\n"
        for path in sorted(entries, key=lambda item: item.relative_to(bundle))
    )


def _publish_no_replace(source: Path, destination: Path) -> None:
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise ReleaseInputError(
            "Linux renameat2 is required for no-replace publication"
        )
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ReleaseInputError(
                f"refusing existing bundle path: {destination}"
            )
        raise OSError(
            error_number,
            os.strerror(error_number),
            str(destination),
        )


def main(argv: list[str] | None = None) -> int:
    if sys.version_info[:2] != (3, 11):
        raise ReleaseInputError(
            "the reviewed build environment requires exactly Python 3.11"
        )

    args = build_parser().parse_args(argv)
    expected_git = _approved_digest(
        args.expected_git_sha256,
        description="expected Git digest",
    )
    expected_python = _approved_digest(
        args.expected_python_sha256,
        description="expected orchestrator Python digest",
    )
    git_path = _approved_executable(
        args.git_path,
        expected_git,
        description="Git client",
    )
    python_path = _approved_executable(
        args.python_path,
        expected_python,
        description="orchestrator Python",
    )
    if Path(sys.executable).resolve(strict=True) != python_path:
        raise ReleaseInputError(
            "the running Python is not the approved orchestrator executable"
        )
    source_identity = _source_identity(
        git_path,
        args.expected_source_commit,
    )
    expected_runtime_lock = _approved_digest(
        args.expected_runtime_lock_sha256,
        description="expected runtime lock digest",
    )
    expected_build_lock = _approved_digest(
        args.expected_build_lock_sha256,
        description="expected build lock digest",
    )
    expected_build_image = _approved_digest(
        args.expected_build_image_digest,
        description="expected build image digest",
    )
    expected_podman = _approved_digest(
        args.expected_podman_sha256,
        description="expected Podman digest",
    )
    expected_oci_runtime = _approved_digest(
        args.expected_oci_runtime_sha256,
        description="expected OCI runtime digest",
    )
    expected_conmon = _approved_digest(
        args.expected_conmon_sha256,
        description="expected conmon digest",
    )
    expected_podman_config = _approved_digest(
        args.expected_podman_config_sha256,
        description="expected Podman configuration digest",
    )
    expected_platform_manifest = _approved_digest(
        args.expected_platform_manifest_digest,
        description="expected platform-manifest digest",
    )
    expected_image_config = _approved_digest(
        args.expected_image_config_digest,
        description="expected image-config digest",
    )
    build_environment, podman_environment = _inspect_build_environment(
        args.podman_path,
        args.empty_hooks_dir,
        args.build_image,
        expected_podman_digest=expected_podman,
        expected_oci_runtime_digest=expected_oci_runtime,
        expected_conmon_digest=expected_conmon,
        expected_repository_digest=expected_build_image,
        expected_platform_manifest_digest=expected_platform_manifest,
        expected_image_config_digest=expected_image_config,
        expected_uid=args.expected_ceremony_uid,
        expected_user=args.expected_ceremony_user,
        podman_config_root=args.podman_config_root,
        expected_podman_config_digest=expected_podman_config,
        podman_data_root=args.podman_data_root,
        podman_runtime_root=args.podman_runtime_root,
    )
    git_version = subprocess.run(
        [str(git_path), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    build_environment["git"] = {
        "path": str(git_path),
        "sha256": expected_git,
        "version": git_version,
    }
    build_environment["python"] = {
        "path": str(python_path),
        "sha256": expected_python,
        "version": platform.python_version(),
    }
    oci_runtime_record = build_environment["oci_runtime"]
    conmon_record = build_environment["conmon"]
    hooks_record = build_environment["hooks_directory"]
    if not all(
        isinstance(record, dict)
        for record in (oci_runtime_record, conmon_record, hooks_record)
    ):
        raise ReleaseInputError("invalid inspected Podman component record")
    oci_runtime_path = Path(str(oci_runtime_record["path"]))
    conmon_path = Path(str(conmon_record["path"]))
    hooks_directory = Path(str(hooks_record["path"]))
    runtime_wheelhouse = require_real_directory(
        args.runtime_wheelhouse,
        description="runtime wheelhouse",
    )
    build_wheelhouse = require_real_directory(
        args.build_wheelhouse,
        description="build wheelhouse",
    )
    output_parent = require_real_directory(
        args.output_parent,
        description="output parent",
    )
    output_stat = output_parent.stat()
    if output_stat.st_uid != os.getuid() or stat.S_IMODE(
        output_stat.st_mode
    ) != 0o700:
        raise ReleaseInputError(
            "output parent must be owned by the current user and mode 0700"
        )
    # Retain the descriptor for the process lifetime so the lock stays held.
    _ceremony_lock_fd = _acquire_ceremony_lock(output_parent)

    archive_one = _git_archive(git_path, source_identity["commit"])
    archive_two = _git_archive(git_path, source_identity["commit"])
    if archive_one != archive_two:
        raise ReleaseInputError(
            "two source archives from the reviewed commit differ"
        )
    archive_sha256 = sha256_bytes(archive_one)

    with tempfile.TemporaryDirectory(
        prefix=".shard-core-release-",
        dir=output_parent,
    ) as temporary_name:
        temporary = Path(temporary_name)
        source_one = temporary / "source-one"
        source_two = temporary / "source-two"
        _extract_archive(archive_one, source_one)
        _extract_archive(archive_two, source_two)

        runtime_lock_one, runtime_lock_two = _bind_archived_lock(
            source_one,
            source_two,
            RUNTIME_LOCK_RELATIVE,
            expected_runtime_lock,
        )
        build_lock_one, build_lock_two = _bind_archived_lock(
            source_one,
            source_two,
            BUILD_LOCK_RELATIVE,
            expected_build_lock,
        )
        runtime_wheelhouse_one = _snapshot_wheelhouse(
            runtime_wheelhouse,
            temporary / "build-one-runtime-wheels",
        )
        runtime_wheelhouse_two = _snapshot_wheelhouse(
            runtime_wheelhouse,
            temporary / "build-two-runtime-wheels",
        )
        build_wheelhouse_one = _snapshot_wheelhouse(
            build_wheelhouse,
            temporary / "build-one-build-wheels",
        )
        build_wheelhouse_two = _snapshot_wheelhouse(
            build_wheelhouse,
            temporary / "build-two-build-wheels",
        )
        runtime_records_one = verify_wheelhouse(
            runtime_lock_one,
            runtime_wheelhouse_one,
            target=RUNTIME_TARGET,
        )
        runtime_records_two = verify_wheelhouse(
            runtime_lock_two,
            runtime_wheelhouse_two,
            target=RUNTIME_TARGET,
        )
        build_records_one = verify_wheelhouse(
            build_lock_one,
            build_wheelhouse_one,
            target=BUILD_TARGET,
        )
        build_records_two = verify_wheelhouse(
            build_lock_two,
            build_wheelhouse_two,
            target=BUILD_TARGET,
        )
        if _record_identity(runtime_records_one) != _record_identity(
            runtime_records_two
        ):
            raise ReleaseInputError(
                "independent runtime-wheel snapshots differ"
            )
        if _record_identity(build_records_one) != _record_identity(
            build_records_two
        ):
            raise ReleaseInputError(
                "independent build-wheel snapshots differ"
            )
        source_tree_one = _tree_digest(source_one)
        source_tree_two = _tree_digest(source_two)
        if source_tree_one != source_tree_two:
            raise ReleaseInputError("independent source snapshots differ")

        project_name, project_version = _load_project(source_one)
        if _load_project(source_two) != (project_name, project_version):
            raise ReleaseInputError("source archive project metadata differs")

        bundle_name = (
            f"UNAPPROVED-CANDIDATE-{project_name}-{project_version}-offline-"
            f"cp39-abi3-manylinux_2_17_x86_64"
        )
        final_bundle = output_parent / bundle_name
        if final_bundle.is_symlink() or final_bundle.exists():
            raise ReleaseInputError(
                f"refusing existing bundle path: {final_bundle}"
            )

        wheel_one, wheel_one_container_digest = _build_once(
            source_one,
            temporary / "build-one",
            podman_path=args.podman_path,
            podman_environment=podman_environment,
            oci_runtime_path=oci_runtime_path,
            conmon_path=conmon_path,
            hooks_directory=hooks_directory,
            podman_data_root=args.podman_data_root,
            podman_runtime_root=args.podman_runtime_root,
            build_image=args.build_image,
            build_lock=build_lock_one,
            runtime_lock=runtime_lock_one,
            build_wheelhouse=build_wheelhouse_one,
            runtime_wheelhouse=runtime_wheelhouse_one,
            expected_build_lock=expected_build_lock,
            expected_runtime_lock=expected_runtime_lock,
            expected_source_tree=source_tree_one,
            source_date_epoch=source_identity["commit_timestamp"],
        )
        wheel_two, wheel_two_container_digest = _build_once(
            source_two,
            temporary / "build-two",
            podman_path=args.podman_path,
            podman_environment=podman_environment,
            oci_runtime_path=oci_runtime_path,
            conmon_path=conmon_path,
            hooks_directory=hooks_directory,
            podman_data_root=args.podman_data_root,
            podman_runtime_root=args.podman_runtime_root,
            build_image=args.build_image,
            build_lock=build_lock_two,
            runtime_lock=runtime_lock_two,
            build_wheelhouse=build_wheelhouse_two,
            runtime_wheelhouse=runtime_wheelhouse_two,
            expected_build_lock=expected_build_lock,
            expected_runtime_lock=expected_runtime_lock,
            expected_source_tree=source_tree_two,
            source_date_epoch=source_identity["commit_timestamp"],
        )
        if sha256_file(build_lock_one) != expected_build_lock:
            raise ReleaseInputError("first build lock changed during build")
        if sha256_file(build_lock_two) != expected_build_lock:
            raise ReleaseInputError("second build lock changed during build")
        if sha256_file(runtime_lock_one) != expected_runtime_lock:
            raise ReleaseInputError("first runtime lock changed during build")
        if sha256_file(runtime_lock_two) != expected_runtime_lock:
            raise ReleaseInputError("second runtime lock changed during build")
        if _record_identity(
            verify_wheelhouse(
                build_lock_one,
                build_wheelhouse_one,
                target=BUILD_TARGET,
            )
        ) != _record_identity(build_records_one):
            raise ReleaseInputError("first build wheelhouse changed")
        if _record_identity(
            verify_wheelhouse(
                build_lock_two,
                build_wheelhouse_two,
                target=BUILD_TARGET,
            )
        ) != _record_identity(build_records_two):
            raise ReleaseInputError("second build wheelhouse changed")
        if _record_identity(
            verify_wheelhouse(
                runtime_lock_one,
                runtime_wheelhouse_one,
                target=RUNTIME_TARGET,
            )
        ) != _record_identity(runtime_records_one):
            raise ReleaseInputError("first runtime wheelhouse changed")
        if _record_identity(
            verify_wheelhouse(
                runtime_lock_two,
                runtime_wheelhouse_two,
                target=RUNTIME_TARGET,
            )
        ) != _record_identity(runtime_records_two):
            raise ReleaseInputError("second runtime wheelhouse changed")
        if (
            _tree_digest(source_one) != source_tree_one
            or _tree_digest(source_two) != source_tree_two
        ):
            raise ReleaseInputError("source snapshot changed during build")
        if (
            _source_identity(git_path, args.expected_source_commit)
            != source_identity
        ):
            raise ReleaseInputError("reviewed repository changed during build")
        _assert_build_environment_unchanged(
            build_environment,
            podman_environment,
        )

        runtime_records = runtime_records_one
        build_records = build_records_one
        runtime_lock = runtime_lock_one
        build_lock = build_lock_one
        wheel_one_bytes = wheel_one.read_bytes()
        wheel_two_bytes = wheel_two.read_bytes()
        if sha256_bytes(wheel_one_bytes) != wheel_one_container_digest:
            raise ReleaseInputError(
                "first wheel changed after isolated export"
            )
        if sha256_bytes(wheel_two_bytes) != wheel_two_container_digest:
            raise ReleaseInputError(
                "second wheel changed after isolated export"
            )
        if wheel_one_bytes != wheel_two_bytes:
            raise ReleaseInputError(
                "two clean builds produced different project wheel bytes"
            )

        project_record = inspect_wheel(wheel_one)
        if (
            project_record.normalized_name
            != re.sub(r"[-_.]+", "-", project_name).lower()
            or project_record.version != project_version
        ):
            raise ReleaseInputError(
                "built wheel identity differs from pyproject.toml"
            )
        if not wheel_supports_target(project_record, RUNTIME_TARGET):
            raise ReleaseInputError(
                "built project wheel is incompatible with bundle target"
            )
        runtime_names = {
            record.normalized_name for record in runtime_records
        }
        runtime_filenames = {record.path.name for record in runtime_records}
        if project_record.normalized_name in runtime_names:
            raise ReleaseInputError(
                "runtime lock must not contain the project wheel"
            )
        if project_record.path.name in runtime_filenames:
            raise ReleaseInputError(
                "project wheel filename collides with a runtime wheel"
            )

        bundle = temporary / "bundle"
        wheels = bundle / "wheels"
        wheels.mkdir(parents=True, mode=0o700)
        for record in runtime_records:
            _copy_exclusive(record.path, wheels / record.path.name)

        bundled_runtime_records = verify_wheelhouse(
            runtime_lock,
            wheels,
            target=RUNTIME_TARGET,
        )
        expected_runtime = {
            (record.normalized_name, record.version, record.sha256)
            for record in runtime_records
        }
        actual_runtime = {
            (record.normalized_name, record.version, record.sha256)
            for record in bundled_runtime_records
        }
        if actual_runtime != expected_runtime:
            raise ReleaseInputError(
                "bundled runtime wheels differ from verified staged inputs"
            )

        _copy_exclusive(wheel_one, wheels / wheel_one.name)

        final_records = tuple(
            inspect_wheel(path)
            for path in sorted(wheels.glob("*.whl"))
        )
        validate_unique_inventory(final_records)
        expected_final = expected_runtime | {
            (
                project_record.normalized_name,
                project_record.version,
                project_record.sha256,
            )
        }
        actual_final = {
            (record.normalized_name, record.version, record.sha256)
            for record in final_records
        }
        if actual_final != expected_final:
            raise ReleaseInputError(
                "final wheel inventory differs from reviewed inputs and "
                "the reproducible project wheel"
            )
        _write_text(
            bundle / "requirements-linux-x86_64.txt",
            render_hashed_requirements(final_records),
        )
        _write_json(
            bundle / "WHEELHOUSE.json",
            inventory_document(
                final_records,
                schema="shard-core-wheelhouse-v1",
                target=RUNTIME_TARGET,
            ),
        )
        _write_json(
            bundle / "BUNDLE-METADATA.json",
            {
                "schema": "shard-core-bundle-metadata-v1",
                "bundle_name": bundle_name,
                "release_status": "unapproved_candidate",
                "project": {
                    "name": project_record.name,
                    "version": project_record.version,
                    "wheel_tags": list(project_record.tags),
                },
                "target": {
                    **RUNTIME_TARGET.as_dict(),
                    "operating_system": "Linux",
                    "architecture": "x86_64",
                    "validated_cpython": "3.9",
                    "project_requires_python": (
                        project_record.requires_python
                    ),
                    "libc": "glibc >= 2.17",
                },
            },
        )

        scripts = (
            ROOT / "scripts" / "build-offline-bundle.py",
            ROOT / "scripts" / "container-build-wheel.py",
            ROOT / "scripts" / "fetch-reviewed-wheels.py",
            ROOT / "scripts" / "release_support.py",
            ROOT / "scripts" / "validate-release-wheels.py",
        )
        _write_json(
            bundle / "PROVENANCE.json",
            {
                "schema": "shard-core-provenance-v1",
                "release_status": "unapproved_candidate",
                "source": {
                    **source_identity,
                    "archive_sha256": archive_sha256,
                },
                "inputs": {
                    "runtime_lock_sha256": sha256_file(runtime_lock),
                    "build_lock_sha256": sha256_file(build_lock),
                    "runtime_wheels": [
                        record.as_dict() for record in runtime_records
                    ],
                    "build_wheels": [
                        record.as_dict() for record in build_records
                    ],
                    "release_scripts": {
                        path.relative_to(ROOT).as_posix(): sha256_file(path)
                        for path in scripts
                    },
                },
                "build_environment": {
                    "orchestrator_python": platform.python_version(),
                    "orchestrator_platform": platform.platform(),
                    "orchestrator_machine": platform.machine(),
                    "orchestrator_libc": list(platform.libc_ver()),
                    "rootless_podman": build_environment,
                    "deterministic_environment": {
                        **DETERMINISTIC_ENVIRONMENT,
                        "SOURCE_DATE_EPOCH": source_identity[
                            "commit_timestamp"
                        ],
                    },
                    "network_policy": "OCI network namespace set to none",
                    "root_filesystem": "read-only",
                    "input_mounts": "read-only",
                    "image_pull_policy": "never",
                    "platform": "linux/amd64",
                    "user_namespace": "keep-id",
                    "ceremony_lock": "exclusive advisory lock held",
                },
                "result": {
                    "wheel_filename": project_record.path.name,
                    "wheel_sha256": sha256_bytes(wheel_one_bytes),
                    "second_build_wheel_sha256": sha256_bytes(
                        wheel_two_bytes
                    ),
                    "first_container_emitted_sha256": (
                        wheel_one_container_digest
                    ),
                    "second_container_emitted_sha256": (
                        wheel_two_container_digest
                    ),
                    "two_local_builds_identical": True,
                    "independent_reproducibility_verified": False,
                },
            },
        )
        _write_text(
            bundle / "UNAPPROVED-CANDIDATE.txt",
            (
                "UNAPPROVED CANDIDATE\n\n"
                "This directory is not a production ceremony bundle and "
                "contains no installer. It requires independent review, "
                "producer authentication, and an authenticated promotion "
                "step before operational use.\n"
            ),
        )
        _write_text(bundle / "SHA256SUMS", _checksums(bundle))
        _publish_no_replace(bundle, final_bundle)

    print(f"built deterministic candidate bundle: {final_bundle}")
    print(f"source commit: {source_identity['commit']}")
    print("producer authentication and independent approval remain required")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseInputError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
