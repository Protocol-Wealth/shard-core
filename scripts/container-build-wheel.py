#!/usr/bin/env python3
"""Container entrypoint for one isolated shard-core wheel build."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BUILD_PYTHON_TARGET = {
    "implementation": "cp",
    "python_version": "3.11",
    "abi": "none",
    "platform": "manylinux_2_17_x86_64",
}
RUNTIME_PYTHON_TARGET = {
    "implementation": "cp",
    "python_version": "3.9",
    "abi": "abi3",
    "platform": "manylinux_2_17_x86_64",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--build-lock", required=True, type=Path)
    parser.add_argument("--runtime-lock", required=True, type=Path)
    parser.add_argument("--build-wheelhouse", required=True, type=Path)
    parser.add_argument("--runtime-wheelhouse", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True)
    parser.add_argument("--expected-build-lock-sha256", required=True)
    parser.add_argument("--expected-runtime-lock-sha256", required=True)
    return parser


def _require_read_only(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"missing container input: {path}")
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise ValueError(f"container input is not read-only: {path}")


def _require_isolation() -> None:
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise ValueError("container root filesystem is not read-only")
    interfaces = {path.name for path in Path("/sys/class/net").iterdir()}
    if interfaces != {"lo"}:
        raise ValueError(
            f"container network is not isolated; interfaces={interfaces}"
        )


def _environment(source_date_epoch: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": "/work/home",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "SOURCE_DATE_EPOCH": source_date_epoch,
            "TZ": "UTC",
        }
    )
    return environment


def main(argv: list[str] | None = None) -> int:
    from release_support import (
        WheelTarget,
        sha256_file,
        verify_wheelhouse,
    )

    args = build_parser().parse_args(argv)
    _require_isolation()
    for path in (
        Path("/inputs/source"),
        args.build_lock,
        args.runtime_lock,
        args.build_wheelhouse,
        args.runtime_wheelhouse,
    ):
        _require_read_only(path)

    work = Path("/work")
    home = work / "home"
    virtualenv = work / "venv"
    build_lock = work / "build-lock.txt"
    runtime_lock = work / "runtime-lock.txt"
    build_wheelhouse = work / "build-wheels"
    runtime_wheelhouse = work / "runtime-wheels"
    private_output = work / "output"
    home.mkdir(mode=0o700)
    shutil.copy2(args.build_lock, build_lock)
    shutil.copy2(args.runtime_lock, runtime_lock)
    shutil.copytree(args.build_wheelhouse, build_wheelhouse)
    shutil.copytree(args.runtime_wheelhouse, runtime_wheelhouse)
    private_output.mkdir(mode=0o700)

    if sha256_file(build_lock) != args.expected_build_lock_sha256:
        raise ValueError("private build-lock copy has an unapproved digest")
    if sha256_file(runtime_lock) != args.expected_runtime_lock_sha256:
        raise ValueError("private runtime-lock copy has an unapproved digest")
    verify_wheelhouse(
        build_lock,
        build_wheelhouse,
        target=WheelTarget(**BUILD_PYTHON_TARGET),
    )
    verify_wheelhouse(
        runtime_lock,
        runtime_wheelhouse,
        target=WheelTarget(**RUNTIME_PYTHON_TARGET),
    )
    environment = _environment(args.source_date_epoch)

    subprocess.run(
        [sys.executable, "-m", "venv", str(virtualenv)],
        check=True,
        env=environment,
    )
    python = virtualenv / "bin" / "python"
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(build_wheelhouse),
            "--require-hashes",
            "-r",
            str(build_lock),
        ],
        check=True,
        env=environment,
    )
    subprocess.run(
        [
            str(python),
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(private_output),
            str(args.source),
        ],
        check=True,
        env=environment,
    )

    wheels = sorted(private_output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError(
            f"expected one project wheel, found {len(wheels)}"
        )
    subprocess.run(
        [
            str(python),
            str(args.source / "scripts" / "validate-release-wheels.py"),
            "--runtime-wheelhouse",
            str(runtime_wheelhouse),
            "--project-wheel",
            str(wheels[0]),
            "--python-version",
            "3.9",
            "--project-extra",
            "slip39",
        ],
        check=True,
        env=environment,
    )
    output_wheel = args.output / wheels[0].name
    with wheels[0].open("rb") as input_stream, output_wheel.open(
        "xb"
    ) as output_stream:
        shutil.copyfileobj(input_stream, output_stream)
        output_stream.flush()
        os.fsync(output_stream.fileno())
    result = {
        "filename": output_wheel.name,
        "sha256": sha256_file(wheels[0]),
    }
    print(f"SHARD_CORE_BUILD_RESULT={json.dumps(result, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
