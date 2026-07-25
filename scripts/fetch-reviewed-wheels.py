#!/usr/bin/env python3
"""Fetch only wheels authorized by a pre-existing reviewed hash lock."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from release_support import (
    ReleaseInputError,
    WheelTarget,
    atomic_write_json,
    inventory_document,
    require_regular_file,
    sha256_file,
    verify_wheelhouse,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch binary wheels matching an independently reviewed hash "
            "lock. This command never creates or updates the lock."
        )
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--abi", required=True)
    return parser


def _download_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    lock = require_regular_file(args.lock, description="hash lock")
    destination = args.destination.absolute()
    receipt = args.receipt.absolute()
    target = WheelTarget(
        implementation=args.implementation,
        python_version=args.python_version,
        abi=args.abi,
        platform=args.platform,
    )

    if destination.is_symlink() or destination.exists():
        raise ReleaseInputError(
            f"refusing existing wheel destination: {destination}"
        )
    if receipt.is_symlink() or receipt.exists():
        raise ReleaseInputError(f"refusing existing receipt: {receipt}")
    try:
        receipt.relative_to(destination)
    except ValueError:
        pass
    else:
        raise ReleaseInputError(
            "receipt must be outside the wheel-only destination"
        )

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.mkdir(mode=0o700)
    succeeded = False
    try:
        command = [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--no-input",
            "--only-binary=:all:",
            "--require-hashes",
            "--dest",
            str(destination),
            "--platform",
            target.platform,
            "--python-version",
            target.python_version,
            "--implementation",
            target.implementation,
            "--abi",
            target.abi,
            "-r",
            str(lock),
        ]
        subprocess.run(
            command,
            check=True,
            env=_download_environment(),
        )

        records = verify_wheelhouse(
            lock,
            destination,
            target=target,
        )
        receipt_document = inventory_document(
            records,
            schema="shard-core-fetch-receipt-v1",
            target=target,
        )
        receipt_document["lock"] = {
            "path": str(lock),
            "sha256": sha256_file(lock),
        }
        receipt_document["trust_semantics"] = (
            "The lock hashes were inputs. This receipt records fetched "
            "artifacts and does not approve or replace those hashes."
        )
        atomic_write_json(receipt, receipt_document)
        succeeded = True
    finally:
        if not succeeded:
            shutil.rmtree(destination, ignore_errors=True)

    print(f"fetched {len(records)} reviewed wheels into {destination}")
    print(f"receipt: {receipt}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseInputError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
