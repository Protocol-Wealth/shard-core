#!/usr/bin/env python3
"""Validate an exact stable tag against PEP 440 project metadata."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

from packaging.version import InvalidVersion, Version


STABLE_TAG = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
PROJECT_VERSION = re.compile(
    r'^\s*version\s*=\s*"([^"]+)"\s*(?:#.*)?$'
)


def read_project_version(pyproject: Path) -> str:
    in_project = False
    versions: list[str] = []

    for line in pyproject.read_text(encoding="utf-8").splitlines():
        section = SECTION.fullmatch(line)
        if section is not None:
            in_project = section.group(1).strip() == "project"
            continue

        if not in_project:
            continue

        match = PROJECT_VERSION.fullmatch(line)
        if match is not None:
            versions.append(match.group(1))

    if len(versions) != 1:
        raise ValueError(
            "pyproject [project] must contain exactly one literal version"
        )

    return versions[0]


def validate(tag: str, pyproject: Path) -> str:
    if STABLE_TAG.fullmatch(tag) is None:
        raise ValueError("stable tag must exactly match vX.Y.Z")

    raw_version = read_project_version(pyproject)

    try:
        version = Version(raw_version)
    except InvalidVersion as exc:
        raise ValueError("project version is not valid PEP 440") from exc

    if (
        len(version.release) != 3
        or version.is_prerelease
        or version.is_devrelease
        or version.is_postrelease
        or version.local is not None
    ):
        raise ValueError("project version must be a final X.Y.Z release")

    normalized = ".".join(str(component) for component in version.release)
    if raw_version != normalized:
        raise ValueError("project version must use canonical X.Y.Z spelling")
    if tag != f"v{normalized}":
        raise ValueError("tag does not match project version")

    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--pyproject", required=True, type=Path)
    args = parser.parse_args()

    try:
        version = validate(args.tag, args.pyproject)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
