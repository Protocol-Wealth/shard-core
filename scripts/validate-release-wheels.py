#!/usr/bin/env python3
"""Validate release-wheel compatibility using the reviewed packaging wheel."""

from __future__ import annotations

import argparse
from collections import deque
import re
import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from release_support import (
    ReleaseInputError,
    inspect_wheel,
    normalize_name,
    validate_unique_inventory,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-wheelhouse", required=True, type=Path)
    parser.add_argument("--project-wheel", required=True, type=Path)
    parser.add_argument("--python-version", required=True)
    parser.add_argument(
        "--project-extra",
        action="append",
        default=[],
    )
    return parser


def _target_environment(python_version: str) -> dict[str, str]:
    parts = python_version.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ReleaseInputError(
            f"target Python must be major.minor: {python_version}"
        )
    return {
        "implementation_name": "cpython",
        "implementation_version": f"{python_version}.0",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "platform_python_implementation": "CPython",
        "platform_release": "",
        "platform_system": "Linux",
        "platform_version": "",
        "python_full_version": f"{python_version}.0",
        "python_version": python_version,
        "sys_platform": "linux",
        "extra": "",
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runtime_paths = sorted(args.runtime_wheelhouse.glob("*.whl"))
    if not runtime_paths:
        raise ReleaseInputError("runtime wheelhouse is empty")

    project_record = inspect_wheel(args.project_wheel)
    records = tuple(inspect_wheel(path) for path in runtime_paths) + (
        project_record,
    )
    validate_unique_inventory(records)
    by_name = {record.normalized_name: record for record in records}
    environment = _target_environment(args.python_version)
    target_python = Version(f"{args.python_version}.0")

    for record in records:
        if record.requires_python:
            try:
                supports_python = target_python in SpecifierSet(
                    record.requires_python
                )
            except InvalidSpecifier as exc:
                raise ReleaseInputError(
                    f"invalid Requires-Python for {record.name}: "
                    f"{record.requires_python}"
                ) from exc
            if not supports_python:
                raise ReleaseInputError(
                    f"{record.name} does not support Python "
                    f"{args.python_version}: {record.requires_python}"
                )

    work: deque[tuple[str, str]] = deque(
        (record.normalized_name, "") for record in records
    )
    declared_project_extras = {
        normalize_name(extra) for extra in project_record.provides_extra
    }
    for requested_extra in args.project_extra:
        normalized_extra = normalize_name(requested_extra)
        if normalized_extra not in declared_project_extras:
            raise ReleaseInputError(
                f"project does not declare requested extra: "
                f"{requested_extra}"
            )
        work.append((project_record.normalized_name, normalized_extra))
    processed: set[tuple[str, str]] = set()
    while work:
        record_name, active_extra = work.popleft()
        if (record_name, active_extra) in processed:
            continue
        processed.add((record_name, active_extra))
        record = by_name[record_name]
        marker_environment = {
            **environment,
            "extra": active_extra,
        }

        for requirement_text in record.requires_dist:
            try:
                requirement = Requirement(requirement_text)
            except InvalidRequirement as exc:
                raise ReleaseInputError(
                    f"invalid Requires-Dist for {record.name}: "
                    f"{requirement_text}"
                ) from exc
            if requirement.url is not None:
                raise ReleaseInputError(
                    f"direct-URL dependency is forbidden for {record.name}: "
                    f"{requirement_text}"
                )
            if requirement.marker is not None:
                marker_text = str(requirement.marker)
                if re.search(
                    r"\b(platform_release|platform_version)\b",
                    marker_text,
                ):
                    raise ReleaseInputError(
                        f"marker uses an unapproved target field for "
                        f"{record.name}: {requirement_text}"
                    )
                if not requirement.marker.evaluate(
                    environment=marker_environment
                ):
                    continue

            dependency = by_name.get(normalize_name(requirement.name))
            if dependency is None:
                raise ReleaseInputError(
                    f"missing runtime dependency for {record.name}: "
                    f"{requirement.name}"
                )
            try:
                dependency_version = Version(dependency.version)
            except InvalidVersion as exc:
                raise ReleaseInputError(
                    f"invalid dependency version: {dependency.version}"
                ) from exc
            if dependency_version not in requirement.specifier:
                raise ReleaseInputError(
                    f"runtime dependency version does not satisfy "
                    f"{record.name}: {requirement_text}"
                )
            declared_dependency_extras = {
                normalize_name(extra)
                for extra in dependency.provides_extra
            }
            for requested_extra in requirement.extras:
                normalized_extra = normalize_name(requested_extra)
                if normalized_extra not in declared_dependency_extras:
                    raise ReleaseInputError(
                        f"{dependency.name} does not declare requested "
                        f"extra: {requested_extra}"
                    )
                work.append(
                    (
                        dependency.normalized_name,
                        normalized_extra,
                    )
                )

    print(
        f"validated {len(records)} wheels for CPython "
        f"{args.python_version} on Linux x86_64"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
