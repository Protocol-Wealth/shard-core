#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _locked_packages(path: Path, purpose: str) -> list[dict[str, object]]:
    packages: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name_version = line.split(" --hash=", 1)[0]
        name, version = name_version.split("==", 1)
        spdx_name = name.replace("-", "-")
        packages.append(
            {
                "name": name,
                "SPDXID": f"SPDXRef-{purpose}-{spdx_name}",
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "primaryPackagePurpose": purpose,
                "comment": f"Hash-locked via {path.name}",
            }
        )
    return packages


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle-name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-rev", required=True)
    parser.add_argument("--source-describe", required=True)
    parser.add_argument("--source-archive-sha256", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--build-lock", type=Path, required=True)
    args = parser.parse_args()

    shard_core = {
        "name": "shard-core",
        "SPDXID": "SPDXRef-APPLICATION-shard-core",
        "versionInfo": args.version,
        "downloadLocation": (
            "git+https://github.com/Protocol-Wealth/shard-core@"
            f"{args.source_rev}"
        ),
        "filesAnalyzed": False,
        "primaryPackagePurpose": "APPLICATION",
        "sourceInfo": (
            f"commit {args.source_rev} ({args.source_describe}); "
            f"git archive sha256 {args.source_archive_sha256}"
        ),
        "comment": "Built from an archived reviewed commit; see BUILD_INFO.txt",
    }
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": args.bundle_name,
        "documentNamespace": (
            "https://github.com/Protocol-Wealth/shard-core/offline/"
            f"{args.bundle_name}"
        ),
        "creationInfo": {
            "created": args.created,
            "creators": [
                "Tool: scripts/render-release-sbom.py",
                "Organization: Protocol Wealth LLC",
            ],
        },
        "packages": [
            shard_core,
            *_locked_packages(args.runtime_lock, "LIBRARY"),
            *_locked_packages(args.build_lock, "BUILD_TOOL"),
        ],
    }
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
