"""Non-secret inventory manifests for SHRD custody artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Sequence

from . import __version__, core

SCHEMA = "shard-core-manifest-v1"


def build_shrd_manifest(
    shard_b64_list: Sequence[str],
    *,
    labels: Sequence[str],
    filenames: Sequence[str],
    file_contents: Sequence[bytes],
    git_commit: str = "unknown",
) -> dict:
    """Build an inventory manifest without hashing or describing plaintext."""
    count = len(shard_b64_list)
    if not (
        count
        == len(labels)
        == len(filenames)
        == len(file_contents)
    ):
        raise ValueError("manifest inputs must have equal lengths")
    if not count:
        raise ValueError("cannot build a manifest for an empty shard set")

    parsed = [core.parse_shard(shard) for shard in shard_b64_list]
    set_ids = {core.protect_set_id(shard) for shard in parsed}
    if len(set_ids) != 1:
        raise ValueError("manifest inputs are from different protect sets")

    reference = parsed[0]
    entries = []
    seen_indices: set[int] = set()
    for shard_b64, metadata, label, filename, content in zip(
        shard_b64_list,
        parsed,
        labels,
        filenames,
        file_contents,
    ):
        index = metadata["index"]
        if index in seen_indices:
            raise ValueError(f"duplicate manifest share index {index}")
        seen_indices.add(index)
        decoded = base64.b64decode(shard_b64, validate=True)
        entries.append({
            "index": index,
            "holder_label": label,
            "label_authenticated": False,
            "filename": Path(filename).name,
            "file_sha256": hashlib.sha256(content).hexdigest(),
            "decoded_payload_sha256": hashlib.sha256(decoded).hexdigest(),
        })

    entries.sort(key=lambda entry: entry["index"])
    return {
        "schema": SCHEMA,
        "artifact_type": "SHRD",
        "format_version": reference["version"],
        "set_id": next(iter(set_ids)),
        "threshold": reference["threshold"],
        "declared_total": reference["shares"],
        "created_with": {
            "shard_core_version": __version__,
            "git_commit": git_commit or "unknown",
        },
        "shares": entries,
    }


def dumps(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
