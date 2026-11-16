#!/usr/bin/env python3
"""Verify a payload-free attack-memory audit pack without private sources."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path}: expected a JSON object")
    return value


def _csv_count(path: Path) -> int:
    with path.open(newline="", encoding="utf-8") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def _verify_event_chain(path: Path) -> int:
    previous: str | None = None
    count = 0
    with path.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            event = json.loads(line)
            if not isinstance(event, dict):
                raise TypeError(f"{path}:{index + 1}: expected a JSON object")
            if event.get("event_index") != index:
                raise ValueError(f"{path}:{index + 1}: event index mismatch")
            if event.get("previous_event_sha256") != previous:
                raise ValueError(f"{path}:{index + 1}: predecessor mismatch")
            unsigned = dict(event)
            claimed = unsigned.pop("event_sha256", None)
            actual = hashlib.sha256(canonical_json(unsigned)).hexdigest()
            if claimed != actual:
                raise ValueError(f"{path}:{index + 1}: event hash mismatch")
            previous = str(claimed)
            count += 1
    return count


def _record_count(path: Path, relative: str) -> int:
    if path.suffix == ".csv":
        return _csv_count(path)
    if path.suffix == ".jsonl":
        return _verify_event_chain(path)
    if relative == "json/memory_flow.json":
        value = _load_object(path)
        episodes = value.get("episodes")
        if not isinstance(episodes, list):
            raise TypeError(f"{path}: episodes must be an array")
        return len(episodes)
    return 1


def verify_pack(pack: Path) -> dict[str, Any]:
    root = pack.resolve()
    manifest = _load_object(root / "manifest.json")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise TypeError("manifest.artifacts must be a non-empty object")

    checked: dict[str, dict[str, Any]] = {}
    for relative, raw_metadata in sorted(artifacts.items()):
        if not isinstance(relative, str) or not isinstance(raw_metadata, Mapping):
            raise TypeError("manifest artifact entries must be path/object pairs")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError(f"unsafe artifact path: {relative}")
        path = root / relative_path
        if not path.is_file():
            raise FileNotFoundError(path)
        actual_sha = sha256_file(path)
        actual_bytes = path.stat().st_size
        actual_records = _record_count(path, relative)
        if actual_sha != raw_metadata.get("sha256"):
            raise ValueError(f"{relative}: SHA-256 mismatch")
        if actual_bytes != raw_metadata.get("bytes"):
            raise ValueError(f"{relative}: byte-size mismatch")
        if actual_records != raw_metadata.get("records"):
            raise ValueError(f"{relative}: record-count mismatch")
        checked[relative] = {
            "sha256": actual_sha,
            "bytes": actual_bytes,
            "records": actual_records,
        }

    summary = _load_object(root / "json" / "collection_summary.json")
    flow = _load_object(root / "json" / "memory_flow.json")
    counts = summary.get("counts")
    if not isinstance(counts, Mapping):
        raise TypeError("collection_summary.counts must be an object")
    expected = {
        "csv/episodes.csv": counts.get("episodes"),
        "csv/retrievals.csv": counts.get("retrieval_label_records"),
        "csv/queries.csv": counts.get("target_query_records"),
        "csv/transitions.csv": counts.get("query_to_query_transitions"),
        "csv/memory_updates.csv": counts.get("episodes"),
        "csv/final_slots.csv": counts.get("final_memory_slots"),
        "json/memory_flow.json": counts.get("episodes"),
        "jsonl/memory_flow.jsonl": counts.get("event_ledger_records"),
    }
    for relative, expected_records in expected.items():
        if checked[relative]["records"] != expected_records:
            raise ValueError(f"{relative}: summary count mismatch")
    if flow.get("summary") != summary:
        raise ValueError("memory_flow.summary does not match collection_summary.json")
    final_slots = flow.get("final_slots")
    if not isinstance(final_slots, list) or len(final_slots) != counts.get(
        "final_memory_slots"
    ):
        raise ValueError("memory_flow final-slot count mismatch")
    if summary.get("raw_attack_payload_included") is not False:
        raise ValueError("pack does not declare itself payload-free")
    verification = summary.get("verification")
    if not isinstance(verification, Mapping) or verification.get(
        "payload_leakage_gate"
    ) != "passed":
        raise ValueError("export-time payload leakage gate is not attested as passed")

    return {
        "pack": str(root),
        "schema_version": manifest.get("schema_version"),
        "artifacts_verified": len(checked),
        "event_hash_chain_valid": True,
        "cross_format_counts_valid": True,
        "export_time_payload_leakage_gate": "passed",
        "private_source_content_rechecked": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    print(json.dumps(verify_pack(args.pack), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
