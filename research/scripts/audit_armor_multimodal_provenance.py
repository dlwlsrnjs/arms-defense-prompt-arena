#!/usr/bin/env python3
"""Audit ARMOR Stage-0 multimodal judge provenance without changing results."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_multimodal_audit import (
    audit_prepared_multimodal_provenance,
    write_multimodal_audit_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepared",
        required=True,
        type=Path,
        help="prepared ARMOR Stage-0 directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional separate JSON report path; stdout is always emitted",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = audit_prepared_multimodal_provenance(args.prepared)
    if args.output is not None:
        write_multimodal_audit_report(
            args.output,
            report,
            prepared_root=args.prepared,
        )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
