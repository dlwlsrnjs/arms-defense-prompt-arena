#!/usr/bin/env python3
"""Build an integrity-checked, exact-token ARMOR Stage-0 comparison pack.

This command is CPU/tokenizer-only: it performs no model inference and starts
no GPU or vLLM server.  ``--help`` does not import Transformers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_token_match import (
    CandidateIntegrityError,
    ExactTokenMatchError,
    select_exact_token_prompts,
    verify_candidate_manifest,
    write_selection_pack,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _tokenizer_artifact_sha256(source: Path) -> str | None:
    records = []
    for filename in (
        "added_tokens.json",
        "chat_template.jinja",
        "merges.txt",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer.model",
        "tokenizer_config.json",
        "vocab.json",
    ):
        path = source / filename
        if path.is_file():
            records.append(
                {
                    "filename": filename,
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    if not records:
        return None
    return hashlib.sha256(_canonical_json({"files": records}).encode("utf-8")).hexdigest()


def _load_qwen_tokenizer(
    source: str,
) -> tuple[Callable[[str], int], str, Mapping[str, Any]]:
    """Load a local Qwen tokenizer lazily and return reproducible provenance."""

    source_path = Path(source).expanduser()
    resolved_source = str(source_path.resolve()) if source_path.exists() else source

    # Lazy import is important for --help and CPU-only integrity tooling.
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        resolved_source,
        local_files_only=True,
        trust_remote_code=True,
    )
    tokenizer_class = type(tokenizer).__name__
    if "qwen" not in tokenizer_class.casefold():
        raise ValueError(
            f"exact-token paper artifacts require a Qwen tokenizer, got {tokenizer_class}"
        )

    def count_tokens(text: str) -> int:
        return len(tokenizer.encode(text, add_special_tokens=False))

    artifact_sha = (
        _tokenizer_artifact_sha256(Path(resolved_source))
        if Path(resolved_source).is_dir()
        else None
    )
    identity = {
        "mode": "huggingface_local_qwen",
        "source": resolved_source,
        "class": tokenizer_class,
        "vocab_size": int(getattr(tokenizer, "vocab_size", 0)),
        "artifact_sha256": artifact_sha,
        "commit_sha": str(getattr(tokenizer, "init_kwargs", {}).get("_commit_hash") or ""),
        "local_files_only": True,
    }
    identity_sha = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    class_slug = re.sub(r"[^a-z0-9]+", "-", tokenizer_class.casefold()).strip("-")
    token_counter = f"hf-{class_slug[:48]}-{identity_sha[:16]}"
    return count_tokens, token_counter, {**identity, "identity_sha256": identity_sha}


def select_artifacts(args: argparse.Namespace) -> Mapping[str, Any]:
    count_tokens, token_counter, tokenizer_metadata = _load_qwen_tokenizer(args.tokenizer)
    generic = verify_candidate_manifest(
        args.generic, relation="generic", count_tokens=count_tokens
    )
    matched = verify_candidate_manifest(
        args.matched, relation="matched", count_tokens=count_tokens
    )
    shuffled = verify_candidate_manifest(
        args.shuffled, relation="label_shuffled", count_tokens=count_tokens
    )
    selection = select_exact_token_prompts(
        generic,
        matched,
        shuffled,
        count_tokens=count_tokens,
    )
    return write_selection_pack(
        args.out,
        selection=selection,
        generic_pack=generic,
        matched_pack=matched,
        shuffled_pack=shuffled,
        count_tokens=count_tokens,
        token_counter=token_counter,
        tokenizer_metadata=tokenizer_metadata,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--generic",
        type=Path,
        required=True,
        help="generic candidates manifest",
    )
    parser.add_argument(
        "--matched",
        type=Path,
        required=True,
        help="matched-memory candidates manifest",
    )
    parser.add_argument(
        "--shuffled",
        type=Path,
        required=True,
        help="label-shuffled candidates manifest",
    )
    parser.add_argument(
        "--tokenizer",
        required=True,
        help="local Qwen tokenizer path or a Qwen model id already in the local cache",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="output comparison pack",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = select_artifacts(args)
    except (
        CandidateIntegrityError,
        ExactTokenMatchError,
        FileNotFoundError,
        NotADirectoryError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
    conditions = manifest["conditions"]
    print(
        json.dumps(
            {
                "output": str(args.out.expanduser().resolve()),
                "target_defense_tokens": manifest["target_defense_tokens"],
                "token_counter": manifest["token_counter"],
                "selected_candidate_ids": {
                    name: value.get("provenance", {}).get("candidate_id")
                    for name, value in conditions.items()
                    if name != "native"
                },
                "native_prompt_empty": True,
                "raw_attack_payload_written": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
