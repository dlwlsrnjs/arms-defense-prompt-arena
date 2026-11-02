from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from defense_arena.armor_prompt import SLOT_ORDER
from defense_arena.armor_token_match import (
    CandidateIntegrityError,
    ExactTokenMatchError,
    GenericSuffix,
    select_exact_token_prompts,
    verify_candidate_manifest,
    write_selection_pack,
)
from scripts import select_armor_token_matched as selector_cli


def _word_tokens(value: str) -> int:
    return len(value.split())


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_text(value: str) -> str:
    return _sha_bytes(value.encode())


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _words(prefix: str, count: int) -> str:
    return " ".join(f"{prefix}{index}" for index in range(count))


def _write_fixture_pack(
    root: Path,
    *,
    relation: str,
    candidates: list[tuple[str, str, float]],
) -> Path:
    root.mkdir(parents=True)
    records = []
    for candidate_id, text, priority in candidates:
        program = {
            "slots": [
                {
                    "slot": slot,
                    "priority": priority / len(SLOT_ORDER),
                    "clause_id": f"{candidate_id}.{slot}",
                }
                for slot in SLOT_ORDER
            ]
        }
        base = {
            "schema_version": 1,
            "compiler_version": "armor-offline-compiler-v1",
            "candidate_id": candidate_id,
            "tokens": _word_tokens(text),
            "token_budget": 64,
            "token_counter": "fixture-whitespace-v1",
            "program_sha256": _sha_text(_canonical(program)),
            "text_sha256": _sha_text(text),
            "attack_memory_sha256": "a" * 64,
            "defense_memory_sha256": "b" * 64,
            "config_sha256": "c" * 64,
            "program": program,
        }
        candidate_manifest_sha = _sha_text(_canonical(base))
        prompt_relative = Path("prompts") / f"{candidate_id}.txt"
        prompt_bytes = (text + "\n").encode()
        (root / prompt_relative).parent.mkdir(parents=True, exist_ok=True)
        (root / prompt_relative).write_bytes(prompt_bytes)
        flag = "raw_payload_included" if relation == "generic" else "raw_attack_payload_included"
        record = {
            **base,
            "manifest_sha256": candidate_manifest_sha,
            "prompt_path": prompt_relative.as_posix(),
            "prompt_file_sha256": _sha_bytes(prompt_bytes),
            flag: False,
        }
        if relation != "generic":
            record["overlap_gate"] = {
                "longest_consecutive_word_overlap": 0,
                "source_text_exposed": False,
            }
        records.append(record)

    manifest = {
        "schema_version": 1,
        "compiler_version": "fixture-compiler-v1",
        "token_budget": 64,
        "candidate_count": len(records),
        "token_counter": "fixture-whitespace-v1",
        "candidates": records,
    }
    if relation == "generic":
        manifest["payload_contract"] = {
            "raw_attack_payload_read": False,
            "raw_attack_payload_written": False,
        }
    else:
        manifest["relation"] = relation
        manifest["memory_sha256"] = "d" * 64
        manifest["memory_semantic_sha256"] = "e" * 64
    manifest_path = root / "candidates-B64.json"
    manifest_bytes = _json_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)

    if relation == "generic":
        budget_record = {
            "token_budget": 64,
            "candidate_count": len(records),
            "manifest_path": manifest_path.name,
            "manifest_sha256": _sha_bytes(manifest_bytes),
        }
    else:
        budget_record = {
            "token_budget": 64,
            "candidate_count": len(records),
            "path": manifest_path.name,
            "sha256": _sha_bytes(manifest_bytes),
        }
    compiler_manifest = {
        "schema_version": 1,
        "token_counter": "fixture-whitespace-v1",
        "budget_manifests": [budget_record],
    }
    if relation != "generic":
        compiler_memory_sha = "d" * 64 if relation == "matched" else "f" * 64
        compiler_manifest.update(
            {
                "relation": relation,
                "memory_sha256": "d" * 64,
                "clause_pack": {
                    "relation": relation,
                    "memory_sha256": "d" * 64,
                    "compiler_memory_provenance_sha256": compiler_memory_sha,
                },
            }
        )
    (root / "compiler_manifest.json").write_bytes(_json_bytes(compiler_manifest))
    return manifest_path


@pytest.fixture
def source_packs(tmp_path: Path):
    shared_memory_text = _words("shared", 21)
    generic_path = _write_fixture_pack(
        tmp_path / "generic",
        relation="generic",
        candidates=[
            ("armor-generic-high", _words("generic", 13), 5.0),
            ("armor-generic-low", _words("low", 12), 4.0),
        ],
    )
    matched_path = _write_fixture_pack(
        tmp_path / "matched",
        relation="matched",
        candidates=[
            ("armor-matched-high", shared_memory_text, 10.0),
            ("armor-matched-long", _words("matchedlong", 22), 7.0),
        ],
    )
    shuffled_path = _write_fixture_pack(
        tmp_path / "shuffled",
        relation="label_shuffled",
        candidates=[
            ("armor-shuffled-identical", shared_memory_text, 11.0),
            ("armor-shuffled-distinct", _words("distinct", 21), 8.0),
            ("armor-shuffled-long", _words("shuffledlong", 22), 6.0),
        ],
    )
    suffix = GenericSuffix(
        "fixture.benign-utility",
        "benign_utility",
        "Answer benign user requests clearly accurately and completely.",
        1.0,
    )
    return generic_path, matched_path, shuffled_path, suffix


def _verified(source_packs):
    generic_path, matched_path, shuffled_path, suffix = source_packs
    generic = verify_candidate_manifest(
        generic_path, relation="generic", count_tokens=_word_tokens
    )
    matched = verify_candidate_manifest(
        matched_path, relation="matched", count_tokens=_word_tokens
    )
    shuffled = verify_candidate_manifest(
        shuffled_path, relation="label_shuffled", count_tokens=_word_tokens
    )
    return generic, matched, shuffled, suffix


def test_selector_verifies_and_chooses_priority_first_distinct_exact_match(source_packs):
    generic, matched, shuffled, suffix = _verified(source_packs)

    selection = select_exact_token_prompts(
        generic,
        matched,
        shuffled,
        count_tokens=_word_tokens,
        suffixes=(suffix,),
    )

    assert selection.target_tokens == 21
    assert selection.matched.candidate_id == "armor-matched-high"
    # The higher-priority shuffled candidate is text-identical and must be skipped.
    assert selection.shuffled.candidate_id == "armor-shuffled-distinct"
    assert selection.generic.source.candidate_id == "armor-generic-high"
    assert selection.generic.suffixes == (suffix,)
    assert generic.compiler_memory_provenance_sha256 is None
    assert matched.compiler_memory_provenance_sha256 == "d" * 64
    assert shuffled.compiler_memory_provenance_sha256 == "f" * 64
    assert _word_tokens(selection.generic.text) == 21
    assert len(
        {
            selection.generic.text_sha256,
            selection.matched.text_sha256,
            selection.shuffled.text_sha256,
        }
    ) == 3


def test_writer_publishes_empty_native_and_three_literal_equal_length_prompts(
    source_packs, tmp_path: Path
):
    generic, matched, shuffled, suffix = _verified(source_packs)
    selection = select_exact_token_prompts(
        generic,
        matched,
        shuffled,
        count_tokens=_word_tokens,
        suffixes=(suffix,),
    )
    output = tmp_path / "selected"

    manifest = write_selection_pack(
        output,
        selection=selection,
        generic_pack=generic,
        matched_pack=matched,
        shuffled_pack=shuffled,
        count_tokens=_word_tokens,
        token_counter="fixture-whitespace-v1",
        tokenizer_metadata={"mode": "fixture", "identity_sha256": "f" * 64},
    )

    saved = json.loads((output / "selection_manifest.json").read_text())
    manifest_without_hash = dict(saved)
    manifest_sha = manifest_without_hash.pop("manifest_sha256")
    assert manifest_sha == _sha_text(_canonical(manifest_without_hash))
    assert saved == manifest
    assert saved["target_defense_tokens"] == 21
    assert saved["conditions"]["native"]["compiler_memory_provenance_sha256"] is None
    assert saved["conditions"]["generic"]["compiler_memory_provenance_sha256"] is None
    assert (
        saved["conditions"]["matched_memory"]["compiler_memory_provenance_sha256"]
        == "d" * 64
    )
    assert (
        saved["conditions"]["label_shuffled"]["compiler_memory_provenance_sha256"]
        == "f" * 64
    )
    assert (
        saved["inputs"]["matched_memory"]["compiler_memory_provenance_sha256"]
        == "d" * 64
    )
    assert (output / saved["conditions"]["native"]["prompt_path"]).read_bytes() == b""
    for condition in ("generic", "matched_memory", "label_shuffled"):
        record = saved["conditions"][condition]
        prompt = (output / record["prompt_path"]).read_text()
        assert not prompt.endswith("\n")
        assert _word_tokens(prompt) == record["tokens"] == 21
        assert _sha_text(prompt) == record["text_sha256"]
        assert _sha_text(prompt) == record["prompt_file_sha256"]
    assert len(
        {
            saved["conditions"][name]["text_sha256"]
            for name in ("generic", "matched_memory", "label_shuffled")
        }
    ) == 3
    # Provenance stores only the semantic suffix hash, not its text.
    assert suffix.text not in (output / "selection_manifest.json").read_text()
    assert not list(output.rglob("*.tmp"))
    assert saved["payload_contract"]["raw_attack_payload_written"] is False


def test_verifier_fails_closed_on_prompt_and_parent_manifest_tampering(source_packs):
    generic_path, _, _, _ = source_packs
    manifest = json.loads(generic_path.read_text())
    prompt = generic_path.parent / manifest["candidates"][0]["prompt_path"]
    prompt.write_text(prompt.read_text() + "tamper\n")

    with pytest.raises(CandidateIntegrityError, match="prompt file digest mismatch"):
        verify_candidate_manifest(generic_path, relation="generic", count_tokens=_word_tokens)

    # Restore the prompt, then change the candidate manifest without updating its parent.
    original_text = _words("generic", 13)
    prompt.write_text(original_text + "\n")
    changed = json.loads(generic_path.read_text())
    changed["tampered"] = True
    generic_path.write_bytes(_json_bytes(changed))
    with pytest.raises(CandidateIntegrityError, match="digest disagrees"):
        verify_candidate_manifest(generic_path, relation="generic", count_tokens=_word_tokens)


def test_verifier_rejects_candidate_hash_as_compiler_memory_provenance(source_packs):
    _, _, shuffled_path, _ = source_packs
    candidate_manifest = json.loads(shuffled_path.read_text())
    candidate_hash = candidate_manifest["candidates"][0]["manifest_sha256"]
    compiler_path = shuffled_path.parent / "compiler_manifest.json"
    compiler = json.loads(compiler_path.read_text())
    compiler["clause_pack"]["compiler_memory_provenance_sha256"] = candidate_hash
    compiler_path.write_bytes(_json_bytes(compiler))

    with pytest.raises(CandidateIntegrityError, match="candidate or manifest artifact hash"):
        verify_candidate_manifest(
            shuffled_path,
            relation="label_shuffled",
            count_tokens=_word_tokens,
        )


def test_selector_fails_instead_of_padding_when_semantic_suffix_cannot_match(source_packs):
    generic, matched, shuffled, _ = _verified(source_packs)
    short_suffix = GenericSuffix(
        "fixture.safe-action",
        "safe_action",
        "Offer one safe useful alternative.",
        1.0,
    )

    with pytest.raises(ExactTokenMatchError, match="cannot exactly match"):
        select_exact_token_prompts(
            generic,
            matched,
            shuffled,
            count_tokens=_word_tokens,
            suffixes=(short_suffix,),
        )


def test_cli_selection_uses_injected_tokenizer_and_writes_pack(
    source_packs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    generic_path, matched_path, shuffled_path, suffix = source_packs
    # The CLI uses the production catalog, so inject this fixture suffix into the
    # selector call while leaving tokenizer loading and artifact plumbing under test.
    original_select = selector_cli.select_exact_token_prompts

    def select_with_fixture_suffix(*args, **kwargs):
        return original_select(*args, **kwargs, suffixes=(suffix,))

    monkeypatch.setattr(
        selector_cli,
        "_load_qwen_tokenizer",
        lambda _source: (
            _word_tokens,
            "fixture-qwen-tokenizer-v1",
            {"mode": "fixture_qwen", "identity_sha256": "f" * 64},
        ),
    )
    monkeypatch.setattr(selector_cli, "select_exact_token_prompts", select_with_fixture_suffix)
    output = tmp_path / "cli-output"
    args = Namespace(
        generic=generic_path,
        matched=matched_path,
        shuffled=shuffled_path,
        tokenizer="unused-fixture-qwen",
        out=output,
    )

    manifest = selector_cli.select_artifacts(args)

    assert manifest["target_defense_tokens"] == 21
    assert manifest["token_counter"] == "fixture-qwen-tokenizer-v1"
    assert (output / "selection_manifest.json").is_file()


def test_cli_help_does_not_need_to_load_transformers():
    script = Path(__file__).parents[1] / "scripts" / "select_armor_token_matched.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "--tokenizer" in result.stdout
    assert "CPU/tokenizer-only" in result.stdout
