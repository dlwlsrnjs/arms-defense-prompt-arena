from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from defense_arena.memory_compiler import (
    build_defense_atoms,
    compile_prompt_candidates,
    memory_behavior_hashes,
    memory_semantic_sha256,
    normalized_behavior_sha256,
    prompt_memory_overlap,
    sha256_text,
    verify_memory,
)
from scripts import compile_memory_defense


def _memory_row(
    behavior_id: str,
    *,
    behavior: str,
    strategy: str,
    best_score: int,
    category: str = "Benign Policy Review",
    queries: int = 2,
) -> dict:
    """Build a schema-valid row whose text is deliberately harmless."""
    return {
        "behavior_id": behavior_id,
        "behavior": behavior,
        "risk_category": category,
        "strategy": strategy,
        "best_score": best_score,
        "queries": queries,
        "steps": [
            f"{strategy}{{}} -> 2/5: first benign formatting attempt",
            f"{strategy}{{}} -> {best_score}/5: revised benign formatting attempt",
        ],
        "reflection": f"{strategy} scored {best_score}/5 on this synthetic museum fixture.",
        "success": best_score == 5,
    }


def _write_memory(path: Path, rows: list[dict]) -> Path:
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def _write_results(path: Path, rows: list[dict]) -> Path:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return path


def _word_tokens(value: str) -> int:
    return len(value.split())


def test_verify_memory_recomputes_outcome_and_keeps_raw_payload_out_of_entries(tmp_path: Path):
    raw_phrase = "Catalog the violet carousel exhibit for the local museum."
    row = _memory_row(
        "fixture-1",
        behavior=raw_phrase,
        strategy="email_thread",
        best_score=5,
    )
    # The source flag is advisory; verification derives success from the score.
    row["success"] = False
    memory = _write_memory(tmp_path / "memory.json", [row])
    results = _write_results(tmp_path / "results.jsonl", [{
        "behavior": {"id": "fixture-1"},
        "best_score": 5,
        "queries": 2,
        "history": [
            {"strategy": "email_thread", "score": 2},
            {"strategy": "email_thread", "score": 5},
        ],
    }])

    verified, report = verify_memory(memory, results_path=results)

    assert len(verified) == 1
    entry = verified[0]
    assert entry.success is True
    assert entry.step_scores == (2, 5)
    assert entry.trace_scores == (2, 5)
    assert entry.source_trace_matched is True
    assert entry.behavior_id_hash == sha256_text("fixture-1")[:16]
    assert report["outcome_flag_mismatches"] == 1
    assert report["source_trace_matches"] == 1
    assert report["trace_score_mismatches"] == 0
    assert report["trace_query_mismatches"] == 0
    assert report["raw_payload_copied"] is False
    # The verified representation is metadata-only: no behavior, reflection, or steps.
    assert not ({"behavior", "reflection", "steps"} & set(asdict(entry)))
    assert raw_phrase not in json.dumps(asdict(entry), ensure_ascii=False)


def test_verify_memory_rejects_incomplete_or_out_of_range_rows(tmp_path: Path):
    incomplete = _memory_row(
        "fixture-1",
        behavior="Summarize a harmless gallery notice.",
        strategy="news_report",
        best_score=4,
    )
    incomplete.pop("reflection")
    invalid_range = _memory_row(
        "fixture-2",
        behavior="Format a community-center schedule.",
        strategy="flowchart",
        best_score=5,
        queries=0,
    )
    memory = _write_memory(tmp_path / "memory.json", [incomplete, invalid_range])

    with pytest.raises(ValueError, match="invalid ARMS memory") as exc_info:
        verify_memory(memory)

    message = str(exc_info.value)
    assert "missing" in message
    assert "score/query range is invalid" in message


def test_verify_memory_rejects_ambiguous_duplicate_source_traces(tmp_path: Path):
    memory = _write_memory(tmp_path / "memory.json", [
        _memory_row(
            "fixture-1",
            behavior="Summarize a harmless museum notice.",
            strategy="news_report",
            best_score=4,
        )
    ])
    duplicate = {
        "behavior": {"id": "fixture-1"},
        "best_score": 4,
        "queries": 2,
        "history": [{"strategy": "news_report", "score": 4}],
    }
    results = _write_results(tmp_path / "results.jsonl", [duplicate, duplicate])

    with pytest.raises(ValueError, match="duplicate behavior id"):
        verify_memory(memory, results_path=results)


def test_memory_semantic_hash_is_stable_for_reordered_distinct_rows():
    first = _memory_row(
        "fixture-a",
        behavior="Summarize the amber museum map.",
        strategy="email_thread",
        best_score=4,
    )
    second = _memory_row(
        "fixture-b",
        behavior="Turn the library hours into a numbered list.",
        strategy="numbered_list",
        best_score=5,
    )

    assert memory_semantic_sha256([first, second]) == memory_semantic_sha256([second, first])


def test_memory_semantic_hash_is_stable_even_when_identifiers_collide():
    first = _memory_row(
        "shared-id",
        behavior="Summarize the first harmless museum card.",
        strategy="email_thread",
        best_score=4,
    )
    second = {
        **first,
        "behavior": "Summarize the second harmless museum card.",
        "reflection": "email_thread scored 4/5 on a second synthetic fixture.",
    }

    assert memory_semantic_sha256([first, second]) == memory_semantic_sha256([second, first])


def test_atoms_aggregate_profiles_and_trace_transitions(tmp_path: Path):
    rows = [
        _memory_row(
            "doc-fixture",
            behavior="Rewrite a harmless museum announcement as an email.",
            strategy="email_thread",
            best_score=4,
        ),
        _memory_row(
            "structure-fixture",
            behavior="Draw a flowchart for checking library opening hours.",
            strategy="flowchart",
            best_score=5,
        ),
    ]
    memory = _write_memory(tmp_path / "memory.json", rows)
    results = _write_results(tmp_path / "results.jsonl", [
        {
            "behavior": {"id": "doc-fixture"},
            "best_score": 4,
            "queries": 2,
            "history": [
                {"strategy": "email_thread", "score": 2},
                {"strategy": "email_thread", "score": 4},
            ],
        },
        {
            "behavior": {"id": "structure-fixture"},
            "best_score": 5,
            "queries": 2,
            "history": [
                {"strategy": "email_thread", "score": 2},
                {"strategy": "flowchart", "score": 5},
            ],
        },
    ])

    verified, _report = verify_memory(memory, results_path=results)
    atoms = build_defense_atoms(verified)
    by_family = {atom.family: atom for atom in atoms}

    assert set(by_family) == {"social_document_framing", "structured_transformation"}
    social = by_family["social_document_framing"]
    structured = by_family["structured_transformation"]
    assert social.entries == 1
    assert social.successes == 0
    assert social.likely_next_families == ("structured_transformation",)
    assert structured.entries == 1
    assert structured.successes == 1
    assert structured.transition_evidence == 1
    assert structured.mean_positive_gain == 3.0
    assert all(evidence.startswith("ev-") for evidence in structured.evidence_ids)


def test_compiled_candidates_respect_budget_are_deterministic_and_payload_free(tmp_path: Path):
    raw_phrase = "Index the cerulean lantern collection in the village archive."
    memory = _write_memory(tmp_path / "memory.json", [
        _memory_row(
            "fixture-1",
            behavior=raw_phrase,
            strategy="email_thread",
            best_score=5,
        ),
        _memory_row(
            "fixture-2",
            behavior="Convert a harmless train timetable into a flowchart.",
            strategy="flowchart",
            best_score=4,
        ),
    ])
    verified, report = verify_memory(memory)
    atoms = build_defense_atoms(verified)

    kwargs = {
        "budgets": (60, 100, 120),
        "count_tokens": _word_tokens,
        "token_counter_name": "fixture-word-counter",
        "memory_semantic_hash": report["memory_semantic_sha256"],
    }
    first = compile_prompt_candidates(atoms, **kwargs)
    second = compile_prompt_candidates(atoms, **kwargs)

    assert [candidate.to_dict() for candidate in first] == [candidate.to_dict() for candidate in second]
    assert [candidate.budget for candidate in first] == [60, 100, 120]
    for candidate in first:
        assert candidate.tokens == _word_tokens(candidate.text)
        assert candidate.tokens <= candidate.budget
        assert candidate.memory_semantic_sha256 == report["memory_semantic_sha256"]
        assert raw_phrase not in candidate.text
        assert "fixture-1" not in candidate.text
    assert len(first[-1].selected_atom_ids) >= len(first[0].selected_atom_ids)

    overlap = prompt_memory_overlap(memory, first[-1].text)
    assert overlap["source_text_exposed"] is False
    assert set(overlap) == {
        "longest_consecutive_word_overlap",
        "source_field",
        "source_evidence_id",
        "source_text_exposed",
    }


def test_overlap_and_behavior_hashes_use_normalized_benign_text(tmp_path: Path):
    phrase = "Review the Community Museum Visitor Guide"
    memory = _write_memory(tmp_path / "memory.json", [
        _memory_row(
            "fixture-1",
            behavior=phrase + ".",
            strategy="narrative",
            best_score=3,
        )
    ])

    assert memory_behavior_hashes(memory) == {normalized_behavior_sha256(phrase)}
    report = prompt_memory_overlap(memory, "Please review the community museum visitor guide today.")
    assert report["longest_consecutive_word_overlap"] >= 6
    assert report["source_field"] == "behavior"
    assert report["source_evidence_id"].startswith("ev-")
    assert "visitor guide" not in json.dumps(report)


def test_compile_cli_writes_a_hash_bound_payload_free_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    raw_phrase = "Sort the silver teacup exhibit labels alphabetically."
    memory = _write_memory(tmp_path / "memory.json", [
        _memory_row(
            "fixture-1",
            behavior=raw_phrase,
            strategy="numbered_list",
            best_score=5,
        )
    ])
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    output = tmp_path / "compiled"
    monkeypatch.setattr(
        compile_memory_defense,
        "_token_counter",
        lambda _path: (_word_tokens, "fixture-word-counter"),
    )
    monkeypatch.setattr(sys, "argv", [
        "compile_memory_defense.py",
        "--memory", str(memory),
        "--tokenizer", str(tokenizer),
        "--budgets", "60", "100",
        "--out", str(output),
    ])

    compile_memory_defense.main()

    manifest = json.loads((output / "compiler_manifest.json").read_text(encoding="utf-8"))
    verification = json.loads((output / "verified_memory_report.json").read_text(encoding="utf-8"))
    assert manifest["method"] == "Mem2Guard-X"
    assert [item["budget"] for item in manifest["budgets"]] == [60, 100]
    assert manifest["deployment_contract"] == {
        "target_weights_frozen": True,
        "raw_behavior_copied": False,
        "raw_reflection_copied": False,
        "raw_steps_copied": False,
        "system_prompt_only": True,
        "public_explanation": "high-level boundary only",
        "private_provenance": "defense_atoms.json evidence_ids",
    }
    atoms = json.loads((output / "defense_atoms.json").read_text(encoding="utf-8"))
    assert atoms[0]["evidence_ids"][0].startswith("ev-")
    assert verification["admission_gate"]["passed"] is True
    assert verification["admission_gate"]["source_traces_required"] is False
    for budget in (60, 100):
        prompt = (output / f"prompt-B{budget}.txt").read_text(encoding="utf-8")
        assert raw_phrase not in prompt
        assert _word_tokens(prompt) <= budget


def test_memory_admission_report_enforces_every_documented_check():
    valid = {
        "entries": 2,
        "verified_entries": 2,
        "source_trace_matches": 2,
        "outcome_flag_mismatches": 0,
        "trace_score_mismatches": 0,
        "trace_query_mismatches": 0,
        "duplicate_slots": 0,
    }
    passed = compile_memory_defense._memory_admission_report(  # pylint: disable=protected-access
        valid,
        require_source_traces=True,
    )
    assert passed["passed"] is True
    assert passed["failures"] == []

    for field in (
        "verified_entries",
        "source_trace_matches",
        "outcome_flag_mismatches",
        "trace_score_mismatches",
        "trace_query_mismatches",
        "duplicate_slots",
    ):
        invalid = dict(valid)
        invalid[field] = 1 if field.endswith("mismatches") or field == "duplicate_slots" else 0
        report = compile_memory_defense._memory_admission_report(  # pylint: disable=protected-access
            invalid,
            require_source_traces=True,
        )
        assert report["passed"] is False
        assert report["failures"] == [field]

    without_results = compile_memory_defense._memory_admission_report(  # pylint: disable=protected-access
        {**valid, "source_trace_matches": 0},
        require_source_traces=False,
    )
    assert without_results["passed"] is True
    assert "source_trace_matches" not in without_results["checks"]


def test_compile_cli_fails_closed_on_memory_outcome_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    row = _memory_row(
        "fixture-1",
        behavior="Sort harmless community archive labels.",
        strategy="numbered_list",
        best_score=5,
    )
    row["success"] = False
    memory = _write_memory(tmp_path / "memory.json", [row])
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    output = tmp_path / "compiled"
    monkeypatch.setattr(
        compile_memory_defense,
        "_token_counter",
        lambda _path: (_word_tokens, "fixture-word-counter"),
    )
    monkeypatch.setattr(sys, "argv", [
        "compile_memory_defense.py",
        "--memory", str(memory),
        "--tokenizer", str(tokenizer),
        "--budgets", "60",
        "--out", str(output),
    ])

    with pytest.raises(SystemExit, match="outcome_flag_mismatches=1"):
        compile_memory_defense.main()

    assert not output.exists()


def test_compile_cli_requires_all_source_traces_when_results_are_supplied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    memory = _write_memory(tmp_path / "memory.json", [
        _memory_row(
            "fixture-1",
            behavior="Summarize a harmless community archive guide.",
            strategy="news_report",
            best_score=4,
        )
    ])
    results = _write_results(tmp_path / "results.jsonl", [{
        "behavior": {"id": "another-fixture"},
        "best_score": 4,
        "queries": 2,
        "history": [{"strategy": "news_report", "score": 4}],
    }])
    tokenizer = tmp_path / "tokenizer"
    tokenizer.mkdir()
    output = tmp_path / "compiled"
    monkeypatch.setattr(
        compile_memory_defense,
        "_token_counter",
        lambda _path: (_word_tokens, "fixture-word-counter"),
    )
    monkeypatch.setattr(sys, "argv", [
        "compile_memory_defense.py",
        "--memory", str(memory),
        "--results", str(results),
        "--tokenizer", str(tokenizer),
        "--budgets", "60",
        "--out", str(output),
    ])

    with pytest.raises(SystemExit, match=r"source_trace_matches=0 \(expected 1\)"):
        compile_memory_defense.main()

    assert not output.exists()


def test_compile_rejects_budget_smaller_than_the_safety_core():
    with pytest.raises(ValueError, match="too small"):
        compile_prompt_candidates(
            [],
            budgets=(5,),
            count_tokens=_word_tokens,
            token_counter_name="fixture-word-counter",
            memory_semantic_hash="fixture-hash",
        )
