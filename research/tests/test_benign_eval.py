from __future__ import annotations

import json

import pytest

from defense_arena.benign_eval import (
    detect_refusal,
    load_benign_cases,
    select_balanced_cases,
    summarize_pairs,
    validate_judge_result,
)


def _write_jsonl(path, rows) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_load_and_source_balanced_selection(tmp_path) -> None:
    dataset = tmp_path / "benign.jsonl"
    rows = [
        {
            "id": f"a-{index}",
            "query": f"Explain safe topic A{index}.",
            "source": "source-a",
            "safety_label": "benign",
            "modality": "text",
            "media": [],
        }
        for index in range(4)
    ]
    rows.extend(
        {
            "id": f"b-{index}",
            "query": f"Explain safe topic B{index}.",
            "source": "source-b",
            "safety_label": "benign",
            "modality": "text",
            "media": [],
        }
        for index in range(2)
    )
    _write_jsonl(dataset, rows)

    cases = load_benign_cases(dataset)
    first = select_balanced_cases(cases, limit=4, seed=7)
    second = select_balanced_cases(cases, limit=4, seed=7)

    assert [case.id for case in first] == [case.id for case in second]
    assert [case.source for case in first[:2]] == ["source-a", "source-b"]
    assert {case.source for case in first} == {"source-a", "source-b"}


def test_loader_fails_closed_on_non_benign_or_media(tmp_path) -> None:
    dataset = tmp_path / "mixed.jsonl"
    _write_jsonl(
        dataset,
        [{"id": "bad", "query": "Not used", "safety_label": "harmful", "modality": "text"}],
    )
    with pytest.raises(ValueError, match="non-benign"):
        load_benign_cases(dataset)


def test_loader_can_explicitly_filter_mixed_candidate_data(tmp_path) -> None:
    dataset = tmp_path / "defender_train.jsonl"
    _write_jsonl(
        dataset,
        [
            {
                "id": "safe-one",
                "query": "Explain a safe topic.",
                "source": "source-a",
                "safety_label": "benign",
                "modality": "text",
                "media": [],
            },
            {
                "id": "filtered-row",
                "query": "This row must not be loaded.",
                "source": "source-b",
                "safety_label": "harmful",
                "modality": "text",
                "media": [],
            },
            {
                "id": "safe-two",
                "query": "Summarize another safe topic.",
                "source": "source-a",
                "safety_label": "benign",
                "modality": "text",
                "media": [],
            },
        ],
    )

    cases = load_benign_cases(dataset, allow_mixed=True)

    assert [case.id for case in cases] == ["safe-one", "safe-two"]


def test_refusal_detector_is_conservative() -> None:
    assert detect_refusal("I'm sorry, but I cannot assist with that request.")["detected"] is True
    assert detect_refusal("I can't wait to help you plan this trip.")["detected"] is False
    assert detect_refusal("Here is a concise explanation of the water cycle.")["detected"] is False


def test_paired_summary_reports_regression_and_judge_delta() -> None:
    rows = [
        {
            "id": "one",
            "source": "xstest",
            "no_added_prompt": {
                "error": None,
                "characters": 100,
                "refusal": {"detected": False},
            },
            "defended": {
                "error": None,
                "characters": 40,
                "refusal": {"detected": True},
            },
            "judge": {
                "error": None,
                "baseline_helpfulness": 5,
                "defended_helpfulness": 2,
                "baseline_task_fulfillment": 5,
                "defended_task_fulfillment": 1,
                "baseline_refusal": False,
                "defended_refusal": True,
                "preference": "baseline",
            },
        },
        {
            "id": "two",
            "source": "xstest",
            "no_added_prompt": {
                "error": None,
                "characters": 80,
                "refusal": {"detected": False},
            },
            "defended": {
                "error": None,
                "characters": 90,
                "refusal": {"detected": False},
            },
            "judge": {
                "error": None,
                "baseline_helpfulness": 4,
                "defended_helpfulness": 4,
                "baseline_task_fulfillment": 4,
                "defended_task_fulfillment": 4,
                "baseline_refusal": False,
                "defended_refusal": False,
                "preference": "tie",
            },
        },
    ]

    report = summarize_pairs(rows)

    refusal = report["heuristic_refusal"]
    assert refusal["over_refusal_regressions"] == 1
    assert refusal["over_refusal_regression_rate_among_baseline_non_refusals"] == 0.5
    utility = report["judge_utility"]
    assert utility["mean_paired_helpfulness_delta"] == -1.5
    assert utility["over_refusal_regressions"] == 1
    assert utility["preferences"] == {"baseline": 1, "tie": 1}
    assert report["by_source"]["xstest"]["n"] == 2


def test_validate_judge_result() -> None:
    value = validate_judge_result(
        {
            "baseline_helpfulness": 5,
            "defended_helpfulness": 4,
            "baseline_task_fulfillment": 5,
            "defended_task_fulfillment": 4,
            "baseline_refusal": False,
            "defended_refusal": False,
            "preference": "baseline",
        }
    )
    assert value["baseline_helpfulness"] == 5
    with pytest.raises(ValueError, match="between 1 and 5"):
        validate_judge_result({**value, "defended_helpfulness": 6})
