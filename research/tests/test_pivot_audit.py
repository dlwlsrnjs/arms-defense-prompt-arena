from __future__ import annotations

from defense_arena.pivot_audit import (
    audit_pair,
    instrumentation_summary,
    movement_label,
    planner_status,
)


def _row(
    behavior_id: str,
    score: int,
    *,
    queries: int = 3,
    steps: int = 6,
    category: str = "Example",
    strategy: str = "flowchart",
) -> dict:
    return {
        "behavior": {"id": behavior_id, "risk_category": category},
        "best_score": score,
        "queries": queries,
        "steps": steps,
        "history": [
            {"score": score, "strategy": strategy, "turns": [{"text": "redacted"}]}
        ] if queries else [],
        "trajectory": {"strategy": strategy} if queries else None,
    }


def test_movement_labels_prioritize_threshold_crossings():
    assert movement_label(1, 5) == "new_strict_regression"
    assert movement_label(5, 1) == "strict_improvement"
    assert movement_label(1, 4) == "new_substantial_regression"
    assert movement_label(4, 1) == "substantial_improvement"
    assert movement_label(1, 2) == "severity_regression"


def test_planner_status_distinguishes_censoring_and_success():
    assert planner_status(_row("a", 0, queries=0, steps=90), query_budget=3, max_steps=90) == (
        "zero_query_step_exhaustion"
    )
    assert planner_status(_row("a", 1, queries=2, steps=90), query_budget=3, max_steps=90) == (
        "under_budget_step_exhaustion"
    )
    assert planner_status(_row("a", 5, queries=2, steps=4), query_budget=3, max_steps=90) == (
        "early_strict_success"
    )


def test_zero_query_case_is_imputed_from_paired_control():
    report = audit_pair(
        [_row("a", 5)],
        [_row("a", 0, queries=0, steps=90)],
        label="candidate",
        query_budget=3,
        max_steps=90,
    )
    case = report["attention_cases"][0]
    assert case["candidate"]["score"] == 0
    assert case["conservative_candidate_score"] == 5
    assert case["zero_query_imputed_from_control"] is True
    assert report["strict_successes"] == {"control": 1, "candidate": 1}


def test_regression_and_worst_case_censoring_are_reported():
    report = audit_pair(
        [_row("a", 1), _row("b", 1)],
        [_row("a", 4), _row("b", 1, queries=2, steps=90)],
        label="candidate",
        query_budget=3,
        max_steps=90,
    )
    assert report["movement_counts"]["new_substantial_regression"] == 1
    assert report["worst_case_strict_successes_if_censoring_is_failure"] == 1
    assert len(report["attention_cases"]) == 2


def test_instrumentation_counts_unjudged_intermediate_responses():
    single = _row("a", 1)
    multi = _row("b", 1)
    multi["history"] = [
        {"score": 1, "strategy": "crescendo", "turns": [{}, {}, {}]},
        {"score": 1, "strategy": "flowchart", "turns": [{}]},
    ]
    report = instrumentation_summary([single, multi])
    assert report == {
        "episodes": 2,
        "judged_attempts": 3,
        "multi_turn_attempts": 1,
        "target_generation_calls": 5,
        "unjudged_intermediate_responses": 2,
    }
