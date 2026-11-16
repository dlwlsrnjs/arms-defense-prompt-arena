from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from defense_arena.aamd_benchmark import TRACK_IDS, validate_benchmark_config, validate_benchmark_file
from defense_arena.adaptive_attack_memory_dataset import DatasetValidationError


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "aamd_benchmark_v1.json"
SCRIPT = ROOT / "scripts" / "validate_aamd_benchmark.py"


def _config() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _track(config: dict, track_id: str) -> dict:
    return next(row for row in config["tracks"] if row["id"] == track_id)


def test_reference_benchmark_is_valid_but_has_no_scores_or_claims() -> None:
    summary = validate_benchmark_file(CONFIG)

    assert summary["valid"] is True
    assert summary["status"] == "protocol_candidate_no_scores"
    assert summary["track_ids"] == list(TRACK_IDS)
    assert summary["claim_ready"] is False
    assert summary["leaderboard_open"] is False
    assert summary["demo_claim_bearing"] is False
    assert len(summary["sha256"]) == 64


def test_cli_is_offline_and_machine_readable() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["valid"] is True
    assert summary["track_ids"] == ["T1", "T2", "T3", "T4", "T5"]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda raw: raw["claim_boundary"].update(benchmark_released=True), "cannot be released"),
        (lambda raw: raw["claim_boundary"].update(leaderboard_open=True), "cannot be open"),
        (
            lambda raw: raw["shared_contract"].update(same_episode_or_cluster_across_splits_allowed=True),
            "leakage across splits is forbidden",
        ),
        (
            lambda raw: raw["shared_contract"].update(raw_harmful_payload_in_public_track=True),
            "public tracks must remain payload-free",
        ),
        (
            lambda raw: raw["shared_contract"].update(turns_treated_as_independent_samples=True),
            "pseudoreplication is forbidden",
        ),
        (
            lambda raw: raw["shared_contract"].update(
                split_assignment_unit="semantic_behavior_cluster"
            ),
            "must use lineage components",
        ),
        (lambda raw: raw["tracks"].pop(), "exactly T1 through T5"),
        (lambda raw: _track(raw, "T3").update(release_tier="controlled"), "T3 release tier changed"),
        (
            lambda raw: _track(raw, "T2")["input_record_types"].append("memory_retrieval"),
            "cannot expose retrieval or consumption receipts",
        ),
        (
            lambda raw: _track(raw, "T2")["masked_or_target_only_fields"].remove(
                "memory_retrieval.rank"
            ),
            "does not mask every direct or proxy target field",
        ),
        (
            lambda raw: _track(raw, "T3")["masked_or_target_only_fields"].remove(
                "adaptation_transition.next_operation_code"
            ),
            "does not mask every direct or proxy target field",
        ),
        (
            lambda raw: _track(raw, "T4")["input_record_types"].append("annotation_event"),
            "cannot expose human labels or defense targets",
        ),
        (
            lambda raw: _track(raw, "T5")["input_record_types"].append(
                "defense_validation_trial"
            ),
            "cannot expose sealed validation outcomes",
        ),
        (
            lambda raw: _track(raw, "T3").update(research_use="Predict a payload."),
            "abstract-operation prediction task",
        ),
        (
            lambda raw: _track(raw, "T4")["prediction_targets"].pop(),
            "all four defense fields",
        ),
        (
            lambda raw: _track(raw, "T5")["secondary_metrics"].remove("benign_task_utility"),
            "missing safety, utility",
        ),
        (
            lambda raw: _track(raw, "T5")["required_baselines"].remove("linkage_broken_memory"),
            "missing internal or prior-method baselines",
        ),
        (
            lambda raw: raw["track_protocols"].update(status="executable_scorer_ready"),
            "cannot claim an executable scorer before G2",
        ),
        (
            lambda raw: raw["track_protocols"]["T2"]["subtasks"][0].update(
                causal_or_effective_retrieval_claim_allowed=True
            ),
            "T2a cannot support causal claims",
        ),
        (
            lambda raw: raw["track_protocols"]["T4"].update(reference_is_observed_gold=True),
            "hypotheses, not observed gold",
        ),
        (
            lambda raw: raw["track_protocols"]["T5"].update(
                paper_confirmation_and_public_leaderboard_separate=False
            ),
            "must remain separate",
        ),
        (
            lambda raw: raw["human_workspace"].update(demo_data_policy="claim_candidate"),
            "payload-free and excluded",
        ),
        (
            lambda raw: raw["human_workspace"]["required_claim_mode_controls"].remove(
                "initial_label_locked_before_llm_reveal"
            ),
            "controls were weakened",
        ),
        (
            lambda raw: raw["submission_manifest"].update(
                confirmation_feedback_returned_before_final_submission=True
            ),
            "feedback must remain sealed",
        ),
        (
            lambda raw: raw["leaderboard_policy"].update(hidden_set_rotation_required=False),
            "hidden_set_rotation_required=true",
        ),
        (
            lambda raw: raw["reporting"].update(null_and_negative_results_retained=False),
            "null and negative results",
        ),
    ],
)
def test_benchmark_contract_fails_closed(mutator, message: str) -> None:
    raw = copy.deepcopy(_config())
    mutator(raw)

    with pytest.raises(DatasetValidationError, match=message):
        validate_benchmark_config(raw)


def test_unknown_top_level_field_fails_closed() -> None:
    raw = _config()
    raw["measured_score"] = 0.99

    with pytest.raises(DatasetValidationError, match="fields must be ordered exactly"):
        validate_benchmark_config(raw)
