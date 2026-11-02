from __future__ import annotations

import hashlib

import pytest

from defense_arena.armor_prefreeze import (
    PrefreezeValidationError,
    extract_prefreeze_evidence,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _row() -> dict:
    request = "synthetic first request"
    action = _sha("first action")
    image = _sha("fixture image")
    return {
        "behavior": {"id": "fixture-behavior", "text": "ephemeral"},
        "history": [
            {
                "call_index": 1,
                "error": "target_error",
                "turns": [{"text": request, "images": ["img_1"]}],
                "response": "",
                "request_sha256": _sha(request),
                "response_sha256": _sha(""),
                "action_sha256": action,
                "image_content_sha256": [image],
            }
        ],
        "instrumentation": {
            "schema_version": 3,
            "target_call_budget": 4,
            "target_calls_started": 1,
            "target_responses_received": 0,
            "judge_invocations": 0,
            "termination_reason": "target_error",
            "provenance": {
                "base_seed": 7101,
                "initial_retrieval_sha256": _sha("retrieval"),
                "first_target_request_sha256": _sha(request),
                "first_target_action_sha256": action,
                "asset_content_sha256": [image],
            },
            "planner_fallback": {"configured_policy_sha256": _sha("policy")},
        },
    }


def test_extract_prefreeze_returns_metadata_only_pair_contract():
    evidence = extract_prefreeze_evidence(_row(), initial_memory_sha256="1" * 64)
    pair = evidence.to_pair_record(
        pair_id="pair-001",
        decoding_config={"temperature": 0.0, "top_p": 1.0},
    )
    assert pair["first_action_sha256"] == _sha("synthetic first request")
    assert pair["fallback_action_sha256"] == _sha("first action")
    assert pair["fallback_request_sha256"] == pair["first_action_sha256"]
    assert pair["asset_hashes"] == {"first-action-image-001": _sha("fixture image")}
    assert evidence.target_call_budget == 4
    assert "target_call_budget" not in pair
    serialized = str(evidence.to_dict())
    assert "synthetic first request" not in serialized
    assert "ephemeral" not in serialized
    assert evidence.to_dict()["raw_attack_or_response_text_included"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda row: row["instrumentation"].update(target_responses_received=1), "target response"),
        (lambda row: row["instrumentation"].update(judge_invocations=1), "judge"),
        (lambda row: row["instrumentation"].pop("target_call_budget"), "budget"),
        (lambda row: row["instrumentation"].update(target_call_budget=0), "budget"),
        (lambda row: row["history"][0].update(response="not empty"), "must not return"),
        (lambda row: row["history"][0].update(request_sha256="0" * 64), "request hash"),
    ],
)
def test_prefreeze_rejects_any_target_or_provenance_drift(mutation, message):
    row = _row()
    mutation(row)
    with pytest.raises(PrefreezeValidationError, match=message):
        extract_prefreeze_evidence(row, initial_memory_sha256="1" * 64)
