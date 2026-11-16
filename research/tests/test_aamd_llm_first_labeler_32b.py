from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "aamd_llm_first_labeler_32b_v1.json"


def _config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_first_pass_proposer_is_exactly_the_frozen_32b_candidate() -> None:
    config = _config()
    model = config["model"]

    assert config["config_id"] == "aamd-llm-first-labeler-32b-v1"
    assert config["protocol_id"] == "aamd-llm-first-human-review-v2"
    assert config["role"] == "offline_first_pass_proposer"
    assert model["model_id"] == "Qwen/Qwen2.5-VL-32B-Instruct"
    assert model["parameters"] == "32B"
    assert model["revision_candidate"] == (
        "7cfb30d71a1f4f49a57592323337a4a4727301da"
    )
    assert model["revision_status"] == "candidate_needs_G0_attestation"
    assert config["claim_ready"] is False


def test_prompt_bytes_are_frozen_and_payload_free() -> None:
    config = _config()
    prompt_path = ROOT.parent / config["prompt"]["path"]
    prompt = prompt_path.read_bytes()

    assert _sha256(prompt) == config["prompt"]["sha256"]
    assert b"{{TASK_JSON}}" in prompt
    assert config["prompt"]["raw_attack_payload_allowed"] is False
    assert config["prompt"]["hidden_outcome_allowed"] is False


def test_decoding_hash_matches_canonical_json() -> None:
    config = _config()
    canonical = json.dumps(
        config["decoding"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    assert _sha256(canonical) == config["decoding_config_sha256"]
    assert config["decoding"] == {
        "temperature": 0,
        "top_p": 1,
        "max_output_tokens": 2048,
        "seed": 20261116,
        "stop": [],
    }


def test_proposer_is_not_ground_truth_or_downstream_judge() -> None:
    config = _config()
    separation = config["role_separation"]
    gate = config["claim_gate"]

    assert separation["model_is_ground_truth"] is False
    assert separation["human_review_required"] is True
    assert set(separation["prohibited_roles_in_same_confirmation_run"]) == {
        "adjudicator",
        "safety_judge",
        "utility_evaluator",
    }
    assert gate["claim_bearing_revision_status_required"] == "g0_attested"
    assert gate["trusted_g0_attestation_sha256"] is None
    assert gate["trusted_claim_bundle_sha256"] is None
    assert gate["bundle_self_assertion_sufficient"] is False
    assert gate["smaller_model_superiority_claim_allowed"] is False
    assert gate["human_acceptance_implies_accuracy"] is False


def test_worker_and_protocol_pin_the_same_labeler_contract() -> None:
    config = _config()
    protocol = json.loads(
        (ROOT / "configs" / "aamd_human_review_protocol_v2.json").read_text(
            encoding="utf-8"
        )
    )
    worker = (
        ROOT.parent / "aamd-human-workspace-site" / "worker" / "index.js"
    ).read_text(encoding="utf-8")
    labeler = protocol["proposal_contract"]["first_pass_labeler"]

    assert labeler["config_id"] == config["config_id"]
    assert labeler["model_id"] == config["model"]["model_id"]
    assert labeler["parameters"] == config["model"]["parameters"]
    assert labeler["model_revision"] == config["model"]["revision_candidate"]
    assert labeler["prompt_template_hash"] == config["prompt"]["sha256"]
    assert labeler["decoding_config_hash"] == config["decoding_config_sha256"]
    for value in (
        config["config_id"],
        config["model"]["model_id"],
        config["model"]["revision_candidate"],
        config["prompt"]["sha256"],
        config["decoding_config_sha256"],
    ):
        assert value in worker
    assert "const TRUSTED_LABELER_G0_ATTESTATION_SHA256 = null;" in worker
    assert "const TRUSTED_LABELER_CLAIM_BUNDLE_SHA256 = null;" in worker
