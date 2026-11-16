from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "aamd_human_review_protocol_v2.json"


def _protocol() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def test_protocol_identity_and_offline_frozen_proposal_contract() -> None:
    protocol = _protocol()
    proposal = protocol["proposal_contract"]
    labeler = proposal["first_pass_labeler"]

    assert protocol["schema_version"] == 2
    assert protocol["protocol_id"] == "aamd-llm-first-human-review-v2"
    assert protocol["workflow"] == "llm_first_human_review"
    assert protocol["status"] == "protocol_candidate_not_run"
    assert protocol["claim_ready"] is False
    assert proposal["generation_mode"] == "offline"
    assert (
        proposal["release_status"]
        == "available_in_role_authorized_task_view_before_human_review"
    )
    assert proposal["frozen_before_assignment"] is True
    assert proposal["immutable_after_bundle_approval"] is True
    assert proposal["runtime_model_calls_allowed"] is False
    assert proposal["content_addressed_by"] == "proposal_hash"
    assert proposal["proposal_is_ground_truth"] is False
    assert labeler == {
        "config_id": "aamd-llm-first-labeler-32b-v1",
        "model_id": "Qwen/Qwen2.5-VL-32B-Instruct",
        "parameters": "32B",
        "model_revision": "7cfb30d71a1f4f49a57592323337a4a4727301da",
        "model_revision_status": "candidate_needs_G0_attestation",
        "prompt_template_hash": (
            "cfad4c64a0f0afa97db52b779e29f86220df6fd8b6a7fb6f5989f1d8bf27eab2"
        ),
        "decoding_config_hash": (
            "3725e1f6f82d2a4b469375f668431fd7c406314f0e3b57ac6d02b7af9e887add"
        ),
        "claim_bearing_requires_revision_status": "g0_attested",
        "trusted_g0_attestation_sha256": None,
        "trusted_claim_bundle_sha256": None,
        "bundle_self_assertion_sufficient": False,
    }


def test_event_chain_has_only_the_three_llm_first_stages() -> None:
    chain = _protocol()["event_chain"]

    assert chain["chain_version"] == "aamd-stage-chain-v2"
    assert chain["legacy_stages_disabled"] == ["initial", "reveal"]
    assert chain["stages"] == [
        {
            "stage": "final",
            "actor_role": "primary",
            "expected_version": 0,
            "previous_stage": None,
            "previous_event_hash": "GENESIS",
        },
        {
            "stage": "secondary",
            "actor_role": "secondary",
            "expected_version": 1,
            "previous_stage": "final",
            "previous_event_hash": "final.event_hash",
        },
        {
            "stage": "adjudicate",
            "actor_role": "adjudicator",
            "expected_version": 2,
            "previous_stage": "secondary",
            "previous_event_hash": "secondary.event_hash",
        },
    ]


def test_review_decisions_and_role_separation_are_exact() -> None:
    review = _protocol()["review_contract"]

    assert review["decisions"] == ["accept", "edit", "reject", "abstain"]
    assert review["decision_invariants"] == {
        "accept": "judgment_equals_frozen_proposal",
        "edit": "non_abstaining_judgment_differs_from_frozen_proposal",
        "reject": "non_abstaining_replacement_differs_from_frozen_proposal",
        "abstain": "judgment_abstain_is_true",
    }
    assert review["primary_and_secondary_must_be_distinct"] is True
    assert review["adjudicator_must_be_distinct_from_both_reviewers"] is True
    assert review["secondary_requires_locked_stage"] == "final"
    assert review["adjudication_requires_locked_stage"] == "secondary"
    assert review["prior_events_are_append_only"] is True


def test_primary_and_secondary_get_the_same_proposal_but_not_the_same_votes() -> None:
    protocol = _protocol()
    proposal = protocol["proposal_contract"]
    visibility = protocol["visibility_contract"]

    assert proposal["same_proposal_hash_required_for_roles"] == [
        "primary",
        "secondary",
    ]
    assert visibility["primary_proposal_visible"] is True
    assert visibility["secondary_proposal_visible"] is True
    assert visibility["primary_and_secondary_receive_identical_proposal_hash"] is True
    assert visibility["secondary_can_see_primary_vote"] is False
    assert set(visibility["secondary_response_must_omit"]) == {
        "primary_vote",
        "final.payload",
        "final.receipt",
    }
    assert visibility["secondary_receipt_may_include_opaque_previous_event_hash_after_lock"] is True


def test_outcome_method_and_raw_field_families_are_masked_everywhere() -> None:
    visibility = _protocol()["visibility_contract"]
    masked = visibility["masked_field_families"]

    assert set(masked) == {"outcome", "method", "raw"}
    assert {"outcome", "actual_outcome", "ground_truth", "strict_success"} <= set(
        masked["outcome"]
    )
    assert {"method", "attack_method", "attack_method_name", "attack_technique"} <= set(
        masked["method"]
    )
    assert {"raw", "raw_payload", "raw_prompt", "attack_text", "target_response"} <= set(
        masked["raw"]
    )
    assert set(visibility["masking_applies_to"]) == {
        "bundle_ingress",
        "stored_task",
        "stored_proposal",
        "reviewer_views",
        "admin_export",
    }


def test_provenance_is_required_for_bundle_proposal_events_and_export() -> None:
    provenance = _protocol()["provenance_contract"]

    assert set(provenance) == {
        "bundle_required_fields",
        "task_required_fields",
        "offline_proposal_manifest_required_fields",
        "offline_proposal_manifest_conditional_required_fields",
        "event_required_fields",
        "export_required_fields",
    }
    assert {
        "proposal_id",
        "proposal_hash",
        "labeler_config_id",
        "model_id",
        "parameters",
        "model_revision",
        "model_revision_status",
        "prompt_template_hash",
        "decoding_config_hash",
        "seed",
        "generator_code_revision",
        "generated_at",
        "source_bundle_hash",
    } == set(provenance["offline_proposal_manifest_required_fields"])
    assert provenance["offline_proposal_manifest_conditional_required_fields"] == {
        "g0_attestation_hash": "model_revision_status == g0_attested"
    }
    assert {
        "event_id",
        "event_hash",
        "previous_event_hash",
        "payload_hash",
        "request_hash",
        "expected_version",
        "server_received_at",
        "chain_version",
        "signature_algorithm",
    } == set(provenance["event_required_fields"])
    assert {"export_hash", "export_signature", "signature_algorithm", "generated_at"} == set(
        provenance["export_required_fields"]
    )


def test_metrics_do_not_support_anchoring_or_accuracy_claims_without_blind_experts() -> None:
    metrics = _protocol()["metrics_and_claims"]
    subset = metrics["proposal_blind_expert_subset"]
    gates = metrics["claim_gates"]

    assert set(metrics["always_report_descriptive_metrics"]) == {
        "decision_rate_by_role_and_decision",
        "primary_secondary_label_agreement",
        "primary_secondary_decision_agreement",
        "adjudication_rate",
        "abstention_rate_by_role",
        "edit_distance_from_frozen_proposal",
        "review_duration_by_role",
        "missingness_and_failure_rate",
    }
    assert subset == {
        "proposal_visible": False,
        "experts_independent_of_workflow_reviewers": True,
        "sampling_and_analysis_preregistered": True,
        "reference_locked_before_workflow_linkage": True,
    }
    assert set(gates) == {"anchoring", "accuracy"}
    for claim in ("anchoring", "accuracy"):
        assert gates[claim] == {
            "allowed_without_proposal_blind_expert_subset": False,
            "requires": "proposal_blind_expert_subset",
        }
    assert metrics["human_review_implies_ground_truth"] is False
    assert metrics["proposal_human_agreement_is_accuracy"] is False
