from __future__ import annotations

import copy
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from defense_arena.adaptive_attack_memory_dataset import (
    ATTACK_ARM_IDS,
    BLOCKER_IDS,
    DatasetValidationError,
    EVIDENCE_LEVEL_IDS,
    GATE_IDS,
    RECORD_FAMILY_IDS,
    RELEASE_TIER_IDS,
    load_json,
    validate_dataset_bundle,
    validate_dataset_config,
    validate_dataset_record,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs" / "adaptive_attack_memory_dataset_v1.json"
SCHEMA = ROOT / "schemas" / "adaptive-attack-memory-dataset-config-v1.schema.json"
RECORD_SCHEMA = ROOT / "schemas" / "adaptive-attack-memory-record-v1.schema.json"
SCRIPT = ROOT / "scripts" / "validate_adaptive_attack_memory_dataset.py"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _validate_changed(tmp_path: Path, payload: dict, schema: dict | None = None) -> dict:
    config_path = _write(tmp_path / "aamd.json", payload)
    schema_path = SCHEMA if schema is None else _write(tmp_path / "aamd.schema.json", schema)
    return validate_dataset_bundle(config_path, schema_path)


def _family(raw: dict, identifier: str) -> dict:
    return next(row for row in raw["record_families"] if row["id"] == identifier)


def _schema_sample(node: dict, root: dict) -> object:
    if "$ref" in node:
        target: object = root
        for encoded in node["$ref"][2:].split("/"):
            key = encoded.replace("~1", "/").replace("~0", "~")
            assert isinstance(target, dict)
            target = target[key]
        assert isinstance(target, dict)
        return _schema_sample(target, root)
    if "const" in node:
        return copy.deepcopy(node["const"])
    if "enum" in node:
        return copy.deepcopy(node["enum"][0])
    if "oneOf" in node:
        return _schema_sample(node["oneOf"][0], root)

    declared = node.get("type")
    if isinstance(declared, list):
        declared = declared[0]
    if declared == "object" or "properties" in node:
        properties = node.get("properties", {})
        value = {
            key: _schema_sample(properties[key], root)
            for key in node.get("required", [])
        }
        return _repair_schema_sample(value)
    if declared == "array":
        count = node.get("minItems", 0)
        return [_schema_sample(node["items"], root) for _ in range(count)]
    if declared == "boolean":
        return False
    if declared == "integer":
        return int(node.get("minimum", 0))
    if declared == "number":
        if "exclusiveMinimum" in node and "exclusiveMaximum" in node:
            return (node["exclusiveMinimum"] + node["exclusiveMaximum"]) / 2
        if "exclusiveMinimum" in node:
            return node["exclusiveMinimum"] + 0.5
        return node.get("minimum", 0)
    if declared == "null":
        return None
    if declared == "string":
        if node.get("format") == "date-time":
            return "2026-11-16T00:00:00Z"
        pattern = node.get("pattern", "")
        if pattern == "^[0-9a-f]{64}$":
            return "0" * 64
        if pattern == "^(none|uncertain|unmapped|[A-Z][A-Z0-9_.-]{0,63})$":
            return "none"
        return "id"
    raise AssertionError(f"test sample generator cannot materialize schema node: {node}")


def _repair_schema_sample(value: object) -> object:
    if isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = _repair_schema_sample(item)
        return value
    if not isinstance(value, dict):
        return value
    for key, item in list(value.items()):
        value[key] = _repair_schema_sample(item)

    if value.get("receipt_status") == "consumed" and "source_event_ids" in value:
        value["source_event_ids"] = ["source-event"]
        value["target_response_event_ids"] = ["response-event"]
        value["rendered_context_hash"] = "1" * 64
    if {"status", "adjudicator_handle", "final_labels", "decided_at"} <= set(value):
        value.update(
            status="pending_required",
            adjudicator_handle=None,
            final_labels=[],
            reason_code="pending",
            decided_at=None,
            event_hash=None,
        )
    if {"selected", "consumed", "memory_use_receipt_id"} <= set(value):
        value.update(selected=False, consumed=False, memory_use_receipt_id=None)
    return value


def _record(record_type: str) -> dict:
    schema = _json(RECORD_SCHEMA)
    payload = _schema_sample(schema["$defs"][f"{record_type}_payload"], schema)
    return {
        "schema_version": "adaptive-attack-memory-record-v1",
        "dataset_id": "adaptive-attack-memory-dataset-v1",
        "record_type": record_type,
        "record_id": f"record:{record_type}",
        "run_id": "run:test",
        "event_id": f"event:{record_type}",
        "created_at": "2026-11-16T00:00:00Z",
        "event_hash": "a" * 64,
        "previous_event_hash": None,
        "source_manifest_hash": "b" * 64,
        "release_tier": "public",
        "payload": payload,
    }


def test_reference_bundle_is_valid_but_not_claim_ready() -> None:
    summary = validate_dataset_bundle(CONFIG, SCHEMA)

    assert summary["valid"] is True
    assert summary["claim_ready"] is False
    assert summary["status"] == "preregistration_candidate_not_run"
    assert summary["defense_validation_status"] == "not_run"
    assert tuple(summary["record_families"]) == RECORD_FAMILY_IDS
    assert tuple(summary["evidence_levels"]) == EVIDENCE_LEVEL_IDS
    assert tuple(summary["attack_side_arms"]) == ATTACK_ARM_IDS
    assert tuple(summary["release_tiers"]) == RELEASE_TIER_IDS
    assert tuple(summary["gates"]) == GATE_IDS
    assert tuple(summary["blockers"]) == BLOCKER_IDS
    assert summary["minimum_independent_consumers"] == 2
    assert summary["next_gate"] == "G0"
    assert all(len(value) == 64 for value in summary["sha256"].values())


def test_cli_emits_machine_readable_summary_without_model_or_gpu_calls() -> None:
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
    assert summary["claim_ready"] is False
    assert summary["next_gate"] == "G0"


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version": 1, "schema_version": 1}\n', encoding="utf-8")

    with pytest.raises(DatasetValidationError, match="duplicate JSON key"):
        load_json(path)


def test_reference_contract_keeps_attack_memory_and_annotation_evidence_separate() -> None:
    raw = _json(CONFIG)
    levels = raw["evidence_ladder"]

    assert [row["name"] for row in levels["levels"]] == [
        "observed_trace",
        "response_attested_transition",
        "write_attested_candidate",
        "lifecycle_attested_memory",
        "retrieval_consumed_memory",
        "attack_effect_tested_memory",
        "defense_effect_tested_abstraction",
    ]
    assert levels["minimum_level_for_stored_memory_claim"] == "M3"
    assert levels["minimum_level_for_memory_mediated_attack_claim"] == "M4"
    assert levels["minimum_level_for_attack_causal_utility_claim"] == "M5"
    assert levels["minimum_level_for_defense_actionability_claim"] == "M6"
    assert raw["annotation_contract"]["llm_is_proposer_not_ground_truth"] is True


def test_empty_arm_uses_an_explicit_non_memory_control_provenance() -> None:
    raw = _json(CONFIG)
    origins = raw["collection_contract"]["memory_origins"]

    assert [row["id"] for row in origins] == [
        "native_adaptive_state",
        "harmonized_external_memory",
        "no_memory_control",
    ]
    assert origins[-1]["required_label"] == "control"
    assert "never eligible for a stored-memory claim" in origins[-1]["definition"]


def test_prior_method_baselines_are_explicitly_audit_bounded() -> None:
    raw = _json(CONFIG)["defense_actionability"]
    prior = raw["prior_method_baselines"]

    assert [row["id"] for row in prior["methods"]] == ["icag", "safetymem", "armor"]
    assert [row["display_name"] for row in prior["methods"]] == ["ICAG", "SafetyMem", "ARMOR"]
    assert all(
        row["audit_status"] == "subject_to_code_license_and_reproducibility_audit"
        for row in prior["methods"]
    )
    assert raw["all_aamd_internal_prompt_comparisons_token_matched"] is True
    assert raw["prior_method_baselines_mechanism_matched"] is True


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda raw: raw["claim_boundary"].update(claim_ready=True), "cannot be claim ready"),
        (
            lambda raw: raw["claim_boundary"].update(official_arms_reproduction_claimed=True),
            "official ARMS reproduction cannot be claimed",
        ),
        (
            lambda raw: raw["claim_boundary"].update(legacy_pack_claim_bearing=True),
            "legacy pack cannot become claim bearing",
        ),
        (lambda raw: raw["record_families"].pop(), "record families must be ordered exactly"),
        (
            lambda raw: _family(raw, "turn")["required_core_fields"].remove("attacker_input_hash"),
            "semantic receipt fields changed",
        ),
        (
            lambda raw: raw["evidence_ladder"]["levels"][4].update(name="retrieval_observed_memory"),
            "evidence level names must be ordered exactly",
        ),
        (
            lambda raw: raw["evidence_ladder"].update(minimum_level_for_stored_memory_claim="M2"),
            "stored-memory claims require M3",
        ),
        (
            lambda raw: raw["evidence_ladder"].update(
                minimum_level_for_memory_mediated_attack_claim="M3"
            ),
            "memory-mediated attack claims require M4",
        ),
        (
            lambda raw: raw["evidence_ladder"].update(
                minimum_level_for_attack_causal_utility_claim="M4"
            ),
            "causal attack-utility claims require M5",
        ),
        (
            lambda raw: raw["collection_contract"].update(claim_bearing_collection_started=True),
            "cannot claim collection has started",
        ),
        (
            lambda raw: raw["collection_contract"].update(outcome_based_sampling_prohibited=False),
            "outcome_based_sampling_prohibited=true",
        ),
        (
            lambda raw: raw["collection_contract"]["required_receipts"].remove(
                "exact_attacker_input_exposure_hash"
            ),
            "missing required receipts",
        ),
        (
            lambda raw: raw["attack_side_validation"]["arms"].pop(),
            "attack-side arms must be exactly",
        ),
        (
            lambda raw: raw["attack_side_validation"]["arms"][0].update(live_adaptive=False),
            "must use live adaptation",
        ),
        (
            lambda raw: raw["attack_side_validation"].update(
                frozen_replay_allowed_as_primary_evidence=True
            ),
            "frozen replay cannot support",
        ),
        (
            lambda raw: raw["attack_side_validation"].update(
                item_level_claim_requires_leave_one_item_out_or_item_intervention=False
            ),
            "item_level_claim_requires_leave_one_item_out_or_item_intervention=true",
        ),
        (
            lambda raw: raw["annotation_contract"].update(
                human_initial_locked_before_llm_proposal=False
            ),
            "human_initial_locked_before_llm_proposal=true",
        ),
        (
            lambda raw: raw["annotation_contract"].update(confirmation_relabeling_allowed=True),
            "confirmation relabeling must remain forbidden",
        ),
        (
            lambda raw: raw["annotation_contract"]["anchoring_audit_conditions"].pop(),
            "anchoring audit conditions were weakened",
        ),
        (
            lambda raw: raw["annotation_contract"].update(
                independent_expert_reference_required=False
            ),
            "independent_expert_reference_required=true",
        ),
        (
            lambda raw: raw["split_policy"]["leave_one_method_out"][
                "held_out_method_excluded_from"
            ].remove("memory compilation"),
            "held-out isolation is missing stages",
        ),
        (
            lambda raw: raw["split_policy"]["temporal_isolation"].update(required=False),
            "temporal isolation is required",
        ),
        (
            lambda raw: raw["split_policy"].update(
                exact_and_semantic_cluster_overlap_across_splits_allowed=True
            ),
            "cross-split exact or semantic overlap is forbidden",
        ),
        (
            lambda raw: raw["split_policy"].update(assignment_unit="semantic_behavior_cluster"),
            "connected lineage components",
        ),
        (
            lambda raw: raw["split_policy"]["lineage_keys"].remove("memory_derivation_parent"),
            "split lineage graph must cover",
        ),
        (
            lambda raw: raw["defense_actionability"].update(minimum_independent_consumers=1),
            "at least two independent defense consumers",
        ),
        (
            lambda raw: raw["defense_actionability"].update(
                all_aamd_internal_prompt_comparisons_token_matched=False
            ),
            "all_aamd_internal_prompt_comparisons_token_matched=true",
        ),
        (
            lambda raw: raw["defense_actionability"]["prior_method_baselines"]["methods"].pop(),
            "prior-method baselines must be ordered exactly",
        ),
        (
            lambda raw: raw["defense_actionability"]["prior_method_baselines"]["methods"][0].update(
                audit_status="available"
            ),
            "must remain subject to reproducibility audit",
        ),
        (
            lambda raw: raw["release_policy"].update(public_payload_leakage_tolerance=1),
            "payload leakage tolerance must remain zero",
        ),
        (
            lambda raw: raw["release_policy"].update(
                raw_sha256_of_sensitive_content_public=True
            ),
            "raw SHA-256 commitments of sensitive content cannot be public",
        ),
        (
            lambda raw: raw["storage_policy"].update(
                source_repository_capacity_growing_artifacts_allowed=True
            ),
            "capacity-growing artifacts cannot be stored",
        ),
        (
            lambda raw: raw["storage_policy"].update(temporary_root="/tmp/aamd"),
            "must be a scoped child of the runtime root|cannot use root /tmp",
        ),
        (
            lambda raw: raw["gates"][0].update(current_status="passed"),
            "cannot mark G0 passed",
        ),
        (
            lambda raw: raw["current_readiness"].update(claim_ready=True),
            "readiness cannot claim completion",
        ),
    ],
)
def test_semantic_weakening_fails_closed(
    mutator: Callable[[dict], object], message: str
) -> None:
    raw = copy.deepcopy(_json(CONFIG))
    mutator(raw)

    with pytest.raises(DatasetValidationError, match=message):
        validate_dataset_config(raw)


def test_unknown_config_field_is_rejected_by_schema(tmp_path: Path) -> None:
    raw = copy.deepcopy(_json(CONFIG))
    raw["unregistered_release_switch"] = False

    with pytest.raises(DatasetValidationError, match="schema-forbidden keys"):
        _validate_changed(tmp_path, raw)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda schema: schema.update(additionalProperties=True),
        lambda schema: schema["required"].remove("current_readiness"),
        lambda schema: schema["properties"].pop("current_readiness"),
    ],
)
def test_schema_contract_cannot_be_weakened(tmp_path: Path, mutator: Callable[[dict], object]) -> None:
    schema = copy.deepcopy(_json(SCHEMA))
    mutator(schema)

    with pytest.raises(DatasetValidationError, match="schema root|schema.required|schema.properties"):
        _validate_changed(tmp_path, _json(CONFIG), schema)


def test_schema_cannot_resolve_external_references(tmp_path: Path) -> None:
    schema = copy.deepcopy(_json(SCHEMA))
    schema["properties"]["claim_boundary"] = {"$ref": "https://example.invalid/schema.json"}

    with pytest.raises(DatasetValidationError, match="non-local JSON Schema reference"):
        _validate_changed(tmp_path, _json(CONFIG), schema)


@pytest.mark.parametrize("record_type", RECORD_FAMILY_IDS)
def test_record_schema_accepts_a_representative_record_for_every_family(record_type: str) -> None:
    summary = validate_dataset_record(_record(record_type), _json(RECORD_SCHEMA))

    assert summary["valid"] is True
    assert summary["record_type"] == record_type
    assert summary["release_tier"] == "public"


def test_record_schema_rejects_unknown_and_raw_payload_fields() -> None:
    unknown = _record("turn")
    unknown["unregistered_field"] = False
    with pytest.raises(DatasetValidationError, match="schema-forbidden keys"):
        validate_dataset_record(unknown, _json(RECORD_SCHEMA))

    raw = _record("turn")
    raw["payload"]["raw_response"] = "forbidden"
    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(raw, _json(RECORD_SCHEMA))


def test_record_type_must_match_its_discriminated_payload() -> None:
    record = _record("episode")
    record["record_type"] = "turn"

    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(record, _json(RECORD_SCHEMA))


def test_consumed_retrieval_requires_selection_and_a_use_receipt() -> None:
    record = _record("memory_retrieval")
    record["payload"].update(consumed=True, selected=False, memory_use_receipt_id=None)

    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(record, _json(RECORD_SCHEMA))


def test_adaptive_core_transition_requires_an_explicit_consumption_receipt() -> None:
    record = _record("adaptation_transition")
    record["payload"].update(adaptive_core_eligible=True, edge_evidence_type="inferred_order")

    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(record, _json(RECORD_SCHEMA))


def test_annotation_initial_vote_is_blind_to_the_llm_proposal() -> None:
    record = _record("annotation_event")
    record["payload"]["human_initial"]["llm_proposal_visible"] = True

    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(record, _json(RECORD_SCHEMA))


def test_attack_counterfactual_accepts_only_the_four_registered_live_arms() -> None:
    schema = _json(RECORD_SCHEMA)
    for arm_id in ATTACK_ARM_IDS:
        record = _record("attack_counterfactual_trial")
        record["payload"]["arm_id"] = arm_id
        assert validate_dataset_record(record, schema)["valid"] is True

    invalid = _record("attack_counterfactual_trial")
    invalid["payload"]["arm_id"] = "intact_matched"
    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(invalid, schema)


def test_record_release_and_split_enums_fail_closed() -> None:
    schema = _json(RECORD_SCHEMA)
    bad_release = _record("episode")
    bad_release["release_tier"] = "public_payload_free"
    with pytest.raises(DatasetValidationError, match="JSON Schema enum"):
        validate_dataset_record(bad_release, schema)

    bad_split = _record("episode")
    bad_split["payload"]["split"] = "test"
    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(bad_split, schema)


def test_record_schema_contract_cannot_drop_or_add_record_branches() -> None:
    schema = copy.deepcopy(_json(RECORD_SCHEMA))
    schema["oneOf"].pop()

    with pytest.raises(DatasetValidationError, match="record schema branches must be ordered exactly"):
        validate_dataset_record(_record("episode"), schema)


def test_record_schema_conditionals_are_enforced_by_the_offline_validator() -> None:
    record = _record("memory_retrieval")
    record["payload"].update(consumed=True, selected=True, memory_use_receipt_id="use-receipt")
    assert validate_dataset_record(record, _json(RECORD_SCHEMA))["valid"] is True

    record["payload"]["memory_use_receipt_id"] = None
    with pytest.raises(DatasetValidationError, match="exactly one JSON Schema branch"):
        validate_dataset_record(record, _json(RECORD_SCHEMA))
