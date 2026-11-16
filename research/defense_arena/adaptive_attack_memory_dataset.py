"""Offline, fail-closed validation for the AAMD-v1 dataset contract.

This module validates only the public, machine-readable preregistration.  It
does not import model runtimes, inspect accelerators, contact the network, or
start services.  JSON Schema catches structural drift; the semantic checks
below protect protocol invariants that are awkward to express in a schema and
easy to weaken accidentally.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse


TOP_LEVEL_FIELDS = (
    "schema_version",
    "dataset_id",
    "short_name",
    "status",
    "as_of",
    "claim_boundary",
    "source_bundle",
    "contributions",
    "research_questions",
    "record_families",
    "evidence_ladder",
    "collection_contract",
    "attack_side_validation",
    "annotation_contract",
    "split_policy",
    "defense_actionability",
    "release_policy",
    "storage_policy",
    "gates",
    "current_readiness",
)

CONTRIBUTION_IDS = ("C1", "C2", "C3", "C4")
RESEARCH_QUESTION_IDS = ("RQ-D1", "RQ-D2", "RQ-D3", "RQ-D4", "RQ-D5")
RECORD_FAMILY_IDS = (
    "episode",
    "turn",
    "adaptation_transition",
    "memory_candidate",
    "memory_write_decision",
    "memory_retrieval",
    "memory_use_receipt",
    "annotation_event",
    "attack_counterfactual_trial",
    "defense_affordance",
    "defense_validation_trial",
    "artifact_manifest",
)
RECORD_TOP_LEVEL_FIELDS = (
    "schema_version",
    "dataset_id",
    "record_type",
    "record_id",
    "run_id",
    "event_id",
    "created_at",
    "event_hash",
    "previous_event_hash",
    "source_manifest_hash",
    "release_tier",
    "payload",
)
EVIDENCE_LEVEL_IDS = tuple(f"M{index}" for index in range(7))
EVIDENCE_LEVEL_NAMES = (
    "observed_trace",
    "response_attested_transition",
    "write_attested_candidate",
    "lifecycle_attested_memory",
    "retrieval_consumed_memory",
    "attack_effect_tested_memory",
    "defense_effect_tested_abstraction",
)
EVIDENCE_PROMOTION_GATES = ("G2", "G3", "G3", "G4", "G4", "G4", "G6")
MEMORY_ORIGIN_IDS = ("native_adaptive_state", "harmonized_external_memory", "no_memory_control")
ATTACK_ARM_IDS = ("intact", "linkage_shuffled", "unrelated_same_token", "empty")
SPLIT_PHASE_IDS = (
    "excluded_pilot",
    "build_induction",
    "build_application",
    "selection",
    "confirmation",
)
RELEASE_TIER_IDS = ("public", "controlled", "sealed")
GATE_IDS = tuple(f"G{index}" for index in range(7))
BLOCKER_IDS = tuple(f"B{index:02d}" for index in range(1, 9))

REQUIRED_RECORD_FIELDS = {
    "episode": (
        "episode_id", "run_id", "method_id", "method_revision", "memory_origin",
        "target_model_revision", "attacker_model_revision", "judge_model_revision",
        "behavior_cluster_handle", "seed", "budget", "terminal_status",
    ),
    "turn": (
        "turn_id", "episode_id", "turn_index", "attacker_input_hash", "target_response_hash",
        "modality_receipt", "runtime_timestamp",
    ),
    "adaptation_transition": (
        "transition_id",
        "episode_id",
        "predecessor_turn_id",
        "response_signal_code",
        "next_operation_code",
        "edge_evidence_type",
        "source_event_hash",
    ),
    "memory_candidate": (
        "memory_candidate_id", "source_transition_ids", "memory_origin", "abstraction_hash", "scope",
        "evidence_strength", "candidate_status",
    ),
    "memory_write_decision": (
        "write_event_id",
        "memory_candidate_id",
        "decision",
        "reason_code",
        "memory_snapshot_before_hash",
        "memory_snapshot_after_hash",
        "event_hash",
        "previous_event_hash",
    ),
    "memory_retrieval": (
        "retrieval_event_id",
        "episode_id",
        "retrieval_query_hash",
        "memory_item_hash",
        "rank",
        "retrieval_score",
        "memory_snapshot_hash",
    ),
    "memory_use_receipt": (
        "use_receipt_id",
        "retrieval_event_id",
        "memory_item_hash",
        "attacker_input_hash",
        "exposure_position",
        "next_operation_hash",
        "runtime_identity_hash",
    ),
    "annotation_event": (
        "annotation_event_id",
        "subject_record_id",
        "visibility_mask_hash",
        "codebook_hash",
        "annotator_role",
        "labels",
        "evidence_handles",
        "lock_timestamp",
    ),
    "attack_counterfactual_trial": (
        "trial_id",
        "pairing_block_id",
        "arm_id",
        "memory_bundle_hash",
        "initial_state_hash",
        "seed",
        "budget_hash",
        "terminal_outcome",
        "cost_receipt",
    ),
    "defense_affordance": (
        "affordance_id",
        "source_memory_ids",
        "defense_invariant",
        "benign_exception",
        "predicted_readaptation",
        "evaluation_probe",
        "hypothesis_status",
    ),
    "defense_validation_trial": (
        "defense_trial_id",
        "consumer_id",
        "training_memory_manifest_hash",
        "system_prompt_hash",
        "system_prompt_tokens",
        "held_out_method_id",
        "target_model_revision",
        "safety_outcome",
        "utility_outcome",
        "overrefusal_outcome",
        "cost_receipt",
    ),
    "artifact_manifest": (
        "manifest_id",
        "dataset_version",
        "schema_hash",
        "codebook_hash",
        "source_hashes",
        "record_counts",
        "exclusion_counts",
        "release_tier",
        "manifest_hash",
    ),
}

REQUIRED_LIFECYCLE = (
    "experience_observed",
    "memory_candidate_written",
    "retain_merge_replace_reject_or_quarantine_decided",
    "later_memory_retrieved",
    "exact_memory_exposed_to_attacker",
    "next_operation_recorded",
    "outcome_recorded",
)
REQUIRED_RECEIPTS = {
    "append_only_event_hash_chain",
    "runtime_process_and_model_identity",
    "memory_snapshot_before_and_after_hashes",
    "retrieval_query_item_rank_score_and_snapshot",
    "exact_attacker_input_exposure_hash",
    "next_operation_hash",
    "target_attacker_judge_call_and_token_costs",
}
REQUIRED_BLINDED_FIELDS = {
    "attack_method_name",
    "target_parameter_scale",
    "split_name",
    "strict_success",
    "judge_score",
    "judge_reason",
    "defense_condition",
}
REQUIRED_ANNOTATION_OUTPUTS = {
    "response_signal",
    "adaptation_operator",
    "memory_role",
    "evidence_strength",
    "uncertain_none_or_unmapped_status",
    "evidence_handle",
    "defense_invariant_hypothesis",
    "benign_exception",
    "predicted_readaptation",
    "evaluation_probe",
}
REQUIRED_ANCHORING_CONDITIONS = (
    "human_only_delayed_reconsideration",
    "llm_only",
    "human_then_versioned_llm_proposal",
)
REQUIRED_HELD_OUT_EXCLUSIONS = {
    "fold-specific taxonomy induction",
    "annotation examples",
    "LLM proposer prompt examples",
    "memory compilation",
    "defense consumer training",
    "consumer and token-budget selection",
}
REQUIRED_LINEAGE_KEYS = {
    "base_behavior",
    "source_row_commitment",
    "paraphrase_cluster",
    "attack_template_family",
    "trajectory_parent",
    "memory_derivation_parent",
    "augmented_adapter_revision",
    "compiler_example_lineage",
}
REQUIRED_DEFENSE_BASELINES = {
    "generic_safety_prompt",
    "raw_memory_summary",
    "success_only_memory",
    "frequency_only_categories",
    "linkage_broken_transitions",
    "random_same_token_memory",
    "single_method_memory",
}
REQUIRED_DEFENSE_ENDPOINTS = {
    "cluster_macro_strict_episode_asr",
    "safe_horizon",
    "benign_utility_noninferiority",
    "gross_overrefusal",
    "system_prompt_tokens",
    "inference_cost",
    "attacker_readaptation_cost",
    "effect_uncertainty_by_method_target_and_behavior_domain",
}
PRIOR_METHOD_BASELINES = (
    ("icag", "ICAG"),
    ("safetymem", "SafetyMem"),
    ("armor", "ARMOR"),
)
PRIOR_METHOD_AUDIT_STATUS = "subject_to_code_license_and_reproducibility_audit"
REQUIRED_PUBLIC_EXCLUSIONS = {
    "raw harmful payloads",
    "raw target responses",
    "source row identifiers",
    "private split salts",
    "judge rationales",
}

FORBIDDEN_PAYLOAD_KEYS = {
    "attack_payload",
    "attack_prompt",
    "behavior_id",
    "behavior_text",
    "dataset_row_id",
    "judge_reason",
    "prompt_text",
    "query_text",
    "raw_harmful_payload",
    "raw_prompt",
    "raw_response",
    "source_row_id",
    "target_response",
}
SECRET_PATTERNS = (
    re.compile(r"github_pat_", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY"),
)


class DatasetValidationError(ValueError):
    """Raised when the AAMD-v1 machine-readable contract is weakened."""


def _fail(message: str) -> None:
    raise DatasetValidationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    """Read object-valued JSON while rejecting duplicate keys."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except DatasetValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read JSON {path}: {exc}")
    _require(isinstance(value, dict), f"JSON root must be an object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        _fail(f"cannot hash {path}: {exc}")
    return digest.hexdigest()


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    _require(isinstance(value, dict), f"{context} must be an object")
    return value


def _list(value: Any, context: str) -> list[Any]:
    _require(isinstance(value, list), f"{context} must be an array")
    return value


def _scalar_set(value: Any, context: str) -> set[Any]:
    rows = _list(value, context)
    _require(all(not isinstance(row, (dict, list)) for row in rows), f"{context} must contain scalars")
    _require(len(rows) == len(set(rows)), f"{context} contains duplicates")
    return set(rows)


def _ordered_ids(rows: Any, context: str) -> tuple[str, ...]:
    values = tuple(str(_mapping(row, f"{context}[]").get("id")) for row in _list(rows, context))
    _require(len(values) == len(set(values)), f"{context} contains duplicate ids")
    return values


def _resolve_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    _require(reference.startswith("#/"), f"only local JSON Schema refs are allowed: {reference}")
    current: Any = root
    for encoded in reference[2:].split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        _require(isinstance(current, dict) and part in current, f"unresolvable JSON Schema ref: {reference}")
        current = current[part]
    return _mapping(current, f"schema ref {reference}")


def _matches_type(value: Any, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "null":
        return value is None
    _fail(f"unsupported JSON Schema type: {type_name}")


def _schema_matches(value: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str) -> bool:
    try:
        _validate_schema_instance(value, schema, root, path)
    except DatasetValidationError:
        return False
    return True


def _validate_schema_instance(
    value: Any,
    schema: Mapping[str, Any],
    root: Mapping[str, Any],
    path: str = "$",
) -> None:
    """Validate the strict Draft 2020-12 subset used by the AAMD config."""

    if "$ref" in schema:
        _validate_schema_instance(value, _resolve_ref(root, str(schema["$ref"])), root, path)
        return
    if "allOf" in schema:
        for index, child in enumerate(_list(schema["allOf"], f"schema {path}.allOf")):
            _validate_schema_instance(value, _mapping(child, f"schema {path}.allOf[{index}]"), root, path)
    if "anyOf" in schema:
        children = _list(schema["anyOf"], f"schema {path}.anyOf")
        _require(
            any(_schema_matches(value, _mapping(child, "schema anyOf[]"), root, path) for child in children),
            f"{path} does not match any JSON Schema branch",
        )
    if "oneOf" in schema:
        children = _list(schema["oneOf"], f"schema {path}.oneOf")
        matches = sum(_schema_matches(value, _mapping(child, "schema oneOf[]"), root, path) for child in children)
        _require(matches == 1, f"{path} must match exactly one JSON Schema branch")
    if "if" in schema:
        condition = _mapping(schema["if"], f"schema {path}.if")
        branch_name = "then" if _schema_matches(value, condition, root, path) else "else"
        if branch_name in schema:
            branch = _mapping(schema[branch_name], f"schema {path}.{branch_name}")
            _validate_schema_instance(value, branch, root, path)

    if "type" in schema:
        declared = schema["type"]
        choices = declared if isinstance(declared, list) else [declared]
        _require(any(_matches_type(value, str(choice)) for choice in choices),
                 f"{path} does not match JSON Schema type {choices}")
    if "const" in schema:
        _require(value == schema["const"], f"{path} does not match JSON Schema const")
    if "enum" in schema:
        _require(value in schema["enum"], f"{path} is not in the JSON Schema enum")

    if isinstance(value, dict):
        required = set(schema.get("required", []))
        missing = required - set(value)
        _require(not missing, f"{path} missing schema-required keys: {sorted(missing)}")
        if "minProperties" in schema:
            _require(len(value) >= int(schema["minProperties"]), f"{path} has too few properties")
        properties = _mapping(schema.get("properties", {}), f"schema {path}.properties")
        additional = schema.get("additionalProperties", True)
        if additional is False:
            extra = set(value) - set(properties)
            _require(not extra, f"{path} has schema-forbidden keys: {sorted(extra)}")
        for key, item in value.items():
            if key in properties:
                _validate_schema_instance(item, _mapping(properties[key], f"schema {path}.{key}"), root,
                                          f"{path}.{key}")
            elif isinstance(additional, dict):
                _validate_schema_instance(item, additional, root, f"{path}.{key}")
    elif isinstance(value, list):
        if "minItems" in schema:
            _require(len(value) >= int(schema["minItems"]), f"{path} has too few items")
        if "maxItems" in schema:
            _require(len(value) <= int(schema["maxItems"]), f"{path} has too many items")
        if schema.get("uniqueItems") is True:
            normalized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            _require(len(normalized) == len(set(normalized)), f"{path} has duplicate items")
        if "items" in schema:
            item_schema = _mapping(schema["items"], f"schema {path}.items")
            for index, item in enumerate(value):
                _validate_schema_instance(item, item_schema, root, f"{path}[{index}]")
    elif isinstance(value, str):
        if "minLength" in schema:
            _require(len(value) >= int(schema["minLength"]), f"{path} is too short")
        if "maxLength" in schema:
            _require(len(value) <= int(schema["maxLength"]), f"{path} is too long")
        if "pattern" in schema:
            _require(re.search(str(schema["pattern"]), value) is not None,
                     f"{path} does not match schema pattern")
        if schema.get("format") == "date":
            try:
                date.fromisoformat(value)
            except ValueError:
                _fail(f"{path} is not an ISO date")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                _fail(f"{path} is not an ISO date-time")
        if schema.get("format") == "uri":
            parsed = urlparse(value)
            _require(bool(parsed.scheme and parsed.netloc), f"{path} is not an absolute URI")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema:
            _require(value >= schema["minimum"], f"{path} is below schema minimum")
        if "maximum" in schema:
            _require(value <= schema["maximum"], f"{path} is above schema maximum")
        if "exclusiveMinimum" in schema:
            _require(value > schema["exclusiveMinimum"], f"{path} is not above exclusive minimum")
        if "exclusiveMaximum" in schema:
            _require(value < schema["exclusiveMaximum"], f"{path} is not below exclusive maximum")


def _walk_schema_refs(value: Any, context: str = "schema") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref":
                _require(isinstance(item, str) and item.startswith("#/"),
                         f"{context} contains a non-local JSON Schema reference")
            _walk_schema_refs(item, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_schema_refs(item, f"{context}[{index}]")


def _validate_schema_contract(schema: Mapping[str, Any]) -> None:
    _require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
             "dataset config schema must use JSON Schema draft 2020-12")
    _require(schema.get("type") == "object", "dataset config schema root must be object")
    _require(schema.get("additionalProperties") is False, "dataset config schema root must reject unknown keys")
    required = tuple(schema.get("required", []))
    _require(set(required) == set(TOP_LEVEL_FIELDS),
             "dataset config schema.required must exactly cover the registered top-level contract")
    properties = _mapping(schema.get("properties"), "schema.properties")
    _require(set(properties) == set(TOP_LEVEL_FIELDS),
             "dataset config schema.properties must exactly cover the registered top-level contract")
    _walk_schema_refs(schema)


def _validate_record_schema_contract(schema: Mapping[str, Any]) -> None:
    _require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
             "dataset record schema must use JSON Schema draft 2020-12")
    _require(schema.get("type") == "object", "dataset record schema root must be object")
    _require(schema.get("additionalProperties") is False,
             "dataset record schema root must reject unknown keys")
    required = tuple(schema.get("required", []))
    _require(required == RECORD_TOP_LEVEL_FIELDS,
             "dataset record schema.required must exactly preserve the canonical envelope")
    properties = _mapping(schema.get("properties"), "record schema.properties")
    _require(tuple(properties) == RECORD_TOP_LEVEL_FIELDS,
             "dataset record schema.properties must exactly preserve the canonical envelope")
    branches = _list(schema.get("oneOf"), "record schema.oneOf")
    branch_types: list[str] = []
    for index, row in enumerate(branches):
        branch = _mapping(row, f"record schema.oneOf[{index}]")
        _require(branch.get("type") == "object", "every record schema branch must be an object")
        _require(set(branch.get("required", [])) == {"record_type", "payload"},
                 "every record schema branch must bind record_type and payload")
        branch_properties = _mapping(branch.get("properties"),
                                     f"record schema.oneOf[{index}].properties")
        _require(set(branch_properties) == {"record_type", "payload"},
                 "record schema branch may bind only record_type and payload")
        record_type = _mapping(branch_properties["record_type"], "record schema branch record_type")
        payload = _mapping(branch_properties["payload"], "record schema branch payload")
        _require(isinstance(record_type.get("const"), str),
                 "record schema branch needs a constant record_type")
        _require(str(payload.get("$ref", "")).startswith("#/$defs/"),
                 "record schema branch payload must use a local definition")
        branch_types.append(str(record_type["const"]))
    _require(tuple(branch_types) == RECORD_FAMILY_IDS,
             f"record schema branches must be ordered exactly {RECORD_FAMILY_IDS}")
    record_type_property = _mapping(properties.get("record_type"), "record schema record_type")
    _require(tuple(record_type_property.get("enum", [])) == RECORD_FAMILY_IDS,
             f"record schema record_type enum must be exactly {RECORD_FAMILY_IDS}")
    _walk_schema_refs(schema, "record schema")


def _validate_claim_boundary(config: Mapping[str, Any]) -> None:
    boundary = _mapping(config.get("claim_boundary"), "claim_boundary")
    _require(boundary.get("claim_ready") is False, "candidate config cannot be claim ready")
    _require(boundary.get("official_arms_code_used") is False, "official ARMS code cannot be claimed")
    _require(boundary.get("official_arms_reproduction_claimed") is False,
             "official ARMS reproduction cannot be claimed")
    _require(boundary.get("defense_method_contribution_separate") is True,
             "dataset and defense-method contributions must remain separate")
    _require(boundary.get("legacy_pack_role") == "excluded_pilot_only",
             "legacy pack must remain an excluded pilot")
    _require(boundary.get("legacy_pack_claim_bearing") is False,
             "legacy pack cannot become claim bearing")
    blocked = _scalar_set(boundary.get("blocked_current_claims"), "claim_boundary.blocked_current_claims")
    for claim in ("dataset completion", "attack-memory causal efficacy", "defense efficacy"):
        _require(claim in blocked, f"candidate claim boundary must block {claim!r}")


def _validate_source_and_questions(config: Mapping[str, Any]) -> None:
    source = _mapping(config.get("source_bundle"), "source_bundle")
    _require(source.get("attack_universe_config") == "research/configs/adaptive_attack_universe_v1.json",
             "dataset must reference the registered attack universe")
    _require(source.get("behavior_registry_config") == "research/configs/behavior_registry_v1.json",
             "dataset must reference the registered behavior registry")
    _require(source.get("legacy_pilot_pack") == "research/artifacts/attack-memory-v1",
             "legacy pilot identity changed")
    _require(source.get("prospective_run_manifest") is None,
             "candidate config cannot invent a prospective run manifest")
    _require(source.get("source_status") == "candidate_inputs_not_frozen",
             "candidate input status cannot imply a completed freeze")
    _require(source.get("all_source_revisions_and_licenses_required_at_G0") is True,
             "G0 must attest all source revisions and licenses")
    _require(source.get("behavior_cluster_manifest_required_at_G2") is True,
             "G2 must require the behavior-cluster manifest")

    contributions = _list(config.get("contributions"), "contributions")
    _require(_ordered_ids(contributions, "contributions") == CONTRIBUTION_IDS,
             f"contributions must be ordered exactly {CONTRIBUTION_IDS}")
    for row in contributions:
        item = _mapping(row, "contributions[]")
        _require(bool(item.get("claim")), f"{item.get('id')} needs a claim")
        _require(bool(_list(item.get("required_evidence"), f"{item.get('id')}.required_evidence")),
                 f"{item.get('id')} needs required evidence")
        _require(item.get("claim_gate") in {"G4", "G6"}, f"{item.get('id')} has an invalid claim gate")

    questions = _list(config.get("research_questions"), "research_questions")
    _require(_ordered_ids(questions, "research_questions") == RESEARCH_QUESTION_IDS,
             f"research questions must be ordered exactly {RESEARCH_QUESTION_IDS}")
    for row in questions:
        item = _mapping(row, "research_questions[]")
        _require(item.get("tier") in {"primary", "secondary"}, f"{item.get('id')} needs a registered tier")
        _require(bool(item.get("primary_endpoint")), f"{item.get('id')} needs a primary endpoint")
        _require(item.get("claim_gate") in {"G4", "G6"}, f"{item.get('id')} has an invalid claim gate")


def _validate_record_contract(config: Mapping[str, Any]) -> None:
    rows = _list(config.get("record_families"), "record_families")
    _require(_ordered_ids(rows, "record_families") == RECORD_FAMILY_IDS,
             f"record families must be ordered exactly {RECORD_FAMILY_IDS}")
    for row in rows:
        item = _mapping(row, "record_families[]")
        identifier = str(item["id"])
        fields = tuple(_list(item.get("required_core_fields"),
                             f"record_families.{identifier}.required_core_fields"))
        _require(fields == REQUIRED_RECORD_FIELDS[identifier],
                 f"record family {identifier} semantic receipt fields changed")
        _require(bool(item.get("grain")) and bool(item.get("role")), f"record family {identifier} lacks grain or role")
        projection = str(item.get("public_projection", "")).lower()
        _require("raw" not in projection or "non_payload" in projection,
                 f"record family {identifier} cannot promise a raw public projection")

    ladder = _mapping(config.get("evidence_ladder"), "evidence_ladder")
    levels = _list(ladder.get("levels"), "evidence_ladder.levels")
    _require(_ordered_ids(levels, "evidence_ladder.levels") == EVIDENCE_LEVEL_IDS,
             f"evidence ladder must be ordered exactly {EVIDENCE_LEVEL_IDS}")
    names = tuple(str(_mapping(row, "evidence_ladder.levels[]").get("name")) for row in levels)
    _require(names == EVIDENCE_LEVEL_NAMES,
             f"evidence level names must be ordered exactly {EVIDENCE_LEVEL_NAMES}")
    gates = tuple(str(_mapping(row, "evidence_ladder.levels[]").get("promotion_gate")) for row in levels)
    _require(gates == EVIDENCE_PROMOTION_GATES,
             f"evidence promotion gates must be {EVIDENCE_PROMOTION_GATES}")
    _require(ladder.get("ordered") is True, "evidence ladder must remain ordered")
    _require(ladder.get("no_level_inferred_from_a_later_level") is True,
             "later evidence cannot backfill an earlier level")
    _require(ladder.get("negative_and_null_effect_records_retained") is True,
             "negative and null effects must be retained")
    _require(ladder.get("minimum_level_for_stored_memory_claim") == "M3",
             "stored-memory claims require M3 lifecycle evidence")
    _require(ladder.get("minimum_level_for_memory_mediated_attack_claim") == "M4",
             "memory-mediated attack claims require M4 consumption evidence")
    _require(ladder.get("minimum_level_for_attack_causal_utility_claim") == "M5",
             "causal attack-utility claims require M5 counterfactual evidence")
    _require(ladder.get("minimum_level_for_defense_actionability_claim") == "M6",
             "defense-actionability claims require M6 held-out evidence")


def _validate_collection(config: Mapping[str, Any]) -> None:
    contract = _mapping(config.get("collection_contract"), "collection_contract")
    _require(contract.get("mode") == "prospective_only_for_claim_bearing_data",
             "claim-bearing data must be prospectively collected")
    _require(contract.get("claim_bearing_collection_started") is False,
             "candidate config cannot claim collection has started")
    _require(tuple(contract.get("lifecycle_chain", [])) == REQUIRED_LIFECYCLE,
             "memory lifecycle chain was weakened or reordered")
    receipts = _scalar_set(contract.get("required_receipts"), "collection_contract.required_receipts")
    _require(REQUIRED_RECEIPTS <= receipts,
             f"collection contract is missing required receipts: {sorted(REQUIRED_RECEIPTS - receipts)}")
    feedback = str(contract.get("feedback_policy", ""))
    _require(
        feedback == "primary_claims_use_target_response_only_without_judge_score_reason_or_defense_prompt",
             "primary collection feedback must be target-response-only")
    for field in (
        "all_terminal_outcomes_retained",
        "outcome_based_sampling_prohibited",
        "sampling_and_budget_frozen_before_main_calls",
        "legacy_reconstruction_prohibited_for_causal_claims",
        "native_vs_augmented_never_conflated",
        "native_state_and_augmented_memory_results_reported_separately",
    ):
        _require(contract.get(field) is True, f"collection contract requires {field}=true")
    _require(contract.get("method_adapter_parity_gate") == "G1", "adapter parity must gate at G1")
    origins = _list(contract.get("memory_origins"), "collection_contract.memory_origins")
    _require(_ordered_ids(origins, "collection_contract.memory_origins") == MEMORY_ORIGIN_IDS,
             f"memory origins must be exactly {MEMORY_ORIGIN_IDS}")
    labels = tuple(str(_mapping(row, "memory_origins[]").get("required_label")) for row in origins)
    _require(
        labels == ("native", "augmented", "control"),
        "native, augmented, and reserved no-memory control labels must remain distinct",
    )
    control = _mapping(origins[2], "collection_contract.memory_origins[2]")
    _require(
        "never eligible for a stored-memory claim" in str(control.get("definition", "")),
        "no_memory_control must remain ineligible for stored-memory claims",
    )


def _validate_attack_side(config: Mapping[str, Any]) -> None:
    contract = _mapping(config.get("attack_side_validation"), "attack_side_validation")
    _require(contract.get("status") == "not_run", "attack-side validation cannot be pre-completed")
    _require(contract.get("primary_comparison") == "intact_vs_linkage_shuffled",
             "primary attack-side comparison must remain intact vs linkage-shuffled")
    arms = _list(contract.get("arms"), "attack_side_validation.arms")
    _require(_ordered_ids(arms, "attack_side_validation.arms") == ATTACK_ARM_IDS,
             f"attack-side arms must be exactly {ATTACK_ARM_IDS}")
    by_id = {str(row["id"]): _mapping(row, "attack_side_validation.arms[]") for row in arms}
    for identifier in ATTACK_ARM_IDS:
        _require(by_id[identifier].get("live_adaptive") is True,
                 f"attack-side arm {identifier} must use live adaptation")
    for identifier in ATTACK_ARM_IDS[:-1]:
        _require(by_id[identifier].get("same_token_requirement") is True,
                 f"attack-side arm {identifier} must be token matched")
    _require(by_id["empty"].get("same_token_requirement") is False,
             "empty-memory arm must remain an explicitly unmatched diagnostic")
    for field in (
        "same_initial_state_seed_behavior_target_and_budget_within_pairing_block",
        "fresh_target_responses_and_attacker_readaptation_in_every_arm",
        "negative_null_and_reversed_effects_retained",
        "confirmation_outcome_cannot_change_memory_membership",
    ):
        _require(contract.get(field) is True, f"attack-side validation requires {field}=true")
    _require(contract.get("frozen_replay_allowed_as_primary_evidence") is False,
             "frozen replay cannot support the primary adaptive claim")
    _require(contract.get("analysis_unit") == "episode_or_semantic_behavior_cluster",
             "turns cannot be treated as independent attack-side samples")
    _require(
        tuple(contract.get("validation_units", [])) == ("item", "bundle", "compiler"),
        "attack-side validation units must distinguish item, bundle, and compiler scopes",
    )
    for field in (
        "claim_scope_matches_intervention_unit",
        "item_level_claim_requires_leave_one_item_out_or_item_intervention",
        "arm_memory_snapshots_isolated",
        "execution_order_randomized_within_pairing_block",
        "linkage_shuffle_manipulation_check_required",
    ):
        _require(contract.get(field) is True, f"attack-side validation requires {field}=true")
    metrics = _scalar_set(contract.get("required_metrics"), "attack_side_validation.required_metrics")
    _require("paired_effect_estimate_with_95_percent_confidence_interval" in metrics,
             "attack-side validation must report paired uncertainty")


def _validate_annotation(config: Mapping[str, Any]) -> None:
    contract = _mapping(config.get("annotation_contract"), "annotation_contract")
    _require(contract.get("status") == "not_run", "annotation cannot be pre-completed")
    _require(contract.get("primary_unit") == "typed_adaptation_transition_with_bounded_context",
             "annotation primary unit changed")
    workflow = tuple(contract.get("workflow", []))
    expected_workflow = (
        "human_initial_blind_annotation_locked",
        "versioned_llm_proposal_generated",
        "human_post_proposal_decision_locked",
        "independent_second_human_vote_collected",
        "disagreement_adjudicated_without_overwriting_prior_events",
    )
    _require(workflow == expected_workflow, "blind-first annotation workflow was weakened or reordered")
    for field in (
        "human_initial_locked_before_llm_proposal",
        "llm_is_proposer_not_ground_truth",
        "human_initial_and_final_both_preserved",
        "suggestion_induced_label_shift_measured",
        "proposal_correctness_and_confidence_manipulation_preregistered",
        "independent_expert_reference_required",
        "model_revision_prompt_decoding_seed_and_codebook_hash_required",
    ):
        _require(contract.get(field) is True, f"annotation contract requires {field}=true")
    _require(
        tuple(contract.get("anchoring_audit_conditions", [])) == REQUIRED_ANCHORING_CONDITIONS,
        "anchoring audit conditions were weakened or reordered",
    )
    _require(
        contract.get("anchoring_condition_assignment")
        == "preregistered_randomized_annotator_by_task_block",
        "anchoring conditions must use preregistered randomized task-block assignment",
    )
    _require(contract.get("confirmation_relabeling_allowed") is False,
             "confirmation relabeling must remain forbidden")
    _require(contract.get("codebook_induction_allowed_only_in") == "build_induction",
             "codebook induction must remain build-induction-only")
    blinded = _scalar_set(contract.get("blinded_fields"), "annotation_contract.blinded_fields")
    _require(REQUIRED_BLINDED_FIELDS <= blinded,
             f"annotation blinding is missing fields: {sorted(REQUIRED_BLINDED_FIELDS - blinded)}")
    outputs = _scalar_set(contract.get("required_annotation_outputs"),
                          "annotation_contract.required_annotation_outputs")
    _require(REQUIRED_ANNOTATION_OUTPUTS <= outputs,
             f"annotation outputs are missing: {sorted(REQUIRED_ANNOTATION_OUTPUTS - outputs)}")


def _validate_splits(config: Mapping[str, Any]) -> None:
    policy = _mapping(config.get("split_policy"), "split_policy")
    _require(policy.get("split_unit") == "semantic_behavior_cluster",
             "split unit must remain the semantic behavior cluster")
    _require(
        policy.get("assignment_unit") == "connected_lineage_component",
        "split assignment must use connected lineage components",
    )
    lineage_keys = _scalar_set(policy.get("lineage_keys"), "split_policy.lineage_keys")
    _require(
        lineage_keys == REQUIRED_LINEAGE_KEYS,
        "split lineage graph must cover behavior, source, paraphrase, template, trajectory, memory, adapter, and compiler ancestry",
    )
    _require(
        policy.get("cross_split_lineage_component_overlap_allowed") is False,
        "cross-split lineage-component overlap is forbidden",
    )
    _require(
        policy.get("near_duplicate_audit") == "exact_plus_embedding_plus_blinded_llm_assisted",
        "near-duplicate audit must combine exact, embedding, and blinded LLM-assisted review",
    )
    _require(policy.get("episode_atomic") is True, "episodes must remain atomic across splits")
    phases = _list(policy.get("phases"), "split_policy.phases")
    _require(_ordered_ids(phases, "split_policy.phases") == SPLIT_PHASE_IDS,
             f"split phases must be ordered exactly {SPLIT_PHASE_IDS}")
    phase_map = {str(row["id"]): _mapping(row, "split_policy.phases[]") for row in phases}
    _require(phase_map["excluded_pilot"].get("claim_bearing") is False,
             "excluded pilot cannot be claim bearing")
    for identifier in SPLIT_PHASE_IDS[1:]:
        _require(phase_map[identifier].get("claim_bearing") is True,
                 f"registered phase {identifier} cannot silently leave the denominator")
    _require(phase_map["confirmation"].get("permitted_uses") == ["one sealed final evaluation"],
             "confirmation use must remain one sealed evaluation")

    lomo = _mapping(policy.get("leave_one_method_out"), "split_policy.leave_one_method_out")
    _require(lomo.get("enabled") is True, "leave-one-method-out isolation is required")
    exclusions = _scalar_set(lomo.get("held_out_method_excluded_from"),
                             "split_policy.leave_one_method_out.held_out_method_excluded_from")
    _require(REQUIRED_HELD_OUT_EXCLUSIONS <= exclusions,
             f"held-out isolation is missing stages: {sorted(REQUIRED_HELD_OUT_EXCLUSIONS - exclusions)}")
    _require(lomo.get("held_out_unmapped_policy") == "record_as_unmapped_without_post_hoc_codebook_change",
             "held-out novelties must remain unmapped")
    _require(lomo.get("all_registered_methods_held_out_once") is True,
             "every registered method must be held out once")

    temporal = _mapping(policy.get("temporal_isolation"), "split_policy.temporal_isolation")
    _require(temporal.get("required") is True, "temporal isolation is required")
    _require(temporal.get("may_change_taxonomy_or_consumers") is False,
             "temporal evaluation cannot retune taxonomy or consumers")
    _require(temporal.get("status") == "not_selected",
             "candidate config cannot imply a selected temporal holdout")
    _require(policy.get("universal_core_source") == "prior_work_and_permanently_excluded_legacy_pilot_only",
             "universal core may use only prior work and excluded pilots")
    _require(policy.get("universal_core_frozen_at") == "G0", "universal core must freeze at G0")
    _require(policy.get("fold_specific_subcodes_allowed_only_from_training_methods") is True,
             "fold-specific codes may use only training methods")
    _require(policy.get("exact_and_semantic_cluster_overlap_across_splits_allowed") is False,
             "cross-split exact or semantic overlap is forbidden")
    _require(policy.get("confirmation_openings") == 1, "confirmation may be opened exactly once")


def _validate_defense_actionability(config: Mapping[str, Any]) -> None:
    contract = _mapping(config.get("defense_actionability"), "defense_actionability")
    _require(contract.get("status") == "not_run", "defense actionability cannot be pre-completed")
    _require(contract.get("defense_hypotheses_are_gold_labels") is False,
             "defense hypotheses cannot be represented as gold observations")
    minimum = contract.get("minimum_independent_consumers")
    _require(isinstance(minimum, int) and not isinstance(minimum, bool) and minimum >= 2,
             "at least two independent defense consumers are required")
    consumers = _list(contract.get("candidate_consumers"), "defense_actionability.candidate_consumers")
    consumer_ids = _ordered_ids(consumers, "defense_actionability.candidate_consumers")
    classes = tuple(str(_mapping(row, "candidate_consumers[]").get("class")) for row in consumers)
    _require(len(consumer_ids) >= minimum and len(set(classes)) >= minimum,
             "candidate consumers must cover at least two independent classes")
    for row in consumers:
        _require(bool(_mapping(row, "candidate_consumers[]").get("independence_requirement")),
                 "every defense consumer needs an independence requirement")
    baselines = _scalar_set(contract.get("required_baselines"), "defense_actionability.required_baselines")
    _require(REQUIRED_DEFENSE_BASELINES <= baselines,
             f"defense baselines are missing: {sorted(REQUIRED_DEFENSE_BASELINES - baselines)}")
    endpoints = _scalar_set(contract.get("required_endpoints"), "defense_actionability.required_endpoints")
    _require(REQUIRED_DEFENSE_ENDPOINTS <= endpoints,
             f"defense endpoints are missing: {sorted(REQUIRED_DEFENSE_ENDPOINTS - endpoints)}")
    prior = _mapping(contract.get("prior_method_baselines"),
                     "defense_actionability.prior_method_baselines")
    _require(prior.get("comparison_policy") == "mechanism_matched_reporting_not_assumed_token_matched",
             "prior methods must be mechanism-matched and cannot be described as token matched")
    _require(
        prior.get("unavailable_policy")
        == "document_unavailability_and_audit_evidence_instead_of_silent_omission",
        "unavailable prior methods require an explicit reproducibility audit",
    )
    prior_methods = _list(prior.get("methods"), "defense_actionability.prior_method_baselines.methods")
    expected_ids = tuple(identifier for identifier, _ in PRIOR_METHOD_BASELINES)
    _require(_ordered_ids(prior_methods, "defense_actionability.prior_method_baselines.methods") == expected_ids,
             f"prior-method baselines must be ordered exactly {expected_ids}")
    expected_names = dict(PRIOR_METHOD_BASELINES)
    for row in prior_methods:
        method = _mapping(row, "defense_actionability.prior_method_baselines.methods[]")
        identifier = str(method.get("id"))
        _require(method.get("display_name") == expected_names[identifier],
                 f"prior-method baseline {identifier} display name changed")
        _require(method.get("audit_status") == PRIOR_METHOD_AUDIT_STATUS,
                 f"prior-method baseline {identifier} must remain subject to reproducibility audit")
        _require(bool(method.get("venue")) and bool(method.get("comparison_role")),
                 f"prior-method baseline {identifier} needs venue and comparison role")

    for field in (
        "all_aamd_internal_prompt_comparisons_token_matched",
        "prior_method_baselines_mechanism_matched",
        "live_attacker_readaptation_required",
        "utility_noninferiority_margin_frozen_before_selection",
        "dataset_claim_survives_failure_of_a_novel_compiler_only_if_reference_consumers_show_actionability",
    ):
        _require(contract.get(field) is True, f"defense actionability requires {field}=true")


def _validate_release_and_storage(config: Mapping[str, Any]) -> None:
    release = _mapping(config.get("release_policy"), "release_policy")
    _require(release.get("status") == "not_release_ready", "candidate config cannot be release ready")
    _require(
        release.get("public_sensitive_content_commitment") == "domain_separated_keyed_commitment",
        "public sensitive-content commitments must be domain-separated and keyed",
    )
    _require(
        release.get("raw_sha256_of_sensitive_content_public") is False,
        "raw SHA-256 commitments of sensitive content cannot be public",
    )
    _require(release.get("public_redacted_projection_hashes_allowed") is True,
             "public release must hash only redacted projections")
    _require(release.get("sealed_mapping_and_merkle_root_separate") is True,
             "sealed mappings and public Merkle roots must remain separate")
    tiers = _list(release.get("tiers"), "release_policy.tiers")
    _require(_ordered_ids(tiers, "release_policy.tiers") == RELEASE_TIER_IDS,
             f"release tiers must be ordered exactly {RELEASE_TIER_IDS}")
    tier_map = {str(row["id"]): _mapping(row, "release_policy.tiers[]") for row in tiers}
    public_excluded = _scalar_set(tier_map["public"].get("excluded"), "release_policy.public.excluded")
    _require(REQUIRED_PUBLIC_EXCLUSIONS <= public_excluded,
             f"public tier exclusions are missing: {sorted(REQUIRED_PUBLIC_EXCLUSIONS - public_excluded)}")
    _require("sealed confirmation cases" in _scalar_set(tier_map["controlled"].get("excluded"),
                                                         "release_policy.controlled.excluded"),
             "controlled tier must exclude sealed confirmation cases")
    _require("unreviewed external distribution" in _scalar_set(tier_map["sealed"].get("excluded"),
                                                                 "release_policy.sealed.excluded"),
             "sealed tier cannot permit unreviewed distribution")
    for field in (
        "datasheet_required",
        "license_and_dataset_terms_audit_required",
        "annotator_welfare_and_dual_use_review_required",
        "versioned_deprecation_and_removal_policy_required",
    ):
        _require(release.get(field) is True, f"release policy requires {field}=true")
    _require(release.get("public_payload_leakage_tolerance") == 0,
             "public payload leakage tolerance must remain zero")

    storage = _mapping(config.get("storage_policy"), "storage_policy")
    source_root = PurePosixPath(str(storage.get("source_repository_root", "")))
    runtime_root = PurePosixPath(str(storage.get("runtime_root", "")))
    _require(str(source_root) == "/home/ljk98/Amrs", "source repository root changed")
    _require(str(runtime_root) == "/data1/users/ljk98/Amrs-runtime", "runtime root changed")
    _require(storage.get("source_repository_capacity_growing_artifacts_allowed") is False,
             "capacity-growing artifacts cannot be stored in the source repository")
    for field in (
        "dataset_runtime_root",
        "experiment_root",
        "dataset_artifact_root",
        "cache_root",
        "temporary_root",
        "service_state_root",
    ):
        raw = str(storage.get(field, ""))
        path = PurePosixPath(raw)
        _require(path.is_absolute(), f"storage path {field} must be absolute")
        _require(path != runtime_root and runtime_root in path.parents,
                 f"storage path {field} must be a scoped child of the runtime root")
        _require(not raw.startswith("/tmp/"), f"storage path {field} cannot use root /tmp")
    for field in (
        "all_capacity_growing_paths_resolved_and_checked_before_launch",
        "root_filesystem_fail_closed",
        "run_scoped_temporary_data_removed_after_verified_cleanup",
    ):
        _require(storage.get(field) is True, f"storage policy requires {field}=true")


def _validate_gates_and_readiness(config: Mapping[str, Any]) -> None:
    gates = _list(config.get("gates"), "gates")
    _require(_ordered_ids(gates, "gates") == GATE_IDS, f"gates must be ordered exactly {GATE_IDS}")
    for row in gates:
        gate = _mapping(row, "gates[]")
        _require(gate.get("current_status") == "blocked",
                 f"candidate config cannot mark {gate.get('id')} passed")
        _require(bool(_list(gate.get("required_evidence"), f"{gate.get('id')}.required_evidence")),
                 f"{gate.get('id')} needs required evidence")
        _require(bool(gate.get("unlocks")), f"{gate.get('id')} needs an unlock boundary")

    readiness = _mapping(config.get("current_readiness"), "current_readiness")
    _require(readiness.get("overall_status") == "blocked_before_G0",
             "candidate readiness must remain blocked before G0")
    _require(readiness.get("next_gate") == "G0", "next gate must remain G0")
    _require(readiness.get("claim_ready") is False, "readiness cannot claim completion")
    blockers = _list(readiness.get("blockers"), "current_readiness.blockers")
    _require(_ordered_ids(blockers, "current_readiness.blockers") == BLOCKER_IDS,
             f"current blockers must be ordered exactly {BLOCKER_IDS}")
    for row in blockers:
        blocker = _mapping(row, "current_readiness.blockers[]")
        _require(blocker.get("blocking_gate") in GATE_IDS,
                 f"{blocker.get('id')} has an invalid blocking gate")
        _require(bool(blocker.get("description")) and bool(blocker.get("resolution")),
                 f"{blocker.get('id')} needs a description and resolution")


def _scan_public_config(value: Any, context: str = "config") -> None:
    """Reject payload fields and secrets; registered storage paths are checked separately."""

    if isinstance(value, dict):
        for key, item in value.items():
            _require(key not in FORBIDDEN_PAYLOAD_KEYS,
                     f"{context} contains forbidden payload-bearing key {key!r}")
            _scan_public_config(item, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_public_config(item, f"{context}[{index}]")
    elif isinstance(value, str):
        for pattern in SECRET_PATTERNS:
            _require(pattern.search(value) is None, f"{context} contains a secret-like value")


def validate_dataset_config(config: Mapping[str, Any]) -> None:
    """Enforce semantic invariants for an unfrozen AAMD-v1 candidate."""

    _require(tuple(config.keys()) == TOP_LEVEL_FIELDS,
             "dataset config top-level keys or their canonical order changed")
    _require(config.get("schema_version") == 1, "dataset schema_version must be 1")
    _require(config.get("dataset_id") == "adaptive-attack-memory-dataset-v1", "unexpected dataset id")
    _require(config.get("short_name") == "AAMD-v1", "unexpected dataset short name")
    _require(config.get("status") == "preregistration_candidate_not_run",
             "candidate config cannot imply that collection or validation ran")
    try:
        date.fromisoformat(str(config.get("as_of")))
    except ValueError:
        _fail("as_of must be an ISO date")

    _validate_claim_boundary(config)
    _validate_source_and_questions(config)
    _validate_record_contract(config)
    _validate_collection(config)
    _validate_attack_side(config)
    _validate_annotation(config)
    _validate_splits(config)
    _validate_defense_actionability(config)
    _validate_release_and_storage(config)
    _validate_gates_and_readiness(config)
    _scan_public_config(config)


def validate_dataset_record(
    record: Mapping[str, Any],
    schema: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one normalized, payload-free AAMD-v1 record offline.

    Cross-record hash-chain, foreign-key, exactly-one-terminal-outcome, and
    manifest-count checks intentionally remain bundle-level G1/G2 work.  This
    function fail-closes the public envelope, the discriminated payload branch,
    conditional receipt requirements, and obvious secret/payload leakage.
    """

    _require(isinstance(record, dict), "dataset record must be an object")
    _require(isinstance(schema, dict), "dataset record schema must be an object")
    _validate_record_schema_contract(schema)
    _validate_schema_instance(record, schema, schema)
    _require(set(record) == set(RECORD_TOP_LEVEL_FIELDS),
             "dataset record envelope keys changed")
    _require(record.get("schema_version") == "adaptive-attack-memory-record-v1",
             "unexpected dataset record schema version")
    _require(record.get("dataset_id") == "adaptive-attack-memory-dataset-v1",
             "unexpected dataset record dataset id")
    _require(record.get("record_type") in RECORD_FAMILY_IDS,
             "unexpected dataset record type")
    _scan_public_config(record, "record")
    return {
        "valid": True,
        "dataset_id": record["dataset_id"],
        "record_type": record["record_type"],
        "record_id": record["record_id"],
        "release_tier": record["release_tier"],
    }


def validate_dataset_bundle(config_path: Path, schema_path: Path) -> dict[str, Any]:
    """Validate schema and semantics, returning a payload-free readiness summary."""

    config = load_json(config_path)
    schema = load_json(schema_path)
    _validate_schema_contract(schema)
    _validate_schema_instance(config, schema, schema)
    validate_dataset_config(config)

    return {
        "valid": True,
        "claim_ready": False,
        "dataset_id": config["dataset_id"],
        "short_name": config["short_name"],
        "status": config["status"],
        "defense_validation_status": config["defense_actionability"]["status"],
        "record_families": list(RECORD_FAMILY_IDS),
        "evidence_levels": list(EVIDENCE_LEVEL_IDS),
        "attack_side_arms": list(ATTACK_ARM_IDS),
        "minimum_independent_consumers": config["defense_actionability"]["minimum_independent_consumers"],
        "release_tiers": list(RELEASE_TIER_IDS),
        "gates": list(GATE_IDS),
        "next_gate": "G0",
        "blockers": list(BLOCKER_IDS),
        "sha256": {
            "dataset_config": _sha256(config_path),
            "dataset_config_schema": _sha256(schema_path),
        },
    }


__all__ = [
    "ATTACK_ARM_IDS",
    "BLOCKER_IDS",
    "DatasetValidationError",
    "EVIDENCE_LEVEL_IDS",
    "GATE_IDS",
    "RECORD_FAMILY_IDS",
    "RELEASE_TIER_IDS",
    "load_json",
    "validate_dataset_bundle",
    "validate_dataset_config",
    "validate_dataset_record",
]
