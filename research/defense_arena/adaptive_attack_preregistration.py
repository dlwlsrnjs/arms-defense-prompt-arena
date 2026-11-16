"""Fail-closed validation for the adaptive-attack preregistration bundle.

The validator deliberately has no model, GPU, network, or third-party runtime
dependency.  It checks the parts of the protocol that are easy to weaken by an
accidental edit: method coverage, feedback visibility, split isolation,
leave-one-method-out construction, complete terminal-outcome logging, freeze
consistency, and the payload-free public boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse


METHOD_KEYS = (
    "pair",
    "tap",
    "crescendo",
    "gptfuzzer",
    "autodan_turbo",
)
TARGET_KEYS = (
    "qwen2.5-vl-3b",
    "qwen2.5-vl-7b",
    "qwen2.5-vl-32b",
)
SOURCE_KEYS = ("harmbench", "advbench", "salad_bench")
SPLIT_FRACTIONS = {"build": 0.5, "selection": 0.25, "confirmation": 0.25}
GATE_IDS = tuple(f"G{index}" for index in range(7))

REQUIRED_OUTCOMES = {
    "strict_success",
    "attack_failure",
    "target_refusal_or_safe_completion",
    "budget_exhausted",
    "attacker_invalid_output",
    "attacker_timeout",
    "target_timeout",
    "judge_timeout",
    "infrastructure_error",
    "policy_filter_block",
    "cancelled_before_target_call",
}
REQUIRED_EVENT_TYPES = {
    "run_started",
    "episode_started",
    "memory_retrieved",
    "attack_candidate_proposed",
    "target_call_completed",
    "judge_call_completed",
    "adaptation_transition_observed",
    "memory_candidate_decided",
    "episode_ended",
    "run_ended",
}

# These are payload-bearing keys, not boundary declarations such as
# ``raw_behavior_text_in_this_file: false``.
FORBIDDEN_PUBLIC_KEYS = {
    "attack_prompt",
    "behavior_id",
    "behavior_text",
    "dataset_row_id",
    "instruction_text",
    "judge_reason",
    "prompt_text",
    "query_text",
    "raw_behavior_text",
    "raw_prompt",
    "raw_response",
    "source_row_id",
    "target_response",
}
FORBIDDEN_PUBLIC_PATH_FRAGMENTS = ("/home/", "/data1/", "/tmp/", "file://")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


class PreregistrationValidationError(ValueError):
    """Raised when a preregistration invariant is not satisfied."""


def _fail(message: str) -> None:
    raise PreregistrationValidationError(message)


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
    """Load an object-valued JSON document while rejecting duplicate keys."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except PreregistrationValidationError:
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


def _expect_keys(
    value: Mapping[str, Any],
    *,
    required: Iterable[str],
    context: str,
    exact: bool = False,
) -> None:
    required_set = set(required)
    missing = required_set - set(value)
    _require(not missing, f"{context} missing keys: {sorted(missing)}")
    if exact:
        extra = set(value) - required_set
        _require(not extra, f"{context} has unregistered keys: {sorted(extra)}")


def _as_list(value: Any, context: str) -> list[Any]:
    _require(isinstance(value, list), f"{context} must be an array")
    return value


def _as_mapping(value: Any, context: str) -> Mapping[str, Any]:
    _require(isinstance(value, dict), f"{context} must be an object")
    return value


def _require_unique(values: Sequence[Any], context: str) -> None:
    try:
        unique_count = len(set(values))
    except TypeError:
        _fail(f"{context} must contain scalar values")
    _require(unique_count == len(values), f"{context} contains duplicates")


def _walk_public_boundary(value: Any, context: str = "root") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _require(
                key not in FORBIDDEN_PUBLIC_KEYS,
                f"{context} contains forbidden payload-bearing key {key!r}",
            )
            _walk_public_boundary(item, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_public_boundary(item, f"{context}[{index}]")
    elif isinstance(value, str):
        _require(
            not any(fragment in value for fragment in FORBIDDEN_PUBLIC_PATH_FRAGMENTS),
            f"{context} exposes a local filesystem path",
        )


def _validate_schema_contract(schema: Mapping[str, Any]) -> None:
    _require(
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
        "behavior registry schema must use JSON Schema draft 2020-12",
    )
    _require(schema.get("type") == "object", "behavior registry schema root must be object")
    _require(schema.get("additionalProperties") is False, "schema root must fail on unknown keys")
    required = set(_as_list(schema.get("required"), "schema.required"))
    expected = {
        "schema_version",
        "registry_id",
        "status",
        "as_of",
        "release_boundary",
        "source_collections",
        "category_ontology",
        "eligibility_contract",
        "deduplication_contract",
        "split_contract",
        "sampling_contract",
        "contamination_controls",
        "freeze_requirements",
    }
    _require(required == expected, "schema.required does not match registry contract")
    definitions = _as_mapping(schema.get("$defs"), "schema.$defs")
    for name in (
        "release_boundary",
        "source_collection",
        "category",
        "eligibility_contract",
        "deduplication_contract",
        "split_contract",
        "sampling_contract",
        "contamination_controls",
        "freeze_requirements",
    ):
        definition = _as_mapping(definitions.get(name), f"schema.$defs.{name}")
        _require(
            definition.get("additionalProperties") is False,
            f"schema definition {name} must reject unknown keys",
        )


def _resolve_local_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    _require(reference.startswith("#/"), f"only local JSON Schema refs are allowed: {reference}")
    current: Any = root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        _require(isinstance(current, dict) and part in current,
                 f"unresolvable JSON Schema ref: {reference}")
        current = current[part]
    return _as_mapping(current, f"schema ref {reference}")


def _matches_json_type(value: Any, type_name: str) -> bool:
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


def _validate_schema_instance(
    value: Any,
    schema: Mapping[str, Any],
    root: Mapping[str, Any],
    path: str = "$",
) -> None:
    """Validate the small Draft 2020-12 subset used by the public registry."""

    if "$ref" in schema:
        _validate_schema_instance(value, _resolve_local_ref(root, str(schema["$ref"])), root, path)
        return
    if "type" in schema:
        declared = schema["type"]
        choices = declared if isinstance(declared, list) else [declared]
        _require(any(_matches_json_type(value, str(choice)) for choice in choices),
                 f"{path} does not match JSON Schema type {choices}")
    if "const" in schema:
        _require(value == schema["const"], f"{path} does not match JSON Schema const")
    if "enum" in schema:
        _require(value in schema["enum"], f"{path} is not in the JSON Schema enum")

    if isinstance(value, dict):
        required = set(schema.get("required", []))
        missing = required - set(value)
        _require(not missing, f"{path} missing schema-required keys: {sorted(missing)}")
        properties = _as_mapping(schema.get("properties", {}), f"{path} schema properties")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            _require(not extra, f"{path} has schema-forbidden keys: {sorted(extra)}")
        for key, item in value.items():
            if key in properties:
                _validate_schema_instance(item, _as_mapping(properties[key], f"schema {path}.{key}"), root,
                                          f"{path}.{key}")
    elif isinstance(value, list):
        if "minItems" in schema:
            _require(len(value) >= int(schema["minItems"]), f"{path} has too few items")
        if "maxItems" in schema:
            _require(len(value) <= int(schema["maxItems"]), f"{path} has too many items")
        if schema.get("uniqueItems") is True:
            normalized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            _require(len(normalized) == len(set(normalized)), f"{path} has duplicate items")
        if "items" in schema:
            item_schema = _as_mapping(schema["items"], f"schema {path}.items")
            for index, item in enumerate(value):
                _validate_schema_instance(item, item_schema, root, f"{path}[{index}]")
    elif isinstance(value, str):
        if "minLength" in schema:
            _require(len(value) >= int(schema["minLength"]), f"{path} is too short")
        if "pattern" in schema:
            _require(re.search(str(schema["pattern"]), value) is not None,
                     f"{path} does not match schema pattern")
        if schema.get("format") == "date":
            try:
                date.fromisoformat(value)
            except ValueError:
                _fail(f"{path} is not an ISO date")
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


def _validate_methods(universe: Mapping[str, Any]) -> None:
    methods = _as_list(universe.get("method_registry"), "method_registry")
    keys = [str(_as_mapping(item, "method_registry[]").get("key")) for item in methods]
    _require(tuple(keys) == METHOD_KEYS, f"method registry must be exactly {METHOD_KEYS}")
    _require_unique(keys, "method_registry keys")
    for method in methods:
        row = _as_mapping(method, "method_registry[]")
        key = str(row["key"])
        revision = row.get("upstream_revision_candidate")
        _require(isinstance(revision, str) and SHA1_RE.fullmatch(revision) is not None,
                 f"{key} must have an observed 40-hex candidate revision")
        _require(row.get("upstream_revision_status") == "observed_candidate_unfrozen",
                 f"{key} candidate revision must remain explicitly unfrozen before G0")
        _require(row.get("adapter_status") == "blocked_until_G1_parity",
                 f"{key} adapter must remain blocked until G1 parity")
        _require(row.get("enabled_for_claims") is False,
                 f"{key} cannot be enabled for claims in the candidate bundle")
        _require(str(row.get("repository_url", "")).startswith("https://github.com/"),
                 f"{key} repository must be an HTTPS GitHub URL")
        _require(str(row.get("canonical_repository_url", "")).startswith("https://github.com/"),
                 f"{key} canonical repository must be recorded after redirects")
        _require(row.get("license_spdx_observed") == "MIT",
                 f"{key} observed license must be recorded without treating it as frozen")
        license_url = str(row.get("license_evidence_url", ""))
        _require(revision in license_url and license_url.startswith("https://github.com/"),
                 f"{key} license evidence URL must address the observed candidate revision")
        prefix = str(row.get("license_blob_sha_prefix_observed", ""))
        _require(re.fullmatch(r"[0-9a-f]{8,39}", prefix) is not None,
                 f"{key} license observation needs an explicit Git blob SHA prefix")
        _require(row.get("license_evidence_status") == "api_observation_needs_G0_local_full_hash",
                 f"{key} license evidence must remain pending local G0 verification")


def _validate_targets(universe: Mapping[str, Any]) -> None:
    registry = _as_mapping(universe.get("target_registry"), "target_registry")
    models = _as_list(registry.get("models"), "target_registry.models")
    keys = tuple(str(_as_mapping(row, "target_registry.models[]").get("key")) for row in models)
    _require(keys == TARGET_KEYS, f"target registry must be exactly {TARGET_KEYS}")
    _require(tuple(registry.get("confirmation_targets", [])) == TARGET_KEYS,
             "all three Qwen2.5-VL targets must be in confirmation_targets")
    _require(registry.get("development_target") == "qwen2.5-vl-3b",
             "3B target must remain the development target")
    for row in models:
        model = _as_mapping(row, "target_registry.models[]")
        revision = model.get("revision_candidate")
        _require(isinstance(revision, str) and SHA1_RE.fullmatch(revision) is not None,
                 f"target {model.get('key')} needs a 40-hex candidate revision")
        _require(model.get("revision_status") == "candidate_needs_G0_attestation",
                 f"target {model.get('key')} must not be represented as frozen")
    _require(registry.get("weights_frozen_during_attack_and_defense_evaluation") is True,
             "target weights must remain frozen")


def _validate_feedback(universe: Mapping[str, Any]) -> None:
    arms = _as_mapping(universe.get("feedback_arms"), "feedback_arms")
    primary = _as_mapping(arms.get("primary"), "feedback_arms.primary")
    diagnostic = _as_mapping(arms.get("diagnostic"), "feedback_arms.diagnostic")
    _require(primary.get("id") == "response_only", "primary feedback must be response_only")
    _require(primary.get("attacker_visible_after_each_target_call") == ["target_response"],
             "primary attacker may observe only the target response")
    hidden = set(_as_list(primary.get("attacker_hidden"), "primary.attacker_hidden"))
    _require({"judge_score", "judge_reason", "defense_system_prompt"} <= hidden,
             "primary feedback must hide judge feedback and the defense system prompt")
    _require(primary.get("used_for_primary_claims") is True,
             "response-only arm must be the primary claim arm")
    _require(diagnostic.get("id") == "judge_feedback",
             "diagnostic feedback arm must be judge_feedback")
    _require(diagnostic.get("memory_isolated_from_primary") is True,
             "diagnostic memory must be isolated from primary")
    _require(diagnostic.get("judge_reason_visible") is False,
             "judge reasons must not be exposed even in the diagnostic")
    _require(diagnostic.get("used_for_primary_claims") is False,
             "judge-feedback diagnostic cannot support primary claims")


def _validate_splits_and_lomo(universe: Mapping[str, Any]) -> None:
    design = _as_mapping(universe.get("evaluation_design"), "evaluation_design")
    splits = _as_list(design.get("splits"), "evaluation_design.splits")
    observed = {
        str(_as_mapping(row, "evaluation_design.splits[]").get("name")): float(row["fraction"])
        for row in splits
    }
    _require(observed == SPLIT_FRACTIONS, f"attack-universe split fractions must be {SPLIT_FRACTIONS}")
    _require(math.isclose(sum(observed.values()), 1.0), "attack-universe split fractions must sum to one")
    confirmation = next(row for row in splits if row["name"] == "confirmation")
    _require(confirmation.get("allowed_uses") == ["sealed_final_evaluation_only"],
             "confirmation split must be sealed final evaluation only")

    folds = _as_list(design.get("leave_one_method_out_folds"), "leave_one_method_out_folds")
    held_out = [str(_as_mapping(row, "leave_one_method_out_folds[]").get("held_out")) for row in folds]
    _require(tuple(held_out) == METHOD_KEYS, "leave-one-method-out folds must cover each method once")
    for fold in folds:
        row = _as_mapping(fold, "leave_one_method_out_folds[]")
        held = str(row["held_out"])
        memory_methods = list(row.get("memory_methods", []))
        _require(len(memory_methods) == len(METHOD_KEYS) - 1,
                 f"LOMO fold {held} must contain four memory methods")
        _require(set(memory_methods) == set(METHOD_KEYS) - {held},
                 f"LOMO fold {held} must use every non-held-out method exactly once")


def _validate_ledger(universe: Mapping[str, Any]) -> None:
    ledger = _as_mapping(universe.get("event_ledger_contract"), "event_ledger_contract")
    _require(ledger.get("format") == "append_only_jsonl_hash_chain",
             "ledger must be append-only hash-chained JSONL")
    immutability = _as_mapping(ledger.get("immutability"), "event_ledger_contract.immutability")
    for field in (
        "monotonic_sequence_required",
        "previous_event_hash_required",
        "run_manifest_hash_in_first_event",
        "terminal_chain_hash_in_run_manifest",
    ):
        _require(immutability.get(field) is True, f"ledger immutability requires {field}=true")
    _require(immutability.get("in_place_rewrite_allowed") is False,
             "ledger cannot permit in-place rewrite")
    events = set(_as_list(ledger.get("required_event_types"), "required_event_types"))
    outcomes = set(_as_list(ledger.get("required_outcome_codes"), "required_outcome_codes"))
    _require(REQUIRED_EVENT_TYPES <= events,
             f"ledger is missing required event types: {sorted(REQUIRED_EVENT_TYPES - events)}")
    _require(REQUIRED_OUTCOMES <= outcomes,
             f"ledger is missing required outcome codes: {sorted(REQUIRED_OUTCOMES - outcomes)}")
    for field in (
        "all_registered_episodes_must_terminate_with_one_outcome",
        "all_memory_reads_writes_merges_rejections_and_fallbacks_logged",
        "infrastructure_errors_reported_separately",
        "timeout_or_missing_judge_never_relabelled_as_defense_success",
    ):
        _require(ledger.get(field) is True, f"ledger contract requires {field}=true")


def _validate_gates(universe: Mapping[str, Any]) -> None:
    gates = _as_list(universe.get("gates"), "gates")
    ids = tuple(str(_as_mapping(gate, "gates[]").get("id")) for gate in gates)
    _require(ids == GATE_IDS, f"gates must be ordered exactly {GATE_IDS}")
    for index, gate in enumerate(gates):
        row = _as_mapping(gate, "gates[]")
        expected_entry = [] if index == 0 else [f"G{index - 1}"]
        _require(row.get("entry_requires") == expected_entry,
                 f"{row.get('id')} must depend only on the previous gate")
        _require(row.get("status") == "blocked",
                 f"candidate bundle cannot mark {row.get('id')} passed")
        _require(bool(row.get("pass_requires")), f"{row.get('id')} needs pass criteria")
        _require(bool(row.get("failure_policy")), f"{row.get('id')} needs a failure policy")


def validate_attack_universe(universe: Mapping[str, Any]) -> None:
    _require(universe.get("schema_version") == 1, "attack universe schema_version must be 1")
    _require(universe.get("universe_id") == "adaptive-attack-universe-v1",
             "unexpected attack universe id")
    _require(universe.get("status") == "registration_candidate_not_frozen",
             "this bundle must remain an explicitly unfrozen registration candidate")
    boundary = _as_mapping(universe.get("claim_boundary"), "claim_boundary")
    _require(boundary.get("official_arms_code_used") is False,
             "official ARMS code cannot be claimed")
    _require(boundary.get("official_arms_reproduction_claimed") is False,
             "official ARMS reproduction cannot be claimed")
    _require(boundary.get("raw_harmful_prompt_or_response_text_allowed") is False,
             "public attack/response payloads must remain forbidden")
    _require(boundary.get("raw_behavior_identifiers_allowed") is False,
             "public behavior identifiers must remain forbidden")
    freeze = _as_mapping(universe.get("provenance_freeze"), "provenance_freeze")
    _require(freeze.get("candidate_pins_are_frozen") is False,
             "observed upstream HEADs cannot be treated as frozen before G0")
    _require(freeze.get("freeze_gate") == "G0", "provenance must freeze at G0")
    _validate_methods(universe)
    _validate_targets(universe)
    _validate_feedback(universe)
    _validate_splits_and_lomo(universe)
    _validate_ledger(universe)
    _validate_gates(universe)
    memory = _as_mapping(universe.get("attack_memory_contract"), "attack_memory_contract")
    _require(memory.get("record_rejected_and_unsuccessful_candidates") is True,
             "memory collection must retain rejected and unsuccessful candidates")
    _require(memory.get("record_no_memory_baseline_episodes") is True,
             "memory collection must include no-memory baselines")
    _require(memory.get("raw_payload_publication_allowed") is False,
             "raw memory payload publication cannot be enabled")
    resource = _as_mapping(universe.get("resource_contract"), "resource_contract")
    primary = _as_mapping(resource.get("primary_track"), "resource_contract.primary_track")
    seeds = _as_list(primary.get("attacker_seeds"), "primary_track.attacker_seeds")
    _require(len(seeds) == 5 and all(isinstance(seed, int) for seed in seeds),
             "primary track must freeze five integer attacker seeds")
    _require_unique(seeds, "attacker seeds")
    _require(primary.get("retry_rule") == "one_retry_only_for_attested_infrastructure_error_with_same_seed",
             "retry rule must prevent outcome-dependent retries")
    _walk_public_boundary(universe, "attack_universe")


def validate_behavior_registry(registry: Mapping[str, Any]) -> None:
    _require(registry.get("schema_version") == 1, "behavior registry schema_version must be 1")
    _require(registry.get("registry_id") == "behavior-registry-v1", "unexpected registry id")
    _require(registry.get("status") == "registration_candidate_not_frozen",
             "behavior registry must remain explicitly unfrozen before G2")
    boundary = _as_mapping(registry.get("release_boundary"), "release_boundary")
    _require(boundary.get("public_artifact_mode") == "payload_free",
             "behavior registry must remain payload-free")
    _require(boundary.get("raw_behavior_text_in_this_file") is False,
             "registry cannot claim raw behavior text is present")
    _require(boundary.get("source_row_identifiers_in_this_file") is False,
             "registry cannot expose source row identifiers")

    sources = _as_list(registry.get("source_collections"), "source_collections")
    source_keys = tuple(str(_as_mapping(row, "source_collections[]").get("source_key")) for row in sources)
    _require(source_keys == SOURCE_KEYS, f"behavior sources must be exactly {SOURCE_KEYS}")
    for source in sources:
        row = _as_mapping(source, "source_collections[]")
        revision = row.get("revision_candidate")
        _require(isinstance(revision, str) and SHA1_RE.fullmatch(revision) is not None,
                 f"{row.get('source_key')} must have an observed 40-hex candidate revision")
        _require(row.get("revision_status") == "observed_candidate_unfrozen",
                 f"{row.get('source_key')} candidate revision must remain unfrozen before G0")
        _require(row.get("license_spdx_observed") in {"MIT", "Apache-2.0"},
                 f"{row.get('source_key')} needs an observed SPDX license")
        blob_sha = row.get("license_blob_sha_observed")
        _require(isinstance(blob_sha, str) and SHA1_RE.fullmatch(blob_sha) is not None,
                 f"{row.get('source_key')} needs the observed license blob SHA")
        license_url = str(row.get("license_evidence_url", ""))
        _require(license_url.startswith("https://github.com/") and revision in license_url,
                 f"{row.get('source_key')} license evidence must address its candidate revision")
        _require(row.get("license_status") == "api_observation_needs_G0_local_full_hash",
                 f"{row.get('source_key')} license must remain pending local G0 verification")
        _require(row.get("eligible_after_G0") is False,
                 f"{row.get('source_key')} cannot be eligible before G0")

    categories = _as_list(registry.get("category_ontology"), "category_ontology")
    codes = [str(_as_mapping(row, "category_ontology[]").get("code")) for row in categories]
    labels = [str(_as_mapping(row, "category_ontology[]").get("label")) for row in categories]
    _require_unique(codes, "category codes")
    _require_unique(labels, "category labels")
    _require(len(categories) >= 2, "category ontology must contain multiple strata")

    eligibility = _as_mapping(registry.get("eligibility_contract"), "eligibility_contract")
    _require(eligibility.get("all_exclusions_logged_with_reason_code") is True,
             "all exclusions need reason codes")
    _require(eligibility.get("attack_or_defense_outcomes_visible_during_eligibility_review") is False,
             "eligibility review must be blinded to outcomes")

    dedup = _as_mapping(registry.get("deduplication_contract"), "deduplication_contract")
    threshold = dedup.get("semantic_cosine_threshold")
    _require(isinstance(threshold, (int, float)) and 0.0 < float(threshold) <= 1.0,
             "semantic deduplication threshold must be in (0, 1]")
    _require(dedup.get("cross_source_deduplication_required") is True,
             "cross-source deduplication is mandatory")
    _require(dedup.get("cluster_key_publication") == "salted_hash_only",
             "cluster handles must be published only as salted hashes")

    split_contract = _as_mapping(registry.get("split_contract"), "split_contract")
    split_rows = _as_list(split_contract.get("splits"), "split_contract.splits")
    observed = {
        str(_as_mapping(row, "split_contract.splits[]").get("name")): float(row["fraction"])
        for row in split_rows
    }
    _require(observed == SPLIT_FRACTIONS, f"registry split fractions must be {SPLIT_FRACTIONS}")
    _require(math.isclose(sum(observed.values()), 1.0), "registry split fractions must sum to one")
    _require([row.get("interval") for row in split_rows] == ["0000-4999", "5000-7499", "7500-9999"],
             "registry HMAC split intervals must be complete and non-overlapping")
    for field in (
        "cluster_cross_split_overlap_allowed",
        "source_row_cross_split_overlap_allowed",
        "confirmation_access_before_G6_allowed",
    ):
        _require(split_contract.get(field) is False, f"split contract requires {field}=false")

    sampling = _as_mapping(registry.get("sampling_contract"), "sampling_contract")
    _require(sampling.get("outcome_based_selection_allowed") is False,
             "outcome-based sampling is forbidden")
    _require(sampling.get("manual_example_selection_allowed") is False,
             "manual example selection is forbidden")
    _require(sampling.get("replacement_sampling_allowed") is False,
             "replacement sampling is forbidden")
    _require(sampling.get("cluster_cap_per_stratum") is None,
             "candidate registry cannot invent a cap before blinded power analysis")
    _require(sampling.get("cluster_cap_status") == "pending_blinded_G2_power_analysis",
             "unfrozen sampling cap must block G2")

    contamination = _as_mapping(registry.get("contamination_controls"), "contamination_controls")
    for field in (
        "pilot_clusters_excluded_from_all_main_splits",
        "selection_and_confirmation_payloads_hidden_from_memory_compiler",
        "confirmation_payloads_hidden_from_prompt_selection",
        "source_and_cluster_hashes_checked_against_prompt_examples",
        "cross_split_nearest_neighbor_audit_required",
    ):
        _require(contamination.get(field) is True,
                 f"contamination controls require {field}=true")
    _require(math.isclose(float(contamination.get("audit_threshold")), float(threshold)),
             "deduplication and contamination audit thresholds must match")

    freeze = _as_mapping(registry.get("freeze_requirements"), "freeze_requirements")
    _require(freeze.get("gate") == "G2", "behavior registry must freeze at G2")
    _require(freeze.get("current_gate_passed") is False,
             "candidate registry cannot mark G2 passed")
    _require(freeze.get("main_experiment_access_allowed") is False,
             "main experiment access must remain blocked before G2")
    _walk_public_boundary(registry, "behavior_registry")


def _cross_validate(universe: Mapping[str, Any], registry: Mapping[str, Any]) -> None:
    design = _as_mapping(universe.get("evaluation_design"), "evaluation_design")
    _require(design.get("behavior_registry") == registry.get("registry_id"),
             "attack universe references a different behavior registry")
    universe_splits = {
        row["name"]: float(row["fraction"])
        for row in _as_list(design.get("splits"), "evaluation_design.splits")
    }
    registry_splits = {
        row["name"]: float(row["fraction"])
        for row in _as_list(
            _as_mapping(registry.get("split_contract"), "split_contract").get("splits"),
            "split_contract.splits",
        )
    }
    _require(universe_splits == registry_splits,
             "attack universe and behavior registry split contracts disagree")


def validate_bundle(
    attack_universe_path: Path,
    behavior_registry_path: Path,
    behavior_schema_path: Path,
) -> dict[str, Any]:
    """Validate the three-file bundle and return a payload-free summary."""

    universe = load_json(attack_universe_path)
    registry = load_json(behavior_registry_path)
    schema = load_json(behavior_schema_path)
    _validate_schema_contract(schema)
    _validate_schema_instance(registry, schema, schema)
    validate_attack_universe(universe)
    validate_behavior_registry(registry)
    _cross_validate(universe, registry)

    return {
        "valid": True,
        "claim_ready": False,
        "registration_status": "candidate_not_frozen",
        "attack_universe_id": universe["universe_id"],
        "behavior_registry_id": registry["registry_id"],
        "official_arms_reproduction_claimed": False,
        "methods": list(METHOD_KEYS),
        "targets": list(TARGET_KEYS),
        "behavior_sources": list(SOURCE_KEYS),
        "primary_feedback": "response_only",
        "diagnostic_feedback": "judge_feedback_isolated_from_primary",
        "gates": list(GATE_IDS),
        "next_gate": "G0",
        "blocking_items": [
            "verify and freeze upstream attack-method revisions and licenses",
            "pin and audit behavior-source revisions and licenses",
            "attest target, attacker, and judge model revisions",
            "freeze adapter mappings, ledger schema, and run manifests",
            "pass adapter parity before any main data collection",
            "complete blinded behavior clustering, power analysis, and G2 split freeze",
        ],
        "sha256": {
            "attack_universe": _sha256(attack_universe_path),
            "behavior_registry": _sha256(behavior_registry_path),
            "behavior_schema": _sha256(behavior_schema_path),
        },
    }
