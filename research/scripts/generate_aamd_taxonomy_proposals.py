#!/usr/bin/env python3
"""Generate frozen RCAT-7 proposals with an already-running local 32B server.

This program deliberately does not launch, stop, or inspect a model server or GPU.
It calls one OpenAI-compatible loopback endpoint, validates every returned proposal
against the frozen RCAT-7 contract, and writes a new review bundle plus an audit
manifest. Capacity-growing outputs are restricted to the project runtime root.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = Path("/data1/users/ljk98/Amrs-runtime")
DEFAULT_TAXONOMY_PATH = (
    REPOSITORY_ROOT / "research/configs/aamd_rcat7_taxonomy_v1_1.json"
)
DEFAULT_PROMPT_PATH = (
    REPOSITORY_ROOT / "research/prompts/aamd_llm_first_labeler_32b_v3.txt"
)
DEFAULT_CONFIG_PATH = (
    REPOSITORY_ROOT / "research/configs/aamd_llm_first_labeler_32b_v3.json"
)

EXACT_MODEL_ID = "Qwen/Qwen2.5-VL-32B-Instruct"
EXACT_MODEL_REVISION = "7cfb30d71a1f4f49a57592323337a4a4727301da"
EXACT_CONFIG_ID = "aamd-llm-first-labeler-32b-v3"
EXACT_PROTOCOL_ID = "aamd-llm-first-taxonomy-review-v3"
EXACT_CODEBOOK_VERSION = "aamd-rcat-7-v1.1"
EXACT_TAXONOMY_VERSION = "1.1.0"
EXACT_TAXONOMY_HASH = "2f8512333c90888aa640e8432ec262cdd452adbae3d1e8df5c96c5654a5c816c"
EXACT_PROMPT_HASH = "27cf07fb7c46f8885282c62e99dd4ac9f9e80669b129bf8bf0178a18a0958abe"
EXACT_DECODING_HASH = "35f24dbf25c35716b130f7182d3bd369bc15427eb1c04720b57a9df6ab499517"
EXACT_HUMAN_REVIEWED_AXES = (
    "adaptation_mechanism",
    "consumed_response_signal",
    "search_action",
    "semantic_linkage",
)
EXACT_RUNTIME_LOCKED_AXES = (
    "memory_source_scope",
    "memory_operation",
    "evidence_provenance",
    "dialogue_horizon",
)
EXACT_REQUIRED_AXES = EXACT_HUMAN_REVIEWED_AXES + EXACT_RUNTIME_LOCKED_AXES
EXACT_PUBLIC_RECORD_FIELDS = (
    "benchmark",
    "record_handle",
    "title",
    "question",
    "instructions",
    "evidence",
    "taxonomy_id",
    "taxonomy_version",
    "taxonomy_hash",
    "locked_axes",
    "locked_axes_hash",
)
EXACT_V3_VISIBILITY_MASK = {
    "schema_version": 3,
    "strategy": "abstract-evidence-plus-frozen-taxonomy-proposal",
    "forbidden": [
        "raw_payload",
        "raw_prompt",
        "attack_text",
        "harmful_request",
        "target_response",
        "attack_method",
        "outcome",
        "ground_truth",
        "system_prompt",
    ],
    "visible": [*EXACT_PUBLIC_RECORD_FIELDS, "llm_proposal"],
}
GENERATOR_VERSION = "aamd-taxonomy-proposal-generator-v1.1"
PROPOSAL_VERSION = "offline-32b-rcat7-v1.1"
PARSER_VERSION = "strict-json-duplicate-key-reject-v1"
RETRY_POLICY_VERSION = "same-request-429-5xx-or-transport-v1"
REPAIR_POLICY_VERSION = "no-semantic-repair-fail-closed-v1"
MAX_RETRIES = 2
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_MODEL_CONTENT_BYTES = 128 * 1024
SENTINELS = frozenset({"none", "uncertain", "unmapped"})
MAPPING_STATUSES = frozenset({"mapped", "none", "uncertain", "unmapped"})
BENIGN_PLAUSIBILITY = frozenset(
    {
        "RCAT7.CONFOUND_PLAUSIBILITY.UNLIKELY",
        "RCAT7.CONFOUND_PLAUSIBILITY.POSSIBLE",
        "RCAT7.CONFOUND_PLAUSIBILITY.LIKELY",
        "uncertain",
    }
)
T4_FIELDS = (
    "defense_invariant",
    "benign_exception",
    "predicted_readaptation",
    "evaluation_probe",
)
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]*$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
ISO_UTC_MILLIS_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)
FORBIDDEN_KEYS = frozenset(
    {
        "raw_payload",
        "raw_payloads",
        "raw_prompt",
        "raw_attack_prompt",
        "attack_prompt",
        "attack_text",
        "harmful_prompt",
        "harmful_request",
        "harmful_request_text",
        "target_response",
        "raw_target_response",
        "attack_method",
        "attack_method_name",
        "attack_technique",
        "attack_template",
        "outcome",
        "future_outcome",
        "actual_outcome",
        "ground_truth",
        "gold_label",
        "strict_success",
        "judge_score",
        "judge_reason",
        "judge_rationale",
        "real_split",
        "hidden_split",
        "split_name",
        "system_prompt",
        "secret",
        "api_token",
    }
)
RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})
RUNTIME_ATTESTATION_TYPE = "aamd-managed-vllm-runtime-v1"
RUNTIME_ATTESTATION_BINDING_VERSION = 1


class ContractError(ValueError):
    """An input, output, or frozen-artifact contract was violated."""


class CompletionCallError(ContractError):
    """A terminal local-endpoint failure with its bounded attempt receipts."""

    def __init__(self, message: str, attempts: Sequence[Mapping[str, Any]]) -> None:
        super().__init__(message)
        self.attempts = tuple(copy.deepcopy(list(attempts)))


class GenerationError(ContractError):
    """A generation failure that carries an auditable, payload-free manifest."""

    def __init__(self, message: str, failure_manifest: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.failure_manifest = copy.deepcopy(dict(failure_manifest))


@dataclass(frozen=True)
class CompletionResult:
    """One validated OpenAI-compatible response and its audit trail."""

    content: str
    raw_response: bytes
    response_object: Mapping[str, Any]
    attempts: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class TaxonomyContract:
    taxonomy_id: str
    taxonomy_version: str
    taxonomy_hash: str
    required_axes: tuple[str, ...]
    human_reviewed_axes: tuple[str, ...]
    runtime_locked_axes: tuple[str, ...]
    codes_by_axis: Mapping[str, frozenset[str]]
    benign_confound_codes: frozenset[str]
    benign_confound_codes_by_mechanism: Mapping[str, frozenset[str]]


def canonical_json_bytes(value: Any) -> bytes:
    """Return the repository's JCS-compatible canonical bytes.

    The frozen taxonomy contains no non-integer JSON numbers, so Python's sorted,
    compact JSON representation is byte-identical to the registered RFC 8785 JCS
    artifact. NaN and infinities are always rejected.
    """

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError("value is not canonicalizable JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ContractError(f"{name} must be a lowercase SHA-256")
    return value


def validate_runtime_attestation_record(value: Any) -> dict[str, Any]:
    """Validate the manager-produced runtime record without overstating weights.

    The manager verifies pinned small files, the shard set, Hugging Face revision
    metadata/object IDs, and local sizes.  It does *not* hash all shard contents,
    so the record must keep ``snapshot_content_hashed`` false while accurately
    stating that this narrower provenance was checked before launch.
    """

    if not isinstance(value, dict):
        raise ContractError("runtime attestation must be an object")
    if value.get("schema_version") != 1 or value.get("attestation_type") != (
        RUNTIME_ATTESTATION_TYPE
    ):
        raise ContractError("runtime attestation schema/type is invalid")
    run_id = value.get("run_id")
    if not isinstance(run_id, str) or not ID_PATTERN.fullmatch(run_id):
        raise ContractError("runtime attestation run_id is invalid")
    service = value.get("service_identity")
    provenance = value.get("runtime_provenance")
    lifecycle = value.get("lifecycle")
    weights = value.get("weights")
    if not all(
        isinstance(item, dict)
        for item in (service, provenance, lifecycle, weights)
    ):
        raise ContractError("runtime attestation sections must be objects")
    if service.get("run_id") != run_id or service.get("model_id") != EXACT_MODEL_ID:
        raise ContractError("runtime service identity does not match run/model")
    if service.get("runtime_provenance") != provenance:
        raise ContractError("runtime provenance differs from the service identity")
    if provenance.get("model_id") != EXACT_MODEL_ID or provenance.get(
        "model_revision"
    ) != EXACT_MODEL_REVISION:
        raise ContractError("runtime model provenance is not the frozen 32B model")
    for field in (
        "pid",
        "process_start_ticks",
        "process_group_id",
        "session_id",
        "gpu_index",
        "port",
        "hard_deadline_seconds",
    ):
        if not isinstance(service.get(field), int):
            raise ContractError(f"runtime service identity {field} is invalid")
    if service["pid"] != service["process_group_id"] or service["pid"] != service[
        "session_id"
    ]:
        raise ContractError("runtime service is not a captured session leader")
    if service.get("cuda_visible_devices") != str(service["gpu_index"]):
        raise ContractError("runtime CUDA visibility does not match the GPU index")
    _sha256(value.get("manager_script_file_sha256"), name="manager script hash")
    identity_canonical = _sha256(
        value.get("service_identity_canonical_sha256"),
        name="service identity canonical hash",
    )
    _sha256(
        value.get("service_identity_file_sha256"),
        name="service identity file hash",
    )
    provenance_canonical = _sha256(
        value.get("runtime_provenance_canonical_sha256"),
        name="runtime provenance canonical hash",
    )
    if identity_canonical != canonical_sha256(service):
        raise ContractError("runtime service identity canonical hash mismatch")
    if provenance_canonical != canonical_sha256(provenance):
        raise ContractError("runtime provenance canonical hash mismatch")
    expected_lifecycle = {
        "model_server_lifecycle_managed": True,
        "gpu_lifecycle_managed": True,
        "identity_captured_before_service_release": True,
        "watchdog_identity_captured_before_service_release": True,
        "hard_deadline_watchdog_armed": True,
        "cleanup_verification_state": "pending_at_generation",
    }
    if lifecycle != expected_lifecycle:
        raise ContractError("runtime lifecycle attestation is invalid")
    if weights.get("provenance_attested") is not True:
        raise ContractError("runtime weight provenance was not attested")
    if weights.get("snapshot_content_hashed") is not False:
        raise ContractError("runtime attestation must not claim full shard hashing")
    if weights.get("attestation_method") != provenance.get(
        "model_tree_attestation"
    ):
        raise ContractError("runtime weight attestation method mismatch")
    if weights.get("model_revision") != EXACT_MODEL_REVISION:
        raise ContractError("runtime weight revision mismatch")
    return copy.deepcopy(value)


def build_runtime_attestation_binding(
    value: Any,
    raw: bytes,
    *,
    expected_file_sha256: str,
    expected_canonical_sha256: str,
) -> dict[str, Any]:
    record = validate_runtime_attestation_record(value)
    observed_file = sha256_bytes(raw)
    observed_canonical = canonical_sha256(record)
    if observed_file != _sha256(
        expected_file_sha256, name="runtime attestation file hash"
    ):
        raise ContractError("runtime attestation file hash mismatch")
    if observed_canonical != _sha256(
        expected_canonical_sha256, name="runtime attestation canonical hash"
    ):
        raise ContractError("runtime attestation canonical hash mismatch")
    return {
        "schema_version": RUNTIME_ATTESTATION_BINDING_VERSION,
        "file_sha256": observed_file,
        "canonical_sha256": observed_canonical,
        "attestation": record,
    }


def validate_runtime_attestation_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != (
        RUNTIME_ATTESTATION_BINDING_VERSION
    ):
        raise ContractError("runtime attestation binding is invalid")
    record = validate_runtime_attestation_record(value.get("attestation"))
    canonical = _sha256(
        value.get("canonical_sha256"), name="runtime attestation canonical hash"
    )
    file_hash = _sha256(
        value.get("file_sha256"), name="runtime attestation file hash"
    )
    if canonical != canonical_sha256(record):
        raise ContractError("runtime attestation binding canonical hash mismatch")
    return {
        "schema_version": RUNTIME_ATTESTATION_BINDING_VERSION,
        "file_sha256": file_hash,
        "canonical_sha256": canonical,
        "attestation": record,
    }


def public_record_projection(task: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact V3 public-record projection committed by ``record_hash``."""

    return {field: task[field] for field in EXACT_PUBLIC_RECORD_FIELDS}


def ordered_queue_projection(tasks: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return the exact ordered task-identity projection committed by ``queue_hash``."""

    return [
        {
            "ordinal": ordinal,
            "task_id": task["task_id"],
            "record_handle": task["record_handle"],
            "record_hash": task["record_hash"],
        }
        for ordinal, task in enumerate(tasks)
    ]


def _reject_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def strict_json_loads(payload: str | bytes, *, name: str) -> Any:
    """Parse strict JSON while rejecting duplicate keys and non-finite numbers."""

    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ContractError(f"{name} must be UTF-8") from exc
    else:
        text = payload

    def reject_constant(value: str) -> None:
        raise ContractError(f"{name} contains forbidden non-finite number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except ContractError:
        raise
    except json.JSONDecodeError as exc:
        raise ContractError(f"{name} must be one strict JSON value") from exc


def load_json(path: Path, *, name: str) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return strict_json_loads(raw, name=name), raw


def _exact_keys(
    value: Any,
    required: Sequence[str],
    optional: Sequence[str] = (),
    *,
    name: str,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    allowed = set(required) | set(optional)
    unknown = sorted(set(value) - allowed)
    missing = sorted(set(required) - set(value))
    if unknown:
        raise ContractError(f"{name} contains unknown fields: {', '.join(unknown)}")
    if missing:
        raise ContractError(f"{name} is missing fields: {', '.join(missing)}")
    return value


def _string(value: Any, *, name: str, minimum: int = 1, maximum: int = 4000) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{name} must be a string")
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum or "\x00" in normalized:
        raise ContractError(f"{name} must contain {minimum}-{maximum} safe characters")
    return normalized


def _identifier(value: Any, *, name: str, maximum: int = 160) -> str:
    result = _string(value, name=name, maximum=maximum)
    if not ID_PATTERN.fullmatch(result):
        raise ContractError(f"{name} has an invalid identifier format")
    return result


def _sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ContractError(f"{name} must be lowercase SHA-256 hex")
    return value


def _integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ContractError(f"{name} must be in [{minimum}, {maximum}]")
    return value


def _normalized_key(key: str) -> str:
    # Normalize common attempts to disguise a forbidden field name: camelCase,
    # punctuation, whitespace, and repeated separators all collapse identically.
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key.strip())
    return re.sub(
        r"_+", "_", re.sub(r"[^A-Za-z0-9]+", "_", camel_split)
    ).strip("_").lower()


FORBIDDEN_COMPACT_KEYS = frozenset(key.replace("_", "") for key in FORBIDDEN_KEYS)


def reject_forbidden_fields(value: Any, *, path: str = "bundle") -> None:
    """Reject raw payload/outcome/method fields recursively by key name.

    This is a structural field gate, not a semantic harmful-text classifier. The
    accepted task schema is deliberately an upstream-produced abstract projection;
    raw dialogue must never be placed into its allowed free-text values.
    """

    if isinstance(value, list):
        for index, child in enumerate(value):
            reject_forbidden_fields(child, path=f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        normalized = _normalized_key(str(key))
        compact = normalized.replace("_", "")
        if (
            normalized in FORBIDDEN_KEYS
            or compact in FORBIDDEN_COMPACT_KEYS
            or normalized.startswith("raw_")
        ):
            raise ContractError(f"forbidden payload field at {path}.{key}")
        reject_forbidden_fields(child, path=f"{path}.{key}")


def _codes(entries: Any, *, name: str) -> frozenset[str]:
    if not isinstance(entries, list) or not entries:
        raise ContractError(f"{name} must be a non-empty array")
    codes: list[str] = []
    for index, entry in enumerate(entries):
        candidate = entry.get("code") if isinstance(entry, dict) else entry
        codes.append(_identifier(candidate, name=f"{name}[{index}].code"))
    if len(codes) != len(set(codes)):
        raise ContractError(f"{name} contains duplicate codes")
    return frozenset(codes)


def build_taxonomy_contract(
    taxonomy: Any, config: Mapping[str, Any], prompt_bytes: bytes
) -> TaxonomyContract:
    if not isinstance(taxonomy, dict):
        raise ContractError("taxonomy must be an object")
    if config.get("config_id") != EXACT_CONFIG_ID:
        raise ContractError(f"config_id must be {EXACT_CONFIG_ID}")
    if config.get("protocol_id") != EXACT_PROTOCOL_ID:
        raise ContractError(f"protocol_id must be {EXACT_PROTOCOL_ID}")
    model = config.get("model")
    if not isinstance(model, dict):
        raise ContractError("config.model must be an object")
    if model.get("model_id") != EXACT_MODEL_ID or model.get("parameters") != "32B":
        raise ContractError("the first-pass proposer must be the frozen exact 32B model")
    if model.get("revision_candidate") != EXACT_MODEL_REVISION:
        raise ContractError("model revision must match the frozen 32B revision")
    if model.get("revision_status") != "candidate_needs_G0_attestation":
        raise ContractError("this generator accepts only the registered pilot revision status")

    decoding = config.get("decoding")
    if not isinstance(decoding, dict):
        raise ContractError("config.decoding must be an object")
    expected_decoding = {
        "temperature": 0,
        "top_p": 1,
        "max_output_tokens": 6144,
        "seed": 20261116,
        "stop": [],
    }
    if decoding != expected_decoding:
        raise ContractError("decoding must match the frozen deterministic contract")
    if config.get("decoding_config_sha256") != EXACT_DECODING_HASH:
        raise ContractError("decoding hash must match the frozen V3 contract")
    if canonical_sha256(decoding) != config.get("decoding_config_sha256"):
        raise ContractError("decoding_config_sha256 does not match config.decoding")

    prompt = config.get("prompt")
    if not isinstance(prompt, dict):
        raise ContractError("config.prompt must be an object")
    if prompt.get("sha256") != EXACT_PROMPT_HASH:
        raise ContractError("prompt hash must match the frozen V3 contract")
    if sha256_bytes(prompt_bytes) != prompt.get("sha256"):
        raise ContractError("prompt bytes do not match the frozen prompt hash")
    if prompt_bytes.count(b"{{TASK_JSON}}") != 1 or prompt_bytes.count(
        b"{{TAXONOMY_JSON}}"
    ) != 1:
        raise ContractError("prompt must contain each registered placeholder exactly once")
    if any(
        prompt.get(field) is not False
        for field in (
            "raw_attack_payload_allowed",
            "hidden_outcome_allowed",
            "attack_method_name_allowed",
        )
    ):
        raise ContractError("prompt visibility flags must remain fail-closed")

    taxonomy_config = config.get("taxonomy")
    if not isinstance(taxonomy_config, dict):
        raise ContractError("config.taxonomy must be an object")
    taxonomy_hash = canonical_sha256(taxonomy)
    if taxonomy_hash != EXACT_TAXONOMY_HASH:
        raise ContractError("taxonomy hash must match the frozen V3 contract")
    if taxonomy_hash != taxonomy_config.get("sha256"):
        raise ContractError("taxonomy bytes do not match the frozen canonical hash")
    taxonomy_id = _identifier(taxonomy.get("taxonomy_id"), name="taxonomy.taxonomy_id")
    taxonomy_version = _identifier(
        taxonomy.get("taxonomy_version"), name="taxonomy.taxonomy_version"
    )
    if taxonomy_id != EXACT_CODEBOOK_VERSION or taxonomy_version != EXACT_TAXONOMY_VERSION:
        raise ContractError("taxonomy identity must match the frozen V3 contract")
    if taxonomy_id != taxonomy_config.get("taxonomy_id") or taxonomy_version != taxonomy_config.get("taxonomy_version"):
        raise ContractError("taxonomy identity does not match the labeler config")

    axes_value = taxonomy_config.get("required_axes")
    if not isinstance(axes_value, list) or len(axes_value) < 5:
        raise ContractError("at least five frozen taxonomy axes are required")
    required_axes = tuple(
        _identifier(axis, name="config.taxonomy.required_axes[]") for axis in axes_value
    )
    if required_axes != EXACT_REQUIRED_AXES:
        raise ContractError("required axes must match the frozen V3 order")
    if len(required_axes) != len(set(required_axes)):
        raise ContractError("required taxonomy axes must be unique")
    human_reviewed_axes = tuple(taxonomy_config.get("human_reviewed_axes", ()))
    runtime_locked_axes = tuple(taxonomy_config.get("runtime_locked_axes", ()))
    if human_reviewed_axes != EXACT_HUMAN_REVIEWED_AXES:
        raise ContractError("human-reviewed axes must match the frozen V1.1 order")
    if runtime_locked_axes != EXACT_RUNTIME_LOCKED_AXES:
        raise ContractError("runtime-locked axes must match the frozen V1.1 order")
    if human_reviewed_axes + runtime_locked_axes != required_axes:
        raise ContractError("axis ownership must partition the frozen required axes")

    mechanisms = taxonomy.get("mechanisms")
    mechanism_codes = _codes(mechanisms, name="taxonomy.mechanisms")
    mechanism_sentinels = _codes(
        taxonomy.get("mechanism_sentinels"), name="taxonomy.mechanism_sentinels"
    )
    codes_by_axis: dict[str, frozenset[str]] = {
        "adaptation_mechanism": mechanism_codes | mechanism_sentinels
    }
    orthogonal = taxonomy.get("orthogonal_axes")
    if not isinstance(orthogonal, dict):
        raise ContractError("taxonomy.orthogonal_axes must be an object")
    for axis in required_axes:
        if axis == "adaptation_mechanism":
            continue
        spec = orthogonal.get(axis)
        if not isinstance(spec, dict):
            raise ContractError(f"taxonomy lacks required axis: {axis}")
        codes_by_axis[axis] = _codes(
            spec.get("codes"), name=f"taxonomy.orthogonal_axes.{axis}.codes"
        )
    if set(codes_by_axis) != set(required_axes):
        raise ContractError("taxonomy/config required-axis coverage differs")

    benign_codes: list[str] = []
    benign_codes_by_mechanism: dict[str, frozenset[str]] = {}
    for mechanism_index, mechanism in enumerate(mechanisms):
        mechanism_code = _identifier(
            mechanism.get("code"),
            name=f"taxonomy.mechanisms[{mechanism_index}].code",
        )
        confounds = mechanism.get("benign_confounds")
        if not isinstance(confounds, list):
            raise ContractError(
                f"taxonomy.mechanisms[{mechanism_index}].benign_confounds must be an array"
            )
        mechanism_confound_codes: list[str] = []
        for confound_index, confound in enumerate(confounds):
            if not isinstance(confound, dict):
                raise ContractError("benign confound entries must be objects")
            confound_code = _identifier(
                confound.get("code"),
                name=(
                    f"taxonomy.mechanisms[{mechanism_index}]"
                    f".benign_confounds[{confound_index}].code"
                ),
            )
            benign_codes.append(confound_code)
            mechanism_confound_codes.append(confound_code)
        benign_codes_by_mechanism[mechanism_code] = frozenset(
            mechanism_confound_codes
        )
    benign_codes.extend(sorted(SENTINELS))
    if len(benign_codes) != len(set(benign_codes)):
        raise ContractError("taxonomy benign confound codes must be unique")

    return TaxonomyContract(
        taxonomy_id=taxonomy_id,
        taxonomy_version=taxonomy_version,
        taxonomy_hash=taxonomy_hash,
        required_axes=required_axes,
        human_reviewed_axes=human_reviewed_axes,
        runtime_locked_axes=runtime_locked_axes,
        codes_by_axis=codes_by_axis,
        benign_confound_codes=frozenset(benign_codes),
        benign_confound_codes_by_mechanism=benign_codes_by_mechanism,
    )


def _validate_evidence(value: Any, *, name: str) -> dict[str, str]:
    item = _exact_keys(value, ("handle", "label", "value"), name=name)
    return {
        "handle": _identifier(item["handle"], name=f"{name}.handle"),
        "label": _string(item["label"], name=f"{name}.label", maximum=160),
        "value": _string(item["value"], name=f"{name}.value", maximum=1200),
    }


def validate_locked_axes(
    value: Any,
    locked_axes_hash: Any,
    contract: TaxonomyContract,
    *,
    allowed_handles: set[str],
    name: str,
) -> tuple[dict[str, Any], str]:
    locked = _exact_keys(value, contract.runtime_locked_axes, name=name)
    normalized: dict[str, Any] = {}
    for axis in contract.runtime_locked_axes:
        item_name = f"{name}.{axis}"
        item = _exact_keys(
            locked[axis],
            ("code", "evidence_handles", "derivation_rule", "artifact_hash"),
            name=item_name,
        )
        code = _identifier(item["code"], name=f"{item_name}.code")
        if code not in contract.codes_by_axis[axis]:
            raise ContractError(f"{item_name}.code is outside the frozen codebook")
        handles_raw = item["evidence_handles"]
        if not isinstance(handles_raw, list):
            raise ContractError(f"{item_name}.evidence_handles must be an array")
        handles = [
            _identifier(handle, name=f"{item_name}.evidence_handles[]")
            for handle in handles_raw
        ]
        if len(handles) != len(set(handles)) or any(
            handle not in allowed_handles for handle in handles
        ):
            raise ContractError(f"{item_name} has duplicate or unknown evidence handles")
        if code not in SENTINELS and not handles:
            raise ContractError(f"{item_name} requires runtime-derived evidence handles")
        normalized[axis] = {
            "code": code,
            "evidence_handles": handles,
            "derivation_rule": _identifier(
                item["derivation_rule"], name=f"{item_name}.derivation_rule"
            ),
            "artifact_hash": _sha256(
                item["artifact_hash"], name=f"{item_name}.artifact_hash"
            ),
        }

    source_code = normalized["memory_source_scope"]["code"]
    operation_code = normalized["memory_operation"]["code"]
    source_sentinel = source_code in SENTINELS
    operation_sentinel = operation_code in SENTINELS
    if source_sentinel != operation_sentinel or (
        source_sentinel and source_code != operation_code
    ):
        raise ContractError(
            "memory source and operation must both be non-sentinel or share one sentinel"
        )

    expected_hash = canonical_sha256(normalized)
    supplied_hash = _sha256(locked_axes_hash, name=f"{name}_hash")
    if supplied_hash != expected_hash:
        raise ContractError("locked_axes_hash does not match canonical locked axes")
    return normalized, supplied_hash


def validate_source_bundle(
    bundle: Any, contract: TaxonomyContract, *, output_bundle_id: str
) -> dict[str, Any]:
    """Validate a proposal-free V3 source bundle without mutating it."""

    reject_forbidden_fields(bundle)
    source = _exact_keys(
        bundle,
        (
            "schema_version",
            "bundle_id",
            "mode",
            "claim_bearing",
            "protocol_version",
            "codebook_version",
            "visibility_mask_hash",
            "queue_hash",
            "tasks",
        ),
        name="bundle",
    )
    if source["schema_version"] != 2:
        raise ContractError("V3 taxonomy source bundle requires schema_version 2")
    if source["mode"] != "pilot_import" or source["claim_bearing"] is not False:
        raise ContractError("the unattested 32B revision may generate pilot bundles only")
    if source["protocol_version"] != EXACT_PROTOCOL_ID:
        raise ContractError(f"protocol_version must be {EXACT_PROTOCOL_ID}")
    if source["codebook_version"] != EXACT_CODEBOOK_VERSION:
        raise ContractError(f"codebook_version must be {EXACT_CODEBOOK_VERSION}")
    source_bundle_id = _identifier(source["bundle_id"], name="bundle.bundle_id")
    new_bundle_id = _identifier(output_bundle_id, name="output_bundle_id")
    if source_bundle_id == new_bundle_id:
        raise ContractError("output_bundle_id must differ from the source bundle ID")
    visibility_mask_hash = _sha256(
        source["visibility_mask_hash"], name="bundle.visibility_mask_hash"
    )
    expected_visibility_mask_hash = canonical_sha256(EXACT_V3_VISIBILITY_MASK)
    if visibility_mask_hash != expected_visibility_mask_hash:
        raise ContractError(
            "visibility_mask_hash does not match the frozen V3 visibility mask"
        )
    supplied_queue_hash = _sha256(source["queue_hash"], name="bundle.queue_hash")

    tasks = source["tasks"]
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 500:
        raise ContractError("bundle.tasks must contain 1-500 proposal-free tasks")
    normalized_tasks: list[dict[str, Any]] = []
    task_ids: set[str] = set()
    record_handles: set[str] = set()
    task_keys = (
        "task_id",
        "benchmark",
        "record_handle",
        "record_hash",
        "split",
        "claim_bearing",
        "title",
        "question",
        "instructions",
        "evidence",
        "taxonomy_id",
        "taxonomy_version",
        "taxonomy_hash",
        "locked_axes",
        "locked_axes_hash",
    )
    for index, raw_task in enumerate(tasks):
        name = f"bundle.tasks[{index}]"
        task = _exact_keys(raw_task, task_keys, name=name)
        task_id = _identifier(task["task_id"], name=f"{name}.task_id")
        record_handle = _identifier(
            task["record_handle"], name=f"{name}.record_handle"
        )
        if task_id in task_ids or record_handle in record_handles:
            raise ContractError("task IDs and record handles must be unique")
        task_ids.add(task_id)
        record_handles.add(record_handle)
        if task["benchmark"] not in {"T1", "T2", "T3", "T4"}:
            raise ContractError(f"{name}.benchmark is invalid")
        if task["split"] != "blinded" or task["claim_bearing"] is not False:
            raise ContractError(f"{name} violates blinded pilot boundaries")
        supplied_record_hash = _sha256(
            task["record_hash"], name=f"{name}.record_hash"
        )
        if (
            task["taxonomy_id"] != contract.taxonomy_id
            or task["taxonomy_version"] != contract.taxonomy_version
            or task["taxonomy_hash"] != contract.taxonomy_hash
        ):
            raise ContractError(f"{name} does not bind the frozen taxonomy")
        evidence_raw = task["evidence"]
        if not isinstance(evidence_raw, list) or not 1 <= len(evidence_raw) <= 32:
            raise ContractError(f"{name}.evidence must contain 1-32 items")
        evidence = [
            _validate_evidence(item, name=f"{name}.evidence[{evidence_index}]")
            for evidence_index, item in enumerate(evidence_raw)
        ]
        handles = [entry["handle"] for entry in evidence]
        if len(handles) != len(set(handles)):
            raise ContractError(f"{name}.evidence handles must be unique")
        locked_axes, locked_axes_hash = validate_locked_axes(
            task["locked_axes"],
            task["locked_axes_hash"],
            contract,
            allowed_handles=set(handles),
            name=f"{name}.locked_axes",
        )
        normalized_task = {
            "task_id": task_id,
            "benchmark": task["benchmark"],
            "record_handle": record_handle,
            "record_hash": supplied_record_hash,
            "split": "blinded",
            "claim_bearing": False,
            "title": _string(task["title"], name=f"{name}.title", maximum=240),
            "question": _string(
                task["question"], name=f"{name}.question", maximum=1200
            ),
            "instructions": _string(
                task["instructions"], name=f"{name}.instructions", maximum=1600
            ),
            "evidence": evidence,
            "taxonomy_id": contract.taxonomy_id,
            "taxonomy_version": contract.taxonomy_version,
            "taxonomy_hash": contract.taxonomy_hash,
            "locked_axes": locked_axes,
            "locked_axes_hash": locked_axes_hash,
        }
        expected_record_hash = canonical_sha256(
            public_record_projection(normalized_task)
        )
        if supplied_record_hash != expected_record_hash:
            raise ContractError(
                f"{name}.record_hash does not match the canonical public record"
            )
        normalized_tasks.append(normalized_task)

    expected_queue_hash = canonical_sha256(ordered_queue_projection(normalized_tasks))
    if supplied_queue_hash != expected_queue_hash:
        raise ContractError(
            "bundle.queue_hash does not match the canonical ordered task identity"
        )

    return {
        "schema_version": 2,
        "bundle_id": source_bundle_id,
        "mode": "pilot_import",
        "claim_bearing": False,
        "protocol_version": EXACT_PROTOCOL_ID,
        "codebook_version": EXACT_CODEBOOK_VERSION,
        "visibility_mask_hash": visibility_mask_hash,
        "queue_hash": supplied_queue_hash,
        "tasks": normalized_tasks,
    }


def render_prompt(prompt_text: str, taxonomy: Any, task: Mapping[str, Any]) -> str:
    if prompt_text.count("{{TASK_JSON}}") != 1 or prompt_text.count(
        "{{TAXONOMY_JSON}}"
    ) != 1:
        raise ContractError("prompt placeholders drifted")
    rendered = prompt_text.replace(
        "{{TAXONOMY_JSON}}", canonical_json_bytes(taxonomy).decode("utf-8")
    ).replace("{{TASK_JSON}}", canonical_json_bytes(task).decode("utf-8"))
    if "{{TASK_JSON}}" in rendered or "{{TAXONOMY_JSON}}" in rendered:
        raise ContractError("prompt rendering left an unresolved placeholder")
    return rendered


def build_chat_request(
    rendered_prompt: str, config: Mapping[str, Any]
) -> dict[str, Any]:
    decoding = config["decoding"]
    return {
        "model": EXACT_MODEL_ID,
        "messages": [{"role": "user", "content": rendered_prompt}],
        "temperature": decoding["temperature"],
        "top_p": decoding["top_p"],
        "max_tokens": decoding["max_output_tokens"],
        "seed": decoding["seed"],
        "stop": decoding["stop"],
        "stream": False,
        "n": 1,
    }


def validate_local_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"}:
        raise ContractError("endpoint must use http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ContractError("endpoint must not contain credentials, query, or fragment")
    host = (parsed.hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "::1"}:
        raise ContractError("only a loopback OpenAI-compatible endpoint is allowed")
    path = parsed.path.rstrip("/")
    if not path:
        path = "/v1"
    if not path.endswith("/chat/completions"):
        path += "/chat/completions"
    netloc = parsed.netloc
    return urllib.parse.urlunsplit((parsed.scheme, netloc, path, "", ""))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an HTTP error instead of forwarding a POST."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _urllib_transport(
    url: str, request_bytes: bytes, headers: Mapping[str, str], timeout_seconds: float
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=request_bytes,
        headers=dict(headers),
        method="POST",
    )
    # An explicit empty ProxyHandler ignores *_PROXY environment variables, and the
    # custom redirect handler prevents a loopback server from forwarding the request
    # (including Authorization) to a non-loopback origin.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirectHandler()
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            return int(response.status), response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(MAX_HTTP_RESPONSE_BYTES + 1)


Transport = Callable[[str, bytes, Mapping[str, str], float], tuple[int, bytes]]


def validate_local_api_key(api_key: str | None) -> str | None:
    """Accept only a bounded visible-ASCII token before constructing headers."""

    if api_key is None:
        return None
    if not 1 <= len(api_key) <= 512 or any(
        ord(character) < 33 or ord(character) > 126 for character in api_key
    ):
        raise ContractError("local API key is malformed")
    return api_key


def parse_openai_completion(raw_response: bytes) -> tuple[str, Mapping[str, Any]]:
    if len(raw_response) > MAX_HTTP_RESPONSE_BYTES:
        raise ContractError("OpenAI response exceeds the registered byte limit")
    response = strict_json_loads(raw_response, name="OpenAI response")
    if not isinstance(response, dict):
        raise ContractError("OpenAI response must be an object")
    if response.get("model") != EXACT_MODEL_ID:
        raise ContractError("served response model does not equal the frozen model ID")
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ContractError("OpenAI response must contain exactly one choice")
    choice = choices[0]
    if not isinstance(choice, dict) or choice.get("index") != 0:
        raise ContractError("OpenAI response choice index must be zero")
    if choice.get("finish_reason") != "stop":
        raise ContractError("OpenAI response must finish normally with stop")
    message = choice.get("message")
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ContractError("OpenAI response must contain one assistant message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ContractError("assistant content must be a non-empty JSON string")
    if len(content.encode("utf-8")) > MAX_MODEL_CONTENT_BYTES:
        raise ContractError("assistant content exceeds the registered byte limit")
    return content, response


def call_chat_completion(
    request_object: Mapping[str, Any],
    *,
    endpoint: str,
    timeout_seconds: float,
    api_key: str | None = None,
    transport: Transport = _urllib_transport,
    sleep: Callable[[float], None] = time.sleep,
) -> CompletionResult:
    """Call the same deterministic request, retrying transport/HTTP failures only."""

    url = validate_local_endpoint(endpoint)
    api_key = validate_local_api_key(api_key)
    request_bytes = canonical_json_bytes(request_object)
    request_hash = sha256_bytes(request_bytes)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": GENERATOR_VERSION,
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    attempts: list[Mapping[str, Any]] = []
    for attempt_index in range(MAX_RETRIES + 1):
        started = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        try:
            status, raw = transport(url, request_bytes, headers, timeout_seconds)
            if len(raw) > MAX_HTTP_RESPONSE_BYTES:
                raise ContractError("OpenAI response exceeds the registered byte limit")
            entry: dict[str, Any] = {
                "attempt": attempt_index + 1,
                "kind": "generation" if attempt_index == 0 else "identical_request_retry",
                "started_at": started,
                "request_sha256": request_hash,
                "http_status": status,
                "response_wire_sha256": sha256_bytes(raw),
                "response_bytes": len(raw),
            }
            if status == 200:
                try:
                    content, response_object = parse_openai_completion(raw)
                except ContractError as exc:
                    entry["outcome"] = "terminal_response_contract_error"
                    entry["error_type"] = type(exc).__name__
                    attempts.append(entry)
                    raise CompletionCallError(
                        "local OpenAI response violated the frozen contract", attempts
                    ) from exc
                entry["outcome"] = "response_validated"
                attempts.append(entry)
                return CompletionResult(
                    content=content,
                    raw_response=raw,
                    response_object=response_object,
                    attempts=tuple(attempts),
                )
            entry["outcome"] = "retryable_http_error" if status in RETRYABLE_HTTP_STATUSES else "terminal_http_error"
            attempts.append(entry)
            if status not in RETRYABLE_HTTP_STATUSES or attempt_index == MAX_RETRIES:
                raise CompletionCallError(
                    f"local OpenAI endpoint returned HTTP {status}", attempts
                )
        except CompletionCallError:
            raise
        except ContractError as exc:
            raise CompletionCallError(
                "local OpenAI completion failed its frozen contract", attempts
            ) from exc
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            attempts.append(
                {
                    "attempt": attempt_index + 1,
                    "kind": "generation" if attempt_index == 0 else "identical_request_retry",
                    "started_at": started,
                    "request_sha256": request_hash,
                    "outcome": "transport_error",
                    "error_type": type(exc).__name__,
                }
            )
            if attempt_index == MAX_RETRIES:
                raise CompletionCallError(
                    "local OpenAI endpoint transport failed", attempts
                ) from exc
        sleep(0.25 * (2**attempt_index))
    raise AssertionError("retry loop must return or raise")


def validate_proposal_body(
    value: Any,
    task: Mapping[str, Any],
    contract: TaxonomyContract,
) -> dict[str, Any]:
    """Strictly validate and normalize one model-produced proposal body."""

    reject_forbidden_fields(value, path="proposal_body")
    required = [
        "mapping_status",
        "reviewed_axes",
        "locked_axes_hash",
        "benign_confound",
        "rationale",
    ]
    if task["benchmark"] == "T4":
        required.append("affordance")
    body = _exact_keys(
        value,
        required,
        name="proposal_body",
    )
    if task["benchmark"] != "T4" and "affordance" in body:
        raise ContractError("only T4 may contain affordance")
    mapping_status = _identifier(
        body["mapping_status"], name="proposal_body.mapping_status"
    )
    if mapping_status not in MAPPING_STATUSES:
        raise ContractError("proposal_body.mapping_status is outside the frozen codebook")
    labels_raw = body["reviewed_axes"]
    if not isinstance(labels_raw, list) or len(labels_raw) != len(
        contract.human_reviewed_axes
    ):
        raise ContractError("reviewed_axes must contain every human axis exactly once")
    if [entry.get("axis") if isinstance(entry, dict) else None for entry in labels_raw] != list(
        contract.human_reviewed_axes
    ):
        raise ContractError("reviewed_axes must use the frozen human-axis order")
    allowed_handles = {entry["handle"] for entry in task["evidence"]}
    labels: list[dict[str, Any]] = []
    for index, raw_label in enumerate(labels_raw):
        name = f"proposal_body.reviewed_axes[{index}]"
        label = _exact_keys(
            raw_label,
            ("axis", "code", "confidence", "evidence_handles", "rationale"),
            name=name,
        )
        axis = _identifier(label["axis"], name=f"{name}.axis")
        code = _identifier(label["code"], name=f"{name}.code")
        if code not in contract.codes_by_axis[axis]:
            raise ContractError(f"{name}.code is outside the frozen axis codebook")
        handles_raw = label["evidence_handles"]
        if not isinstance(handles_raw, list):
            raise ContractError(f"{name}.evidence_handles must be an array")
        handles = [
            _identifier(handle, name=f"{name}.evidence_handles[]")
            for handle in handles_raw
        ]
        if len(handles) != len(set(handles)) or any(
            handle not in allowed_handles for handle in handles
        ):
            raise ContractError(f"{name} contains duplicate or unknown evidence handles")
        if code not in SENTINELS and not handles:
            raise ContractError(f"{name} requires direct evidence for a non-sentinel code")
        labels.append(
            {
                "axis": axis,
                "code": code,
                "confidence": _integer(
                    label["confidence"], name=f"{name}.confidence", minimum=0, maximum=100
                ),
                "evidence_handles": handles,
                "rationale": _string(
                    label["rationale"], name=f"{name}.rationale", maximum=1600
                ),
            }
        )
    labels_by_axis = {label["axis"]: label for label in labels}
    mechanism_code = labels_by_axis["adaptation_mechanism"]["code"]
    linkage_code = labels_by_axis["semantic_linkage"]["code"]
    positive_linkage = linkage_code in {
        "RCAT7.LINKAGE.EXPLICIT_CONTENT_DEPENDENCE",
        "RCAT7.LINKAGE.IMPLICIT_OPERATION_DEPENDENCE",
    }
    expected_sentinel = mapping_status if mapping_status != "mapped" else None
    if expected_sentinel and mechanism_code != expected_sentinel:
        raise ContractError("mapping_status conflicts with adaptation_mechanism sentinel")
    if expected_sentinel is None and mechanism_code in SENTINELS:
        raise ContractError("mapped status requires a non-sentinel adaptation_mechanism")
    if mapping_status == "mapped" and not positive_linkage:
        raise ContractError("mapped status requires positive semantic_linkage")
    if mapping_status == "none" and linkage_code != "none":
        raise ContractError("none status requires semantic_linkage=none")
    if mapping_status == "unmapped" and not positive_linkage:
        raise ContractError("unmapped status requires positive semantic_linkage")

    locked_axes_hash = _sha256(
        body["locked_axes_hash"], name="proposal_body.locked_axes_hash"
    )
    if locked_axes_hash != task["locked_axes_hash"]:
        raise ContractError("proposal locked_axes_hash must equal the frozen task value")

    confound = _exact_keys(
        body["benign_confound"],
        ("code", "plausibility", "evidence_handles", "rationale"),
        name="proposal_body.benign_confound",
    )
    confound_code = _identifier(
        confound["code"], name="proposal_body.benign_confound.code"
    )
    if confound_code not in contract.benign_confound_codes:
        raise ContractError("benign confound code is outside the frozen codebook")
    allowed_mapped_confounds = contract.benign_confound_codes_by_mechanism.get(
        mechanism_code, frozenset()
    ) | {"uncertain", "unmapped"}
    if mapping_status == "mapped" and confound_code not in allowed_mapped_confounds:
        raise ContractError("mapped benign confound must match the selected mechanism")
    if mapping_status != "mapped" and confound_code != mapping_status:
        raise ContractError("non-mapped benign confound must equal mapping_status")
    plausibility = _identifier(
        confound["plausibility"], name="proposal_body.benign_confound.plausibility"
    )
    if plausibility not in BENIGN_PLAUSIBILITY:
        raise ContractError("benign confound plausibility is invalid")
    confound_handles_raw = confound["evidence_handles"]
    if not isinstance(confound_handles_raw, list):
        raise ContractError("benign_confound.evidence_handles must be an array")
    confound_handles = [
        _identifier(
            handle,
            name="proposal_body.benign_confound.evidence_handles[]",
        )
        for handle in confound_handles_raw
    ]
    if len(confound_handles) != len(set(confound_handles)) or any(
        handle not in allowed_handles for handle in confound_handles
    ):
        raise ContractError("benign confound has duplicate or unknown evidence handles")
    if confound_code not in SENTINELS and not confound_handles:
        raise ContractError("non-sentinel benign confound requires direct evidence")
    if confound_code in {"uncertain", "unmapped"} and plausibility != "uncertain":
        raise ContractError("uncertain/unmapped confound requires uncertain plausibility")
    normalized: dict[str, Any] = {
        "mapping_status": mapping_status,
        "reviewed_axes": labels,
        "locked_axes_hash": locked_axes_hash,
        "benign_confound": {
            "code": confound_code,
            "plausibility": plausibility,
            "evidence_handles": confound_handles,
            "rationale": _string(
                confound["rationale"],
                name="proposal_body.benign_confound.rationale",
                maximum=1600,
            ),
        },
        "rationale": _string(
            body["rationale"], name="proposal_body.rationale", maximum=2400
        ),
    }
    if task["benchmark"] == "T4":
        affordance = _exact_keys(
            body["affordance"], T4_FIELDS, name="proposal_body.affordance"
        )
        normalized["affordance"] = {
            field: _string(
                affordance[field],
                name=f"proposal_body.affordance.{field}",
                maximum=1600,
            )
            for field in T4_FIELDS
        }
    return normalized


CompletionCaller = Callable[[Mapping[str, Any], str], CompletionResult]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _base_generation_manifest(
    *,
    status: str,
    config: Mapping[str, Any],
    contract: TaxonomyContract,
    code_revision: str,
    source_bundle_hash: str,
    prompt_bytes: bytes,
    timestamp: str,
    task_manifests: Sequence[Mapping[str, Any]],
    runtime_attestation_binding: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build the common payload-free manifest for success or terminal failure."""

    managed_runtime = (
        validate_runtime_attestation_binding(runtime_attestation_binding)
        if runtime_attestation_binding is not None
        else None
    )
    manifest = {
        "schema_version": 1,
        "artifact_type": "aamd-offline-taxonomy-proposal-generation-manifest",
        "status": status,
        "claim_ready": False,
        "generator": {
            "version": GENERATOR_VERSION,
            "code_revision": code_revision,
            "script_file_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "python": platform.python_version(),
            "model_server_lifecycle_managed": managed_runtime is not None,
            "gpu_lifecycle_managed": managed_runtime is not None,
        },
        "contract": {
            "protocol_id": EXACT_PROTOCOL_ID,
            "labeler_config_id": EXACT_CONFIG_ID,
            "model_id": EXACT_MODEL_ID,
            "model_revision": config["model"]["revision_candidate"],
            "model_identity_assurance": "request_and_response_name_only",
            "weights_snapshot_attested": False,
            "weights_snapshot_content_hashed": False,
            "weights_provenance_attested": managed_runtime is not None,
            "taxonomy_id": contract.taxonomy_id,
            "taxonomy_version": contract.taxonomy_version,
            "taxonomy_hash": contract.taxonomy_hash,
            "parser_version": PARSER_VERSION,
            "retry_policy_version": RETRY_POLICY_VERSION,
            "retry_budget": MAX_RETRIES,
            "repair_policy_version": REPAIR_POLICY_VERSION,
            "repair_budget": 0,
            "temperature": config["decoding"]["temperature"],
            "seed": config["decoding"]["seed"],
            "determinism_assurance": "request_parameters_only",
        },
        "inputs": {
            "source_bundle_projection_canonical_sha256": source_bundle_hash,
            # Retain the first implementation's field for compatible consumers.
            "source_bundle_canonical_sha256": source_bundle_hash,
            "source_projection_normalization_version": "proposal-free-v3-v1",
            "taxonomy_canonical_sha256": contract.taxonomy_hash,
            "prompt_file_sha256": sha256_bytes(prompt_bytes),
            "labeler_config_canonical_sha256": canonical_sha256(config),
        },
        "tasks": [copy.deepcopy(dict(item)) for item in task_manifests],
        "generated_at": timestamp,
    }
    if managed_runtime is not None:
        manifest["contract"]["model_identity_assurance"] = (
            "manager_runtime_provenance_plus_request_response_name"
        )
        manifest["runtime_attestation"] = managed_runtime
    return manifest


def _failed_task_manifest(
    *,
    task: Mapping[str, Any],
    rendered: str,
    request_object: Mapping[str, Any],
    stage: str,
    attempts: Sequence[Mapping[str, Any]],
    result: CompletionResult | None = None,
) -> dict[str, Any]:
    """Create a failure receipt without retaining prompt or response contents."""

    receipt: dict[str, Any] = {
        "task_id": task["task_id"],
        "status": "failed",
        "terminal_stage": stage,
        "task_canonical_sha256": canonical_sha256(task),
        "rendered_prompt_sha256": sha256_bytes(rendered.encode("utf-8")),
        "request_canonical_sha256": canonical_sha256(request_object),
        "attempts": [copy.deepcopy(dict(attempt)) for attempt in attempts],
        "retry_count": max(0, len(attempts) - 1),
        "repair_count": 0,
    }
    if result is not None:
        content_bytes = result.content.encode("utf-8")
        receipt.update(
            {
                "response_wire_sha256": sha256_bytes(result.raw_response),
                "response_content_sha256": sha256_bytes(content_bytes),
                "response_content_bytes": len(content_bytes),
            }
        )
    return receipt


def generate_bundle(
    source_bundle: Any,
    taxonomy: Any,
    prompt_text: str,
    config: Mapping[str, Any],
    *,
    output_bundle_id: str,
    generator_code_revision: str,
    completion_caller: CompletionCaller,
    generated_at: str | None = None,
    runtime_attestation_binding: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate and validate every proposal without performing file I/O."""

    prompt_bytes = prompt_text.encode("utf-8")
    contract = build_taxonomy_contract(taxonomy, config, prompt_bytes)
    normalized_output_bundle_id = _identifier(
        output_bundle_id, name="output_bundle_id"
    )
    normalized_source = validate_source_bundle(
        source_bundle, contract, output_bundle_id=normalized_output_bundle_id
    )
    code_revision = _identifier(
        generator_code_revision, name="generator_code_revision"
    )
    timestamp = generated_at or _utc_now()
    managed_runtime = (
        validate_runtime_attestation_binding(runtime_attestation_binding)
        if runtime_attestation_binding is not None
        else None
    )
    if not ISO_UTC_MILLIS_PATTERN.fullmatch(timestamp):
        raise ContractError("generated_at must use canonical UTC milliseconds")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("generated_at must be ISO-8601 UTC") from exc
    if parsed_timestamp.tzinfo != timezone.utc:
        raise ContractError("generated_at must be canonical UTC ending in Z")
    if parsed_timestamp > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ContractError("generated_at cannot be in the future")

    source_bundle_hash = canonical_sha256(normalized_source)
    output = copy.deepcopy(normalized_source)
    output["bundle_id"] = normalized_output_bundle_id
    task_manifests: list[dict[str, Any]] = []
    for task in output["tasks"]:
        rendered = render_prompt(prompt_text, taxonomy, task)
        request_object = build_chat_request(rendered, config)
        try:
            result = completion_caller(request_object, task["task_id"])
        except CompletionCallError as exc:
            failed_task = _failed_task_manifest(
                task=task,
                rendered=rendered,
                request_object=request_object,
                stage="local_endpoint",
                attempts=exc.attempts,
            )
            failure_manifest = _base_generation_manifest(
                status="failed",
                config=config,
                contract=contract,
                code_revision=code_revision,
                source_bundle_hash=source_bundle_hash,
                prompt_bytes=prompt_bytes,
                timestamp=timestamp,
                task_manifests=[*task_manifests, failed_task],
                runtime_attestation_binding=managed_runtime,
            )
            failure_manifest["terminal_failure"] = {
                "task_id": task["task_id"],
                "stage": "local_endpoint",
                "error_type": type(exc).__name__,
                "output_bundle_written": False,
            }
            raise GenerationError(
                "proposal generation failed at the local endpoint", failure_manifest
            ) from exc
        except ContractError as exc:
            failed_task = _failed_task_manifest(
                task=task,
                rendered=rendered,
                request_object=request_object,
                stage="completion_caller_contract",
                attempts=(),
            )
            failure_manifest = _base_generation_manifest(
                status="failed",
                config=config,
                contract=contract,
                code_revision=code_revision,
                source_bundle_hash=source_bundle_hash,
                prompt_bytes=prompt_bytes,
                timestamp=timestamp,
                task_manifests=[*task_manifests, failed_task],
                runtime_attestation_binding=managed_runtime,
            )
            failure_manifest["terminal_failure"] = {
                "task_id": task["task_id"],
                "stage": "completion_caller_contract",
                "error_type": type(exc).__name__,
                "output_bundle_written": False,
            }
            raise GenerationError(
                "proposal completion caller violated its contract", failure_manifest
            ) from exc
        try:
            body_object = strict_json_loads(
                result.content, name="assistant proposal content"
            )
            if not isinstance(body_object, dict):
                raise ContractError("assistant proposal content must be one JSON object")
            proposal_body = validate_proposal_body(body_object, task, contract)
        except ContractError as exc:
            failed_task = _failed_task_manifest(
                task=task,
                rendered=rendered,
                request_object=request_object,
                stage="proposal_parse_or_validation",
                attempts=result.attempts,
                result=result,
            )
            failure_manifest = _base_generation_manifest(
                status="failed",
                config=config,
                contract=contract,
                code_revision=code_revision,
                source_bundle_hash=source_bundle_hash,
                prompt_bytes=prompt_bytes,
                timestamp=timestamp,
                task_manifests=[*task_manifests, failed_task],
                runtime_attestation_binding=managed_runtime,
            )
            failure_manifest["terminal_failure"] = {
                "task_id": task["task_id"],
                "stage": "proposal_parse_or_validation",
                "error_type": type(exc).__name__,
                "output_bundle_written": False,
            }
            raise GenerationError(
                "assistant proposal failed strict parse or validation",
                failure_manifest,
            ) from exc
        body_hash = canonical_sha256(proposal_body)
        proposal_id_hash = canonical_sha256(
            {
                "source_bundle_hash": source_bundle_hash,
                "task_id": task["task_id"],
                "proposal_body_hash": body_hash,
                "config_id": EXACT_CONFIG_ID,
                "taxonomy_hash": contract.taxonomy_hash,
            }
        )
        provenance = {
            "labeler_config_id": EXACT_CONFIG_ID,
            "model_id": EXACT_MODEL_ID,
            "parameters": "32B",
            "model_revision": config["model"]["revision_candidate"],
            "model_revision_status": config["model"]["revision_status"],
            "prompt_template_hash": config["prompt"]["sha256"],
            "decoding_config_hash": config["decoding_config_sha256"],
            "taxonomy_id": contract.taxonomy_id,
            "taxonomy_version": contract.taxonomy_version,
            "taxonomy_hash": contract.taxonomy_hash,
            "seed": config["decoding"]["seed"],
            "generator_code_revision": code_revision,
            "generated_at": timestamp,
            "source_bundle_hash": source_bundle_hash,
        }
        proposal = {
            "proposal_id": f"proposal-{proposal_id_hash[:24]}",
            "version": PROPOSAL_VERSION,
            **proposal_body,
            "provenance": provenance,
        }
        task["llm_proposal"] = proposal
        content_bytes = result.content.encode("utf-8")
        task_manifests.append(
            {
                "task_id": task["task_id"],
                "task_canonical_sha256": canonical_sha256(
                    {key: value for key, value in task.items() if key != "llm_proposal"}
                ),
                "rendered_prompt_sha256": sha256_bytes(rendered.encode("utf-8")),
                "request_canonical_sha256": canonical_sha256(request_object),
                "response_wire_sha256": sha256_bytes(result.raw_response),
                "response_content_sha256": sha256_bytes(content_bytes),
                "response_content_bytes": len(content_bytes),
                "proposal_body_canonical_sha256": body_hash,
                "proposal_canonical_sha256": canonical_sha256(proposal),
                "proposal_id": proposal["proposal_id"],
                "attempts": [dict(attempt) for attempt in result.attempts],
                "retry_count": max(0, len(result.attempts) - 1),
                "repair_count": 0,
            }
        )

    manifest = _base_generation_manifest(
        status="complete",
        config=config,
        contract=contract,
        code_revision=code_revision,
        source_bundle_hash=source_bundle_hash,
        prompt_bytes=prompt_bytes,
        timestamp=timestamp,
        task_manifests=task_manifests,
        runtime_attestation_binding=managed_runtime,
    )
    manifest.update(
        {
        "output": {
            "bundle_id": normalized_output_bundle_id,
            "bundle_canonical_sha256": canonical_sha256(output),
            "task_count": len(output["tasks"]),
        },
        }
    )
    return output, manifest


def resolve_runtime_output_path(path: str | Path, *, name: str) -> Path:
    candidate = Path(path).expanduser().resolve(strict=False)
    runtime = RUNTIME_ROOT.resolve(strict=False)
    try:
        candidate.relative_to(runtime)
    except ValueError as exc:
        raise ContractError(f"{name} must resolve below {runtime}") from exc
    if candidate == runtime:
        raise ContractError(f"{name} must be a file below {runtime}")
    return candidate


def _atomic_write_new(path: Path, payload: bytes) -> None:
    if path.exists():
        raise ContractError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ContractError(f"refusing to overwrite existing output: {path}") from exc
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def write_run_outputs(
    output_bundle: Mapping[str, Any],
    manifest: dict[str, Any],
    *,
    output_path: str | Path,
    manifest_path: str | Path,
) -> tuple[Path, Path]:
    bundle_target = resolve_runtime_output_path(output_path, name="output_path")
    manifest_target = resolve_runtime_output_path(manifest_path, name="manifest_path")
    if bundle_target == manifest_target:
        raise ContractError("output_path and manifest_path must differ")
    if bundle_target.exists() or manifest_target.exists():
        raise ContractError("output and manifest paths must both be unused")
    bundle_bytes = (
        json.dumps(output_bundle, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")
    final_manifest = copy.deepcopy(manifest)
    final_manifest["artifacts"] = {
        "output_bundle": {
            "path": str(bundle_target),
            "file_sha256": sha256_bytes(bundle_bytes),
            "canonical_sha256": canonical_sha256(output_bundle),
        },
        "generation_manifest": {"path": str(manifest_target)},
    }
    manifest_bytes = (
        json.dumps(final_manifest, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")
    _atomic_write_new(bundle_target, bundle_bytes)
    try:
        _atomic_write_new(manifest_target, manifest_bytes)
    except Exception:
        # The bundle is valid and immutable, but an unpaired bundle must not be used.
        # We do not delete it automatically; the explicit missing manifest is safer
        # than a destructive cleanup with an uncertain target.
        raise
    return bundle_target, manifest_target


def write_failure_manifest(
    manifest: Mapping[str, Any], *, manifest_path: str | Path
) -> Path:
    """Persist a terminal failure receipt without creating a partial output bundle."""

    target = resolve_runtime_output_path(manifest_path, name="manifest_path")
    if target.exists():
        raise ContractError(f"refusing to overwrite existing output: {target}")
    final_manifest = copy.deepcopy(dict(manifest))
    final_manifest["artifacts"] = {
        "output_bundle": {"written": False},
        "generation_manifest": {"path": str(target)},
    }
    manifest_bytes = (
        json.dumps(final_manifest, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")
    _atomic_write_new(target, manifest_bytes)
    return target


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-bundle",
        type=Path,
        required=True,
        help="Proposal-free, payload-free V3 source bundle JSON",
    )
    parser.add_argument("--taxonomy", type=Path, default=DEFAULT_TAXONOMY_PATH)
    parser.add_argument("--prompt", type=Path, default=DEFAULT_PROMPT_PATH)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--endpoint", required=True, help="Loopback OpenAI base URL")
    parser.add_argument("--output-bundle-id", required=True)
    parser.add_argument("--generator-code-revision", required=True)
    parser.add_argument("--runtime-attestation")
    parser.add_argument("--runtime-attestation-file-sha256")
    parser.add_argument("--runtime-attestation-canonical-sha256")
    parser.add_argument("--output", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    if not 1 <= args.timeout_seconds <= 3600:
        raise ContractError("timeout-seconds must be in [1, 3600]")
    # Validate both destinations before reading data or making a model call.
    output_path = resolve_runtime_output_path(args.output, name="output_path")
    manifest_path = resolve_runtime_output_path(args.manifest, name="manifest_path")
    if output_path == manifest_path or output_path.exists() or manifest_path.exists():
        raise ContractError("output and manifest must be distinct unused runtime paths")

    runtime_arguments = (
        args.runtime_attestation,
        args.runtime_attestation_file_sha256,
        args.runtime_attestation_canonical_sha256,
    )
    if any(value is not None for value in runtime_arguments) and not all(
        value is not None for value in runtime_arguments
    ):
        raise ContractError("all runtime attestation arguments are required together")
    runtime_binding: dict[str, Any] | None = None
    if args.runtime_attestation is not None:
        runtime_attestation_path = resolve_runtime_output_path(
            args.runtime_attestation, name="runtime_attestation"
        )
        runtime_value, runtime_raw = load_json(
            runtime_attestation_path, name="runtime attestation"
        )
        runtime_binding = build_runtime_attestation_binding(
            runtime_value,
            runtime_raw,
            expected_file_sha256=args.runtime_attestation_file_sha256,
            expected_canonical_sha256=args.runtime_attestation_canonical_sha256,
        )

    endpoint = validate_local_endpoint(args.endpoint)
    if runtime_binding is not None:
        endpoint_port = urllib.parse.urlsplit(endpoint).port
        service_port = runtime_binding["attestation"]["service_identity"]["port"]
        if endpoint_port != service_port:
            raise ContractError("runtime attestation port does not match the endpoint")

    source_bundle, source_raw = load_json(args.input_bundle, name="input bundle")
    taxonomy, taxonomy_raw = load_json(args.taxonomy, name="taxonomy")
    config, config_raw = load_json(args.config, name="labeler config")
    if not isinstance(config, dict):
        raise ContractError("labeler config must be an object")
    prompt_raw = args.prompt.read_bytes()
    try:
        prompt_text = prompt_raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError("prompt must be UTF-8") from exc

    api_key = validate_local_api_key(os.environ.get("AAMD_LOCAL_OPENAI_API_KEY"))

    def completion_caller(
        request_object: Mapping[str, Any], task_id: str
    ) -> CompletionResult:
        del task_id
        return call_chat_completion(
            request_object,
            endpoint=args.endpoint,
            timeout_seconds=args.timeout_seconds,
            api_key=api_key,
        )

    input_file_hashes = {
        "source_bundle_file_sha256": sha256_bytes(source_raw),
        "taxonomy_file_sha256": sha256_bytes(taxonomy_raw),
        "prompt_file_sha256": sha256_bytes(prompt_raw),
        "labeler_config_file_sha256": sha256_bytes(config_raw),
    }
    transport_manifest = {
        "endpoint": endpoint,
        "timeout_seconds": args.timeout_seconds,
        "redirects_followed": False,
        "environment_proxies_used": False,
        "authorization_present": bool(api_key),
        "authorization_value_recorded": False,
    }
    try:
        output_bundle, manifest = generate_bundle(
            source_bundle,
            taxonomy,
            prompt_text,
            config,
            output_bundle_id=args.output_bundle_id,
            generator_code_revision=args.generator_code_revision,
            completion_caller=completion_caller,
            runtime_attestation_binding=runtime_binding,
        )
    except GenerationError as exc:
        failure_manifest = copy.deepcopy(exc.failure_manifest)
        failure_manifest["inputs"].update(input_file_hashes)
        failure_manifest["transport"] = transport_manifest
        write_failure_manifest(failure_manifest, manifest_path=manifest_path)
        raise
    manifest["inputs"].update(input_file_hashes)
    manifest["transport"] = transport_manifest
    written_bundle, written_manifest = write_run_outputs(
        output_bundle,
        manifest,
        output_path=output_path,
        manifest_path=manifest_path,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "bundle": str(written_bundle),
                "manifest": str(written_manifest),
                "task_count": len(output_bundle["tasks"]),
                "bundle_canonical_sha256": canonical_sha256(output_bundle),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
