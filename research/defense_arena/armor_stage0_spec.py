"""Build one-pair Stage-0 specs from frozen, metadata-only ARMOR artifacts.

The builder binds an exact-token prompt selection to one target-free prefreeze
pair. It reads prompt files only to verify their content hashes; prompt text and
raw behavior content are never copied into the resulting spec.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .armor_stage0 import (
    ARM_IDS,
    CONTROL_SUBTYPES,
    SCHEMA_VERSION,
    SHA256_EMPTY,
    build_plan,
    canonical_sha256,
)
from .instrumentation import FALLBACK_POLICY_SHA256


class Stage0SpecBuildError(ValueError):
    """Raised when source artifacts cannot prove a valid one-pair spec."""


PAIR_FIELDS = frozenset(
    {
        "pair_id",
        "behavior_id",
        "attacker_seed",
        "initial_memory_sha256",
        "initial_retrieval_sha256",
        "first_action_sha256",
        "fallback_policy_sha256",
        "fallback_action_sha256",
        "fallback_request_sha256",
        "asset_hashes",
        "decoding_config",
    }
)
PREFREEZE_WRAPPER_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "target_call_budget",
        "pair",
        "pair_sha256",
        "prefreeze_spec_sha256",
        "decoding_config_sha256",
        "raw_attack_or_response_text_included",
    }
)
PREFREEZE_SPEC_FIELDS = frozenset(
    {
        "schema_version",
        "pair_id",
        "attacker_seed",
        "target_call_budget",
        "decoding_config",
    }
)
CONDITION_TO_ARM = {
    "native": ARM_IDS[0],
    "generic": ARM_IDS[1],
    "matched_memory": ARM_IDS[2],
    "label_shuffled": ARM_IDS[3],
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise Stage0SpecBuildError(f"{label} must be an object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Stage0SpecBuildError(f"{label} must be a non-empty string")
    return value.strip()


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise Stage0SpecBuildError(f"{label} must be an integer >= {minimum}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise Stage0SpecBuildError(f"{label} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise Stage0SpecBuildError(
            f"{label} must be a lowercase SHA-256 digest"
        ) from exc
    return value


def _verified_manifest_hash(value: Mapping[str, Any], label: str) -> str:
    claimed = _require_sha256(value.get("manifest_sha256"), f"{label}.manifest_sha256")
    without_hash = dict(value)
    without_hash.pop("manifest_sha256", None)
    if canonical_sha256(without_hash) != claimed:
        raise Stage0SpecBuildError(f"{label} self-hash mismatch")
    return claimed


def _safe_prompt_file(root: Path, relative: Any, label: str) -> Path:
    path_text = _require_string(relative, f"{label}.prompt_path")
    pure = PurePosixPath(path_text)
    if pure.is_absolute() or ".." in pure.parts:
        raise Stage0SpecBuildError(f"{label}.prompt_path escapes the selection pack")
    path = (root / Path(*pure.parts)).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise Stage0SpecBuildError(
            f"{label}.prompt_path escapes the selection pack"
        ) from exc
    if not path.is_file():
        raise Stage0SpecBuildError(f"{label} prompt file is missing")
    return path


def _verify_selection(
    selection: Mapping[str, Any], selection_root: Path
) -> tuple[dict[str, dict[str, Any]], int, int, dict[str, Any]]:
    if selection.get("schema_version") != 1:
        raise Stage0SpecBuildError("selection schema_version must be 1")
    if selection.get("selector_version") != "armor-exact-token-selector-v1":
        raise Stage0SpecBuildError("unsupported exact-token selector version")
    selection_sha = _verified_manifest_hash(selection, "selection")
    target_tokens = _require_int(
        selection.get("target_defense_tokens"),
        "selection.target_defense_tokens",
        minimum=1,
    )
    tokenizer = _require_mapping(selection.get("tokenizer"), "selection.tokenizer")
    tokenizer_identity = _require_sha256(
        tokenizer.get("identity_sha256"), "selection.tokenizer.identity_sha256"
    )
    tokenizer_class = _require_string(tokenizer.get("class"), "selection.tokenizer.class")
    if "qwen" not in tokenizer_class.casefold():
        raise Stage0SpecBuildError("selection tokenizer must be a Qwen tokenizer")
    token_counter = _require_string(selection.get("token_counter"), "selection.token_counter")
    if not token_counter.endswith(tokenizer_identity[:16]):
        raise Stage0SpecBuildError("selection token counter does not bind tokenizer identity")

    inputs = _require_mapping(selection.get("inputs"), "selection.inputs")
    expected_relations = {
        "generic": "generic",
        "matched_memory": "matched",
        "label_shuffled": "label_shuffled",
    }
    input_rows: dict[str, Mapping[str, Any]] = {}
    compiler_budgets: set[int] = set()
    for name, relation in expected_relations.items():
        row = _require_mapping(inputs.get(name), f"selection.inputs.{name}")
        if row.get("relation") != relation:
            raise Stage0SpecBuildError(f"selection input relation mismatch: {name}")
        compiler_budgets.add(
            _require_int(row.get("token_budget"), f"selection.inputs.{name}.token_budget", minimum=1)
        )
        _require_sha256(
            row.get("manifest_sha256"), f"selection.inputs.{name}.manifest_sha256"
        )
        _require_sha256(
            row.get("compiler_manifest_sha256"),
            f"selection.inputs.{name}.compiler_manifest_sha256",
        )
        surfaced_provenance = row.get("compiler_memory_provenance_sha256")
        if name == "generic":
            if surfaced_provenance is not None:
                raise Stage0SpecBuildError(
                    "generic selection input must not claim memory provenance"
                )
        else:
            _require_sha256(
                surfaced_provenance,
                f"selection.inputs.{name}.compiler_memory_provenance_sha256",
            )
        input_rows[name] = row
    if len(compiler_budgets) != 1:
        raise Stage0SpecBuildError("selection inputs must share one compiler token budget")
    prompt_token_budget = next(iter(compiler_budgets))
    if target_tokens > prompt_token_budget:
        raise Stage0SpecBuildError("selected defense tokens exceed compiler token budget")

    conditions = _require_mapping(selection.get("conditions"), "selection.conditions")
    if set(conditions) != set(CONDITION_TO_ARM):
        raise Stage0SpecBuildError("selection must contain exactly four ARMOR conditions")
    verified: dict[str, dict[str, Any]] = {}
    defended_hashes: set[str] = set()
    for condition in CONDITION_TO_ARM:
        row = _require_mapping(conditions[condition], f"selection.conditions.{condition}")
        path = _safe_prompt_file(
            selection_root,
            row.get("prompt_path"),
            f"selection.conditions.{condition}",
        )
        content = path.read_bytes()
        content_hash = _sha256_bytes(content)
        prompt_hash = _require_sha256(
            row.get("text_sha256"), f"selection.conditions.{condition}.text_sha256"
        )
        file_hash = _require_sha256(
            row.get("prompt_file_sha256"),
            f"selection.conditions.{condition}.prompt_file_sha256",
        )
        if content_hash != file_hash or content_hash != prompt_hash:
            raise Stage0SpecBuildError(f"selection prompt hash mismatch: {condition}")
        if row.get("raw_attack_payload_included") is not False:
            raise Stage0SpecBuildError(f"selection prompt payload contract failed: {condition}")
        surfaced_provenance = row.get("compiler_memory_provenance_sha256")
        if condition in {"native", "generic"}:
            if surfaced_provenance is not None:
                raise Stage0SpecBuildError(
                    f"{condition} condition must not claim memory provenance"
                )
        else:
            input_provenance = input_rows[condition].get(
                "compiler_memory_provenance_sha256"
            )
            if surfaced_provenance != input_provenance:
                raise Stage0SpecBuildError(
                    f"selection compiler provenance mismatch: {condition}"
                )
        tokens = _require_int(
            row.get("tokens"), f"selection.conditions.{condition}.tokens"
        )
        if condition == "native":
            if content or tokens != 0 or prompt_hash != SHA256_EMPTY:
                raise Stage0SpecBuildError("native condition must be empty and zero-token")
        else:
            if tokens != target_tokens:
                raise Stage0SpecBuildError(
                    f"defended condition is not exact-token matched: {condition}"
                )
            defended_hashes.add(prompt_hash)
            provenance = _require_mapping(
                row.get("provenance"), f"selection.conditions.{condition}.provenance"
            )
            _require_string(
                provenance.get("candidate_id"),
                f"selection.conditions.{condition}.provenance.candidate_id",
            )
            _require_sha256(
                provenance.get("candidate_manifest_sha256"),
                f"selection.conditions.{condition}.provenance.candidate_manifest_sha256",
            )
            _require_sha256(
                provenance.get("program_sha256"),
                f"selection.conditions.{condition}.provenance.program_sha256",
            )
        verified[condition] = {"prompt_sha256": prompt_hash, "tokens": tokens}
    if len(defended_hashes) != 3:
        raise Stage0SpecBuildError("the three defended prompt texts must be distinct")
    return (
        verified,
        target_tokens,
        prompt_token_budget,
        {
            "selection_manifest_sha256": selection_sha,
            "selector_version": selection["selector_version"],
            "token_counter": token_counter,
            "tokenizer_identity_sha256": tokenizer_identity,
            "input_rows": input_rows,
        },
    )


def _verify_compiler(
    compiler: Mapping[str, Any],
    *,
    compiler_bytes: bytes,
    selection_input: Mapping[str, Any],
    relation: str,
    label: str,
) -> dict[str, str]:
    if not isinstance(compiler_bytes, bytes):
        raise Stage0SpecBuildError(f"{label} compiler bytes must be bytes")
    try:
        parsed_compiler = json.loads(compiler_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Stage0SpecBuildError(f"{label} compiler bytes are not valid JSON") from exc
    if parsed_compiler != compiler:
        raise Stage0SpecBuildError(
            f"{label} compiler object does not match its supplied file bytes"
        )
    compiler_bytes_sha256 = _sha256_bytes(compiler_bytes)
    expected_compiler_sha = _require_sha256(
        selection_input.get("compiler_manifest_sha256"),
        f"selection.inputs.{label}.compiler_manifest_sha256",
    )
    if compiler_bytes_sha256 != expected_compiler_sha:
        raise Stage0SpecBuildError(f"{label} compiler manifest digest mismatch")
    if compiler.get("schema_version") != 1 or compiler.get("relation") != relation:
        raise Stage0SpecBuildError(f"{label} compiler relation or schema mismatch")
    if compiler.get("token_counter") != selection_input.get("source_token_counter"):
        raise Stage0SpecBuildError(f"{label} compiler token counter mismatch")

    candidate_sha = _require_sha256(
        selection_input.get("manifest_sha256"),
        f"selection.inputs.{label}.manifest_sha256",
    )
    token_budget = _require_int(
        selection_input.get("token_budget"),
        f"selection.inputs.{label}.token_budget",
        minimum=1,
    )
    budget_rows = compiler.get("budget_manifests")
    if not isinstance(budget_rows, list):
        raise Stage0SpecBuildError(f"{label} compiler budget_manifests must be a list")
    matches = [
        row
        for row in budget_rows
        if isinstance(row, Mapping)
        and row.get("sha256", row.get("manifest_sha256")) == candidate_sha
        and row.get("token_budget") == token_budget
    ]
    if len(matches) != 1:
        raise Stage0SpecBuildError(
            f"{label} compiler does not bind the selected candidate manifest exactly once"
        )

    memory_sha = _require_sha256(compiler.get("memory_sha256"), f"{label}.memory_sha256")
    semantic_sha = _require_sha256(
        compiler.get("memory_semantic_sha256"), f"{label}.memory_semantic_sha256"
    )
    clause_pack = _require_mapping(compiler.get("clause_pack"), f"{label}.clause_pack")
    if clause_pack.get("relation") != relation:
        raise Stage0SpecBuildError(f"{label} clause-pack relation mismatch")
    if clause_pack.get("raw_attack_payload_included") is not False:
        raise Stage0SpecBuildError(f"{label} compiler payload contract failed")
    if clause_pack.get("memory_sha256") != memory_sha:
        raise Stage0SpecBuildError(f"{label} clause-pack memory hash mismatch")
    if clause_pack.get("memory_semantic_sha256") != semantic_sha:
        raise Stage0SpecBuildError(f"{label} clause-pack semantic hash mismatch")
    compiler_provenance = _require_sha256(
        clause_pack.get("compiler_memory_provenance_sha256"),
        f"{label}.clause_pack.compiler_memory_provenance_sha256",
    )
    surfaced_provenance = _require_sha256(
        selection_input.get("compiler_memory_provenance_sha256"),
        f"selection.inputs.{label}.compiler_memory_provenance_sha256",
    )
    if compiler_provenance != surfaced_provenance:
        raise Stage0SpecBuildError(
            f"{label} compiler provenance differs from the exact selection"
        )
    atom_ids = clause_pack.get("selected_atom_ids")
    atom_hashes = clause_pack.get("selected_atom_sha256")
    if (
        not isinstance(atom_ids, list)
        or not atom_ids
        or not all(isinstance(value, str) and value for value in atom_ids)
        or len(set(atom_ids)) != len(atom_ids)
        or not isinstance(atom_hashes, list)
        or len(atom_hashes) != len(atom_ids)
    ):
        raise Stage0SpecBuildError(f"{label} selected-atom provenance is invalid")
    for index, digest in enumerate(atom_hashes):
        _require_sha256(digest, f"{label}.selected_atom_sha256[{index}]")
    if relation == "matched":
        if compiler_provenance != memory_sha:
            raise Stage0SpecBuildError(
                "matched compiler provenance must equal the source memory hash"
            )
    else:
        derived = canonical_sha256(
            {
                "relation": relation,
                "source_memory_sha256": memory_sha,
                "selected_atom_ids": atom_ids,
                "selected_atom_sha256": atom_hashes,
            }
        )
        if compiler_provenance != derived or compiler_provenance == memory_sha:
            raise Stage0SpecBuildError(
                "label-shuffled compiler provenance derivation mismatch"
            )
    return {
        "compiler_manifest_sha256": compiler_bytes_sha256,
        "memory_sha256": memory_sha,
        "memory_semantic_sha256": semantic_sha,
        "compiler_memory_provenance_sha256": compiler_provenance,
    }


def _verify_pair(pair: Mapping[str, Any]) -> dict[str, Any]:
    if set(pair) != PAIR_FIELDS:
        missing = sorted(PAIR_FIELDS.difference(pair))
        extra = sorted(set(pair).difference(PAIR_FIELDS))
        raise Stage0SpecBuildError(
            f"prefreeze pair fields mismatch; missing={missing}, extra={extra}"
        )
    normalized = dict(pair)
    _require_string(pair.get("pair_id"), "pair.pair_id")
    _require_string(pair.get("behavior_id"), "pair.behavior_id")
    _require_int(pair.get("attacker_seed"), "pair.attacker_seed")
    for field in (
        "initial_memory_sha256",
        "initial_retrieval_sha256",
        "first_action_sha256",
        "fallback_policy_sha256",
        "fallback_action_sha256",
        "fallback_request_sha256",
    ):
        _require_sha256(pair.get(field), f"pair.{field}")
    if pair.get("fallback_policy_sha256") != FALLBACK_POLICY_SHA256:
        raise Stage0SpecBuildError("prefreeze pair fallback policy is not the live policy")
    assets = _require_mapping(pair.get("asset_hashes"), "pair.asset_hashes")
    if not assets:
        raise Stage0SpecBuildError("prefreeze pair must contain at least one VLM asset")
    for asset_id, digest in assets.items():
        _require_string(asset_id, "pair asset id")
        _require_sha256(digest, f"pair.asset_hashes.{asset_id}")
    decoding = _require_mapping(pair.get("decoding_config"), "pair.decoding_config")
    if not decoding:
        raise Stage0SpecBuildError("pair.decoding_config must not be empty")
    return normalized


def _verify_prefreeze_wrapper(
    wrapper: Mapping[str, Any],
    *,
    prefreeze_spec_bytes: bytes,
    target_call_budget: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(wrapper) != PREFREEZE_WRAPPER_FIELDS:
        missing = sorted(PREFREEZE_WRAPPER_FIELDS.difference(wrapper))
        extra = sorted(set(wrapper).difference(PREFREEZE_WRAPPER_FIELDS))
        raise Stage0SpecBuildError(
            f"prefreeze wrapper fields mismatch; missing={missing}, extra={extra}"
        )
    if wrapper.get("schema_version") != 1:
        raise Stage0SpecBuildError("prefreeze wrapper schema_version must be 1")
    if wrapper.get("artifact_type") != "armor-stage0-prefreeze-pair-v1":
        raise Stage0SpecBuildError("unsupported prefreeze wrapper artifact_type")
    if wrapper.get("raw_attack_or_response_text_included") is not False:
        raise Stage0SpecBuildError("prefreeze wrapper violates the raw-text contract")
    attested_budget = _require_int(
        wrapper.get("target_call_budget"),
        "prefreeze wrapper.target_call_budget",
        minimum=1,
    )
    if attested_budget != target_call_budget:
        raise Stage0SpecBuildError(
            "prefreeze target-call budget differs from the Stage-0 budget"
        )

    pair = _verify_pair(_require_mapping(wrapper.get("pair"), "prefreeze wrapper.pair"))
    pair_sha = _require_sha256(
        wrapper.get("pair_sha256"), "prefreeze wrapper.pair_sha256"
    )
    if pair_sha != canonical_sha256(pair):
        raise Stage0SpecBuildError("prefreeze wrapper pair hash mismatch")
    decoding_sha = _require_sha256(
        wrapper.get("decoding_config_sha256"),
        "prefreeze wrapper.decoding_config_sha256",
    )
    if decoding_sha != canonical_sha256(pair["decoding_config"]):
        raise Stage0SpecBuildError("prefreeze wrapper decoding hash mismatch")

    if not isinstance(prefreeze_spec_bytes, bytes):
        raise Stage0SpecBuildError("prefreeze spec bytes must be bytes")
    expected_spec_sha = _require_sha256(
        wrapper.get("prefreeze_spec_sha256"),
        "prefreeze wrapper.prefreeze_spec_sha256",
    )
    if _sha256_bytes(prefreeze_spec_bytes) != expected_spec_sha:
        raise Stage0SpecBuildError("prefreeze spec file digest mismatch")
    try:
        prefreeze_spec = json.loads(prefreeze_spec_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Stage0SpecBuildError("prefreeze spec bytes are not valid JSON") from exc
    if not isinstance(prefreeze_spec, Mapping):
        raise Stage0SpecBuildError("prefreeze spec must be a JSON object")
    if set(prefreeze_spec) != PREFREEZE_SPEC_FIELDS:
        missing = sorted(PREFREEZE_SPEC_FIELDS.difference(prefreeze_spec))
        extra = sorted(set(prefreeze_spec).difference(PREFREEZE_SPEC_FIELDS))
        raise Stage0SpecBuildError(
            f"prefreeze spec fields mismatch; missing={missing}, extra={extra}"
        )
    if prefreeze_spec.get("schema_version") != 1:
        raise Stage0SpecBuildError("prefreeze spec schema_version must be 1")
    if prefreeze_spec.get("pair_id") != pair["pair_id"]:
        raise Stage0SpecBuildError("prefreeze spec pair_id mismatch")
    if prefreeze_spec.get("attacker_seed") != pair["attacker_seed"]:
        raise Stage0SpecBuildError("prefreeze spec attacker_seed mismatch")
    if prefreeze_spec.get("target_call_budget") != attested_budget:
        raise Stage0SpecBuildError("prefreeze spec target-call budget mismatch")
    if prefreeze_spec.get("decoding_config") != pair["decoding_config"]:
        raise Stage0SpecBuildError("prefreeze spec decoding config mismatch")
    return (
        pair,
        {
            "prefreeze_artifact_type": wrapper["artifact_type"],
            "prefreeze_pair_sha256": pair_sha,
            "prefreeze_spec_sha256": expected_spec_sha,
            "prefreeze_decoding_config_sha256": decoding_sha,
            "prefreeze_target_call_budget": attested_budget,
        },
    )


def build_one_pair_stage0_spec(
    *,
    prefreeze_wrapper: Mapping[str, Any],
    prefreeze_spec_bytes: bytes,
    selection_manifest: Mapping[str, Any],
    selection_root: str | Path,
    matched_compiler_manifest: Mapping[str, Any],
    matched_compiler_bytes: bytes,
    shuffled_compiler_manifest: Mapping[str, Any],
    shuffled_compiler_bytes: bytes,
    evaluator_provenance: Mapping[str, Any],
    experiment_id: str,
    target_call_budget: int,
    randomization_seed: int,
    max_censoring_rate: float = 0.01,
) -> dict[str, Any]:
    """Return a fully validated, raw-free Stage-0 source spec."""

    root = Path(selection_root).expanduser().resolve()
    budget = _require_int(target_call_budget, "target_call_budget", minimum=1)
    pair, prefreeze_meta = _verify_prefreeze_wrapper(
        _require_mapping(prefreeze_wrapper, "prefreeze wrapper"),
        prefreeze_spec_bytes=prefreeze_spec_bytes,
        target_call_budget=budget,
    )
    selection = _require_mapping(selection_manifest, "selection manifest")
    prompts, target_tokens, prompt_budget, selection_meta = _verify_selection(
        selection, root
    )
    input_rows = selection_meta.pop("input_rows")
    assert isinstance(input_rows, Mapping)
    matched = _verify_compiler(
        _require_mapping(matched_compiler_manifest, "matched compiler"),
        compiler_bytes=matched_compiler_bytes,
        selection_input=_require_mapping(input_rows["matched_memory"], "matched input"),
        relation="matched",
        label="matched_memory",
    )
    shuffled = _verify_compiler(
        _require_mapping(shuffled_compiler_manifest, "shuffled compiler"),
        compiler_bytes=shuffled_compiler_bytes,
        selection_input=_require_mapping(input_rows["label_shuffled"], "shuffled input"),
        relation="label_shuffled",
        label="label_shuffled",
    )
    if matched["memory_sha256"] != shuffled["memory_sha256"]:
        raise Stage0SpecBuildError(
            "matched and label-shuffled compilers must share one source memory"
        )
    if matched["memory_semantic_sha256"] != shuffled["memory_semantic_sha256"]:
        raise Stage0SpecBuildError(
            "matched and label-shuffled compilers must share semantic memory provenance"
        )
    if pair["initial_memory_sha256"] != matched["memory_sha256"]:
        raise Stage0SpecBuildError(
            "prefreeze memory does not equal matched compiler source memory"
        )

    arms = {
        ARM_IDS[0]: {
            "prompt_sha256": prompts["native"]["prompt_sha256"],
            "prompt_token_count": prompts["native"]["tokens"],
            "memory_relation": "none",
            "compiler_memory_sha256": None,
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[0]],
        },
        ARM_IDS[1]: {
            "prompt_sha256": prompts["generic"]["prompt_sha256"],
            "prompt_token_count": prompts["generic"]["tokens"],
            "memory_relation": "none",
            "compiler_memory_sha256": None,
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[1]],
        },
        ARM_IDS[2]: {
            "prompt_sha256": prompts["matched_memory"]["prompt_sha256"],
            "prompt_token_count": prompts["matched_memory"]["tokens"],
            "memory_relation": "matched",
            "compiler_memory_sha256": matched[
                "compiler_memory_provenance_sha256"
            ],
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[2]],
        },
        ARM_IDS[3]: {
            "prompt_sha256": prompts["label_shuffled"]["prompt_sha256"],
            "prompt_token_count": prompts["label_shuffled"]["tokens"],
            "memory_relation": "mismatched",
            "compiler_memory_sha256": shuffled[
                "compiler_memory_provenance_sha256"
            ],
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[3]],
        },
    }
    experiment = _require_string(experiment_id, "experiment_id")
    random_seed = _require_int(randomization_seed, "randomization_seed")
    if isinstance(max_censoring_rate, bool) or not isinstance(
        max_censoring_rate, (int, float)
    ):
        raise Stage0SpecBuildError("max_censoring_rate must be numeric")
    spec = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": experiment,
        "target_call_budget": budget,
        "randomization_seed": random_seed,
        "prompt_token_budget": prompt_budget,
        "max_censoring_rate": float(max_censoring_rate),
        "evaluator_provenance": dict(
            _require_mapping(evaluator_provenance, "evaluator_provenance")
        ),
        "arms": arms,
        "pairs": [pair],
        "provenance": {
            **selection_meta,
            **prefreeze_meta,
            "target_defense_tokens": target_tokens,
            "matched_compiler_manifest_sha256": matched[
                "compiler_manifest_sha256"
            ],
            "matched_compiler_memory_provenance_sha256": matched[
                "compiler_memory_provenance_sha256"
            ],
            "shuffled_compiler_manifest_sha256": shuffled[
                "compiler_manifest_sha256"
            ],
            "shuffled_compiler_memory_provenance_sha256": shuffled[
                "compiler_memory_provenance_sha256"
            ],
            "raw_prompt_or_behavior_text_included": False,
        },
    }
    # Reuse the definitive Stage-0 validator before returning a source spec.
    build_plan(spec)
    return spec


__all__ = [
    "CONDITION_TO_ARM",
    "PAIR_FIELDS",
    "PREFREEZE_SPEC_FIELDS",
    "PREFREEZE_WRAPPER_FIELDS",
    "Stage0SpecBuildError",
    "build_one_pair_stage0_spec",
]
