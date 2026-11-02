"""Extract a metadata-only Stage-0 pairing contract from a no-target preflight.

The preflight uses the real attacker, memory retrieval, and tools, but replaces
the target with a capture stub that raises before generation.  Consequently it
can freeze the first request and asset hashes without exposing the target to an
extra attack or allowing a defense response to influence the initial action.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any


class PrefreezeValidationError(ValueError):
    """Raised when a capture row is not proof of a target-free preflight."""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _require_sha256(value: Any, label: str) -> str:
    if not _is_sha256(value):
        raise PrefreezeValidationError(f"{label} must be a lowercase SHA-256 digest")
    return str(value)


@dataclass(frozen=True)
class PrefreezeEvidence:
    behavior_id: str
    attacker_seed: int
    target_call_budget: int
    initial_memory_sha256: str
    initial_retrieval_sha256: str
    first_target_request_sha256: str
    first_target_action_sha256: str
    fallback_policy_sha256: str
    fallback_action_sha256: str
    fallback_request_sha256: str
    asset_hashes: tuple[tuple[str, str], ...]
    instrumentation_schema_version: int = 3

    def __post_init__(self) -> None:
        if not self.behavior_id:
            raise PrefreezeValidationError("behavior_id cannot be empty")
        if isinstance(self.attacker_seed, bool) or self.attacker_seed < 0:
            raise PrefreezeValidationError("attacker_seed must be non-negative")
        if (
            isinstance(self.target_call_budget, bool)
            or not isinstance(self.target_call_budget, int)
            or self.target_call_budget < 1
        ):
            raise PrefreezeValidationError("target_call_budget must be positive")
        for field in (
            "initial_memory_sha256",
            "initial_retrieval_sha256",
            "first_target_request_sha256",
            "first_target_action_sha256",
            "fallback_policy_sha256",
            "fallback_action_sha256",
            "fallback_request_sha256",
        ):
            _require_sha256(getattr(self, field), field)
        if not all(name and _is_sha256(digest) for name, digest in self.asset_hashes):
            raise PrefreezeValidationError("asset_hashes must contain named SHA-256 digests")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["asset_hashes"] = dict(self.asset_hashes)
        value["raw_attack_or_response_text_included"] = False
        return value

    def to_pair_record(
        self,
        *,
        pair_id: str,
        decoding_config: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not pair_id.strip():
            raise PrefreezeValidationError("pair_id cannot be empty")
        if not isinstance(decoding_config, Mapping) or not decoding_config:
            raise PrefreezeValidationError("decoding_config must be a non-empty mapping")
        return {
            "pair_id": pair_id.strip(),
            "behavior_id": self.behavior_id,
            "attacker_seed": self.attacker_seed,
            "initial_memory_sha256": self.initial_memory_sha256,
            "initial_retrieval_sha256": self.initial_retrieval_sha256,
            # The Stage-0 schema retains this historical field name, while its
            # manifest explicitly defines the value as first target request.
            "first_action_sha256": self.first_target_request_sha256,
            "fallback_policy_sha256": self.fallback_policy_sha256,
            "fallback_action_sha256": self.fallback_action_sha256,
            "fallback_request_sha256": self.fallback_request_sha256,
            "asset_hashes": dict(self.asset_hashes),
            "decoding_config": dict(decoding_config),
        }


def extract_prefreeze_evidence(
    row: Mapping[str, Any],
    *,
    initial_memory_sha256: str,
) -> PrefreezeEvidence:
    """Validate and reduce one capture-stub ARMS row to hashes only."""

    memory_hash = _require_sha256(initial_memory_sha256, "initial_memory_sha256")
    if not isinstance(row, Mapping):
        raise PrefreezeValidationError("row must be a mapping")
    behavior = row.get("behavior")
    instrumentation = row.get("instrumentation")
    history = row.get("history")
    if not isinstance(behavior, Mapping) or not str(behavior.get("id", "")).strip():
        raise PrefreezeValidationError("row is missing behavior.id")
    if not isinstance(instrumentation, Mapping):
        raise PrefreezeValidationError("row is missing instrumentation")
    if instrumentation.get("schema_version") != 3:
        raise PrefreezeValidationError("prefreeze requires instrumentation schema v3")
    target_call_budget = instrumentation.get("target_call_budget")
    if (
        isinstance(target_call_budget, bool)
        or not isinstance(target_call_budget, int)
        or target_call_budget < 1
    ):
        raise PrefreezeValidationError(
            "prefreeze is missing a positive target_call_budget attestation"
        )
    if not isinstance(history, list) or len(history) != 1 or not isinstance(history[0], Mapping):
        raise PrefreezeValidationError("prefreeze must capture exactly one target call")
    if instrumentation.get("target_calls_started") != 1:
        raise PrefreezeValidationError("prefreeze target call count mismatch")
    if instrumentation.get("target_responses_received") != 0:
        raise PrefreezeValidationError("prefreeze unexpectedly received a target response")
    if instrumentation.get("judge_invocations") != 0:
        raise PrefreezeValidationError("prefreeze unexpectedly invoked a judge")
    if instrumentation.get("termination_reason") != "target_error":
        raise PrefreezeValidationError("prefreeze must terminate at the capture target")

    record = history[0]
    if record.get("call_index") != 1 or record.get("error") != "target_error":
        raise PrefreezeValidationError("first record is not the capture target error")
    request = record.get("turns")
    if not isinstance(request, list) or len(request) != 1 or not isinstance(request[0], Mapping):
        raise PrefreezeValidationError("prefreeze record must contain one resolved request turn")
    request_text = request[0].get("text")
    if not isinstance(request_text, str):
        raise PrefreezeValidationError("prefreeze request text is unavailable for hash verification")
    request_hash = _sha256_text(request_text)
    if record.get("request_sha256") != request_hash:
        raise PrefreezeValidationError("prefreeze request hash mismatch")
    response = record.get("response")
    if response != "" or record.get("response_sha256") != _sha256_text(""):
        raise PrefreezeValidationError("capture target must not return response text")
    action_hash = _require_sha256(record.get("action_sha256"), "first_target_action_sha256")
    image_hashes = record.get("image_content_sha256")
    if not isinstance(image_hashes, list) or not image_hashes:
        raise PrefreezeValidationError("prefreeze first request must contain an image")
    if not all(_is_sha256(value) for value in image_hashes):
        raise PrefreezeValidationError("prefreeze contains an invalid image hash")

    provenance = instrumentation.get("provenance")
    fallback = instrumentation.get("planner_fallback")
    if not isinstance(provenance, Mapping) or not isinstance(fallback, Mapping):
        raise PrefreezeValidationError("prefreeze is missing provenance or fallback metadata")
    if provenance.get("first_target_request_sha256") != request_hash:
        raise PrefreezeValidationError("runtime first target request hash mismatch")
    if provenance.get("first_target_action_sha256") != action_hash:
        raise PrefreezeValidationError("runtime first target action hash mismatch")
    runtime_assets = provenance.get("asset_content_sha256")
    if runtime_assets != sorted(set(image_hashes)):
        raise PrefreezeValidationError("runtime asset provenance mismatch")
    attacker_seed = provenance.get("base_seed")
    if isinstance(attacker_seed, bool) or not isinstance(attacker_seed, int) or attacker_seed < 0:
        raise PrefreezeValidationError("invalid attacker base seed")

    assets = tuple(
        (f"first-action-image-{index:03d}", str(digest))
        for index, digest in enumerate(image_hashes, start=1)
    )
    return PrefreezeEvidence(
        behavior_id=str(behavior["id"]).strip(),
        attacker_seed=attacker_seed,
        target_call_budget=target_call_budget,
        initial_memory_sha256=memory_hash,
        initial_retrieval_sha256=_require_sha256(
            provenance.get("initial_retrieval_sha256"),
            "initial_retrieval_sha256",
        ),
        first_target_request_sha256=request_hash,
        first_target_action_sha256=action_hash,
        fallback_policy_sha256=_require_sha256(
            fallback.get("configured_policy_sha256"),
            "fallback_policy_sha256",
        ),
        # The first frozen valid query is the protocol fallback. The live
        # adapter verifies these values only if fallback is actually exercised.
        fallback_action_sha256=action_hash,
        fallback_request_sha256=request_hash,
        asset_hashes=assets,
    )
