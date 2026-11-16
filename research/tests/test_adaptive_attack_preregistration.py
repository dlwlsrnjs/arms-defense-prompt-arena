from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from defense_arena.adaptive_attack_preregistration import (
    GATE_IDS,
    METHOD_KEYS,
    PreregistrationValidationError,
    SOURCE_KEYS,
    TARGET_KEYS,
    load_json,
    validate_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
ATTACK = ROOT / "configs" / "adaptive_attack_universe_v1.json"
REGISTRY = ROOT / "configs" / "behavior_registry_v1.json"
SCHEMA = ROOT / "schemas" / "behavior-registry-v1.schema.json"
SCRIPT = ROOT / "scripts" / "validate_adaptive_attack_preregistration.py"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _validate_changed(tmp_path: Path, *, attack: dict | None = None, registry: dict | None = None) -> dict:
    attack_path = ATTACK if attack is None else _write(tmp_path / "attack.json", attack)
    registry_path = REGISTRY if registry is None else _write(tmp_path / "registry.json", registry)
    return validate_bundle(attack_path, registry_path, SCHEMA)


def test_reference_bundle_is_valid_but_not_claim_ready() -> None:
    summary = validate_bundle(ATTACK, REGISTRY, SCHEMA)

    assert summary["valid"] is True
    assert summary["claim_ready"] is False
    assert summary["registration_status"] == "candidate_not_frozen"
    assert tuple(summary["methods"]) == METHOD_KEYS
    assert tuple(summary["targets"]) == TARGET_KEYS
    assert tuple(summary["behavior_sources"]) == SOURCE_KEYS
    assert tuple(summary["gates"]) == GATE_IDS
    assert summary["next_gate"] == "G0"
    assert all(len(value) == 64 for value in summary["sha256"].values())


def test_cli_emits_machine_readable_summary_without_model_calls() -> None:
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
    assert summary["primary_feedback"] == "response_only"
    assert summary["official_arms_reproduction_claimed"] is False


def test_observed_pins_licenses_and_canonical_redirects_are_explicit() -> None:
    methods = {row["key"]: row for row in _json(ATTACK)["method_registry"]}

    assert all(len(row["upstream_revision_candidate"]) == 40 for row in methods.values())
    assert all(row["upstream_revision_status"] == "observed_candidate_unfrozen" for row in methods.values())
    assert all(row["license_spdx_observed"] == "MIT" for row in methods.values())
    assert all(row["license_evidence_status"] == "api_observation_needs_G0_local_full_hash" for row in methods.values())
    assert methods["gptfuzzer"]["canonical_repository_url"] == "https://github.com/hubertyoo/GPTFuzz"
    assert methods["autodan_turbo"]["canonical_repository_url"] == "https://github.com/SaFo-Lab/AutoDAN-Turbo"


def test_behavior_source_candidate_pins_and_license_evidence_are_explicit() -> None:
    sources = {row["source_key"]: row for row in _json(REGISTRY)["source_collections"]}

    assert set(sources) == set(SOURCE_KEYS)
    assert all(len(row["revision_candidate"]) == 40 for row in sources.values())
    assert all(row["revision_status"] == "observed_candidate_unfrozen" for row in sources.values())
    assert all(len(row["license_blob_sha_observed"]) == 40 for row in sources.values())
    assert all(row["revision_candidate"] in row["license_evidence_url"] for row in sources.values())
    assert all(
        row["license_status"] == "api_observation_needs_G0_local_full_hash"
        for row in sources.values()
    )
    assert sources["harmbench"]["license_spdx_observed"] == "MIT"
    assert sources["advbench"]["license_spdx_observed"] == "MIT"
    assert sources["salad_bench"]["license_spdx_observed"] == "Apache-2.0"


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version": 1, "schema_version": 1}\n', encoding="utf-8")

    with pytest.raises(PreregistrationValidationError, match="duplicate JSON key"):
        load_json(path)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda raw: raw["method_registry"].pop(),
            "method registry must be exactly",
        ),
        (
            lambda raw: raw["feedback_arms"]["primary"]["attacker_visible_after_each_target_call"].append("judge_score"),
            "may observe only the target response",
        ),
        (
            lambda raw: raw["feedback_arms"]["diagnostic"].update(memory_isolated_from_primary=False),
            "diagnostic memory must be isolated",
        ),
        (
            lambda raw: raw["event_ledger_contract"]["required_outcome_codes"].remove("target_timeout"),
            "missing required outcome codes",
        ),
        (
            lambda raw: raw["event_ledger_contract"]["immutability"].update(in_place_rewrite_allowed=True),
            "cannot permit in-place rewrite",
        ),
        (
            lambda raw: raw["evaluation_design"]["leave_one_method_out_folds"][0]["memory_methods"].append("pair"),
            "must contain four memory methods",
        ),
        (
            lambda raw: raw["gates"][2].update(entry_requires=["G0"]),
            "G2 must depend only on the previous gate",
        ),
        (
            lambda raw: raw["method_registry"][0].update(enabled_for_claims=True),
            "cannot be enabled for claims",
        ),
        (
            lambda raw: raw["claim_boundary"].update(official_arms_reproduction_claimed=True),
            "official ARMS reproduction cannot be claimed",
        ),
    ],
)
def test_attack_contract_weakening_fails_closed(tmp_path: Path, mutator, message: str) -> None:
    raw = copy.deepcopy(_json(ATTACK))
    mutator(raw)

    with pytest.raises(PreregistrationValidationError, match=message):
        _validate_changed(tmp_path, attack=raw)


def test_raw_payload_bearing_field_is_rejected(tmp_path: Path) -> None:
    raw = copy.deepcopy(_json(REGISTRY))
    raw["behavior_text"] = "redacted-placeholder"

    with pytest.raises(PreregistrationValidationError, match="schema-forbidden keys|forbidden payload-bearing key"):
        _validate_changed(tmp_path, registry=raw)


def test_unknown_registry_field_is_rejected_by_schema(tmp_path: Path) -> None:
    raw = copy.deepcopy(_json(REGISTRY))
    raw["release_boundary"]["unregistered_release_switch"] = False

    with pytest.raises(PreregistrationValidationError, match="schema-forbidden keys"):
        _validate_changed(tmp_path, registry=raw)


def test_registry_cannot_be_marked_frozen_early(tmp_path: Path) -> None:
    raw = copy.deepcopy(_json(REGISTRY))
    raw["status"] = "frozen_at_G2"
    raw["freeze_requirements"]["current_gate_passed"] = True
    raw["freeze_requirements"]["main_experiment_access_allowed"] = True

    with pytest.raises(PreregistrationValidationError, match="must remain explicitly unfrozen"):
        _validate_changed(tmp_path, registry=raw)


def test_outcome_based_or_manual_sampling_is_rejected(tmp_path: Path) -> None:
    for field in ("outcome_based_selection_allowed", "manual_example_selection_allowed"):
        raw = copy.deepcopy(_json(REGISTRY))
        raw["sampling_contract"][field] = True
        with pytest.raises(PreregistrationValidationError, match="JSON Schema const"):
            _validate_changed(tmp_path, registry=raw)


def test_attack_and_registry_split_contracts_must_match(tmp_path: Path) -> None:
    raw = copy.deepcopy(_json(ATTACK))
    raw["evaluation_design"]["splits"][0]["fraction"] = 0.4

    with pytest.raises(PreregistrationValidationError, match="split fractions"):
        _validate_changed(tmp_path, attack=raw)


def test_public_bundle_rejects_local_filesystem_paths(tmp_path: Path) -> None:
    raw = copy.deepcopy(_json(ATTACK))
    raw["method_registry"][0]["repository_url"] = "/data1/private/upstream"

    with pytest.raises(PreregistrationValidationError, match="HTTPS GitHub URL|local filesystem path"):
        _validate_changed(tmp_path, attack=raw)
