from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
from jsonschema import ValidationError

try:
    from jsonschema import Draft202012Validator as ContractValidator
except ImportError:  # Ubuntu's jsonschema 3.x; the contract uses a Draft-7-compatible keyword subset.
    from jsonschema import Draft7Validator as ContractValidator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
FIXTURE_DIR = ROOT / "fixtures" / "aamd-benchmark-io-v1"


def _load(name: str):
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _validator(name: str) -> ContractValidator:
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    ContractValidator.check_schema(schema)
    return ContractValidator(schema)


def _visible_fields_hash(fields: list[str]) -> str:
    raw = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def test_all_excluded_demo_envelopes_validate_and_commit_visible_fields() -> None:
    groups = (
        (_load("excluded-demo-instances.json"), _validator("aamd-benchmark-instance-v1.schema.json")),
        (_load("excluded-demo-predictions.json"), _validator("aamd-benchmark-prediction-v1.schema.json")),
    )
    for rows, validator in groups:
        assert len(rows) == 6
        for row in rows:
            validator.validate(row)
            commitment = row["projection_commitment"]
            assert commitment["visible_fields_sha256"] == _visible_fields_hash(
                commitment["visible_fields"]
            )
            assert row["contract_status"] == "g2_pending_no_executable_scorer"


@pytest.mark.parametrize("forbidden_key", ["attack_text", "raw_payload", "target_response", "gold_answer"])
def test_instance_payload_rejects_raw_or_direct_answer_fields(forbidden_key: str) -> None:
    row = copy.deepcopy(_load("excluded-demo-instances.json")[3])
    row["payload"][forbidden_key] = "not_permitted"
    with pytest.raises(ValidationError):
        _validator("aamd-benchmark-instance-v1.schema.json").validate(row)


@pytest.mark.parametrize("forbidden_key", ["answer", "raw_system_prompt", "attack_payload", "direct_score"])
def test_prediction_rejects_direct_answer_or_raw_content_fields(forbidden_key: str) -> None:
    row = copy.deepcopy(_load("excluded-demo-predictions.json")[4])
    row["prediction"][forbidden_key] = "not_permitted"
    with pytest.raises(ValidationError):
        _validator("aamd-benchmark-prediction-v1.schema.json").validate(row)


def test_t2a_and_t2b_are_not_interchangeable() -> None:
    row = copy.deepcopy(_load("excluded-demo-instances.json")[1])
    row["subtrack_id"] = "T2b"
    with pytest.raises(ValidationError):
        _validator("aamd-benchmark-instance-v1.schema.json").validate(row)


def test_t4_has_exactly_four_abstract_prediction_fields() -> None:
    row = copy.deepcopy(_load("excluded-demo-predictions.json")[4])
    assert set(row["prediction"]) == {
        "defense_invariant",
        "benign_exception",
        "predicted_readaptation",
        "evaluation_probe",
    }
    row["prediction"]["explanation"] = ["not_allowed"]
    with pytest.raises(ValidationError):
        _validator("aamd-benchmark-prediction-v1.schema.json").validate(row)


def test_t5_rejects_inline_artifact_content() -> None:
    row = copy.deepcopy(_load("excluded-demo-predictions.json")[5])
    row["prediction"]["frozen_artifact_manifest"]["inline_prompt"] = "not_permitted"
    with pytest.raises(ValidationError):
        _validator("aamd-benchmark-prediction-v1.schema.json").validate(row)
