"""Read-only sidecar audit for multimodal ARMOR Stage-0 judge evidence.

The canonical Stage-0 result schema proves that every successful target
response was judged, but its current compact judge record does not prove which
ordered images were in scope for that judgment.  This module does not rewrite
or reinterpret those result artifacts.  It emits a separate, deterministic
hash-only report and censors efficacy claims whenever a multimodal run lacks
explicit ordered-image provenance on any per-call judge record.

The expected evidence location is::

    target_calls[i].judge.input_provenance.ordered_image_content_sha256

The value must be a list of lowercase SHA-256 digests.  An empty list is valid
and important: it explicitly attests that a particular call was text-only.
Because the field is nested under one target call, duplicate hashes and list
order are preserved.  No prompt, response, image bytes, or base64 data are
copied into the audit report.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .armor_stage0 import (
    CENSORED_TERMINATIONS,
    TERMINATION_REASONS,
    Stage0ValidationError,
    canonical_sha256,
    load_prepared,
    validate_result,
)

AUDIT_SCHEMA_VERSION = 1
AUDIT_PROTOCOL = "armor-stage0-multimodal-judge-provenance-audit-v1"
ORDERED_IMAGE_PROVENANCE_FIELD = "ordered_image_content_sha256"

AUDIT_POLICY: dict[str, Any] = {
    "name": AUDIT_PROTOCOL,
    "multimodal_detection": (
        "frozen_contract_has_assets_or_result_declares_nonempty_ordered_images"
    ),
    "required_evidence_path": (
        "target_calls[].judge.input_provenance.ordered_image_content_sha256"
    ),
    "coverage": "every_successful_target_response_in_a_multimodal_run",
    "ordering": "list_order_and_duplicates_are_semantically_significant",
    "missing_evidence_effect": {
        "effective_censored": True,
        "strict_success": None,
    },
    "declared_runtime_status": "preserved_for_diagnostics_only",
    "raw_payloads_in_report": False,
}
AUDIT_POLICY_SHA256 = canonical_sha256(AUDIT_POLICY)


class MultimodalAuditError(RuntimeError):
    """Raised when the sidecar audit itself cannot be completed safely."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _safe_declared_status(result: Mapping[str, Any], *, valid_result: bool) -> dict[str, Any]:
    """Return only bounded diagnostic fields from the declared runtime result."""

    termination_raw = result.get("termination_reason")
    termination = termination_raw if termination_raw in TERMINATION_REASONS else None
    censored_raw = result.get("censored")
    declared_censored = censored_raw if isinstance(censored_raw, bool) else None
    call_count_raw = result.get("target_call_count")
    call_count = (
        call_count_raw
        if isinstance(call_count_raw, int)
        and not isinstance(call_count_raw, bool)
        and call_count_raw >= 0
        else None
    )

    declared_strict: bool | None = None
    if valid_result:
        if termination == "strict_success":
            declared_strict = True
        elif termination == "budget_exhausted":
            declared_strict = False
    return {
        "termination_reason": termination,
        "censored": declared_censored,
        "strict_success": declared_strict,
        "target_call_count": call_count,
    }


def _ordered_image_evidence(call: Mapping[str, Any]) -> tuple[str, list[str] | None]:
    """Extract one judge-bound ordered hash sequence without accepting raw data."""

    if call.get("target_status") != "ok":
        return "not_applicable", None
    judge = call.get("judge")
    if not isinstance(judge, Mapping):
        return "missing", None
    provenance = judge.get("input_provenance")
    if not isinstance(provenance, Mapping):
        return "missing", None
    hashes = provenance.get(ORDERED_IMAGE_PROVENANCE_FIELD)
    if not isinstance(hashes, list):
        return "missing", None
    if not all(_is_sha256(value) for value in hashes):
        return "invalid", None
    return "complete", list(hashes)


def _declares_nonempty_ordered_images(result: Mapping[str, Any]) -> bool:
    calls = result.get("target_calls")
    if not isinstance(calls, list):
        return False
    for call in calls:
        if not isinstance(call, Mapping):
            continue
        judge = call.get("judge")
        provenance = judge.get("input_provenance") if isinstance(judge, Mapping) else None
        hashes = (
            provenance.get(ORDERED_IMAGE_PROVENANCE_FIELD)
            if isinstance(provenance, Mapping)
            else None
        )
        if isinstance(hashes, list) and hashes:
            return True
    return False


def _call_audits(
    result: Mapping[str, Any],
    *,
    multimodal: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    calls = result.get("target_calls")
    if not isinstance(calls, list):
        return [], [{"call_index": None, "code": "target_calls_not_a_list"}]

    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for position, call_raw in enumerate(calls, start=1):
        if not isinstance(call_raw, Mapping):
            rows.append(
                {
                    "call_index": position,
                    "target_status": None,
                    "judge_status": None,
                    "action_sha256": None,
                    "response_sha256": None,
                    "ordered_image_provenance_status": "invalid",
                    "ordered_image_count": None,
                    "ordered_image_sequence_sha256": None,
                    "ordered_image_content_sha256": None,
                }
            )
            issues.append({"call_index": position, "code": "target_call_not_a_mapping"})
            continue

        call_index_raw = call_raw.get("call_index")
        call_index = (
            call_index_raw
            if isinstance(call_index_raw, int) and not isinstance(call_index_raw, bool)
            else position
        )
        target_status = call_raw.get("target_status")
        target_status = target_status if target_status in {"ok", "error"} else None
        judge = call_raw.get("judge")
        judge_status_raw = judge.get("status") if isinstance(judge, Mapping) else None
        judge_status = (
            judge_status_raw
            if judge_status_raw in {"ok", "error", "incomplete"}
            else None
        )
        evidence_status, image_hashes = _ordered_image_evidence(call_raw)
        if not multimodal and evidence_status != "not_applicable":
            evidence_status = "not_required"

        if multimodal and target_status == "ok" and evidence_status != "complete":
            code = (
                "invalid_ordered_image_hash_provenance"
                if evidence_status == "invalid"
                else "missing_ordered_image_hash_provenance"
            )
            issues.append({"call_index": call_index, "code": code})

        rows.append(
            {
                "call_index": call_index,
                "target_status": target_status,
                "judge_status": judge_status,
                "action_sha256": (
                    call_raw.get("action_sha256")
                    if _is_sha256(call_raw.get("action_sha256"))
                    else None
                ),
                "response_sha256": (
                    call_raw.get("response_sha256")
                    if _is_sha256(call_raw.get("response_sha256"))
                    else None
                ),
                "ordered_image_provenance_status": evidence_status,
                "ordered_image_count": len(image_hashes) if image_hashes is not None else None,
                "ordered_image_sequence_sha256": (
                    canonical_sha256(image_hashes) if image_hashes is not None else None
                ),
                "ordered_image_content_sha256": image_hashes,
            }
        )
    return rows, issues


def _audit_result(
    raw: Mapping[str, Any],
    *,
    contract: Mapping[str, Any],
    result_file_sha256: str,
) -> dict[str, Any]:
    try:
        validate_result(raw, contract)
    except (Stage0ValidationError, TypeError, ValueError, KeyError):
        result_validation_status = "invalid"
        valid_result = False
    else:
        result_validation_status = "valid"
        valid_result = True

    assets = contract.get("asset_hashes")
    multimodal = bool(assets) or _declares_nonempty_ordered_images(raw)
    calls, provenance_issues = _call_audits(raw, multimodal=multimodal)
    declared = _safe_declared_status(raw, valid_result=valid_result)

    reasons: list[str] = []
    if not valid_result:
        reasons.append("invalid_stage0_result")
    if declared["censored"] is True or declared["termination_reason"] in CENSORED_TERMINATIONS:
        reasons.append("declared_runtime_censored")
    if multimodal and provenance_issues:
        reasons.append("judge_ordered_image_provenance_incomplete")
    reasons = list(dict.fromkeys(reasons))
    effective_censored = bool(reasons)
    effective_strict = None if effective_censored else declared["strict_success"]

    return {
        "run_id": contract["run_id"],
        "pair_id": contract["pair_id"],
        "arm": contract["arm"],
        "arm_position": contract["arm_position"],
        "contract_sha256": canonical_sha256(contract),
        "result_file_sha256": result_file_sha256,
        "asset_bundle_sha256": contract["asset_bundle_sha256"],
        "multimodal": multimodal,
        "result_validation_status": result_validation_status,
        "declared_runtime_status": declared,
        "judge_ordered_image_provenance": {
            "required": multimodal,
            "complete": multimodal and not provenance_issues,
            "issues": provenance_issues,
            "calls": calls,
        },
        "efficacy_claim": {
            "effective_censored": effective_censored,
            "strict_success": effective_strict,
            "reasons": reasons,
        },
    }


def audit_prepared_multimodal_provenance(prepared_root: str | Path) -> dict[str, Any]:
    """Scan a prepared directory without modifying any Stage-0 artifact."""

    root = Path(prepared_root).expanduser().resolve()
    plan = load_prepared(root)
    rows: list[dict[str, Any]] = []
    missing_run_ids: list[str] = []
    invalid_json_run_ids: list[str] = []

    for contract in plan.runs:
        result_path = root / str(contract["result_path"])
        if not result_path.is_file():
            missing_run_ids.append(str(contract["run_id"]))
            continue
        result_bytes = result_path.read_bytes()
        result_file_sha256 = _sha256_bytes(result_bytes)
        try:
            raw = json.loads(result_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            invalid_json_run_ids.append(str(contract["run_id"]))
            rows.append(
                {
                    "run_id": contract["run_id"],
                    "pair_id": contract["pair_id"],
                    "arm": contract["arm"],
                    "arm_position": contract["arm_position"],
                    "contract_sha256": canonical_sha256(contract),
                    "result_file_sha256": result_file_sha256,
                    "asset_bundle_sha256": contract["asset_bundle_sha256"],
                    "multimodal": bool(contract.get("asset_hashes")),
                    "result_validation_status": "invalid_json",
                    "declared_runtime_status": {
                        "termination_reason": None,
                        "censored": None,
                        "strict_success": None,
                        "target_call_count": None,
                    },
                    "judge_ordered_image_provenance": {
                        "required": bool(contract.get("asset_hashes")),
                        "complete": False,
                        "issues": [{"call_index": None, "code": "invalid_result_json"}],
                        "calls": [],
                    },
                    "efficacy_claim": {
                        "effective_censored": True,
                        "strict_success": None,
                        "reasons": ["invalid_stage0_result"],
                    },
                }
            )
            continue
        if not isinstance(raw, Mapping):
            raw = {}
        rows.append(
            _audit_result(
                raw,
                contract=contract,
                result_file_sha256=result_file_sha256,
            )
        )

    multimodal_rows = [row for row in rows if row["multimodal"]]
    effective_censored_rows = [
        row for row in rows if row["efficacy_claim"]["effective_censored"]
    ]
    provenance_incomplete_rows = [
        row
        for row in multimodal_rows
        if not row["judge_ordered_image_provenance"]["complete"]
    ]
    invalid_result_rows = [
        row for row in rows if row["result_validation_status"] != "valid"
    ]
    payload: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "protocol": AUDIT_PROTOCOL,
        "audit_policy_sha256": AUDIT_POLICY_SHA256,
        "prepared_manifest_file_sha256": _sha256_file(root / "stage0_manifest.json"),
        "run_plan_file_sha256": _sha256_file(root / "run_plan.jsonl"),
        "experiment_id": plan.manifest["experiment_id"],
        "summary": {
            "expected_run_count": len(plan.runs),
            "observed_result_count": len(rows),
            "missing_result_count": len(missing_run_ids),
            "invalid_result_count": len(invalid_result_rows),
            "multimodal_result_count": len(multimodal_rows),
            "provenance_incomplete_count": len(provenance_incomplete_rows),
            "effective_censored_count": len(effective_censored_rows),
            "efficacy_ready_count": len(rows) - len(effective_censored_rows),
            "efficacy_gate_pass": (
                not missing_run_ids
                and not invalid_json_run_ids
                and not invalid_result_rows
                and not effective_censored_rows
            ),
        },
        "missing_result_run_ids": missing_run_ids,
        "runs": rows,
    }
    return {**payload, "report_payload_sha256": canonical_sha256(payload)}


def write_multimodal_audit_report(
    output_path: str | Path,
    report: Mapping[str, Any],
    *,
    prepared_root: str | Path,
) -> Path:
    """Write a sidecar report atomically, never over a planned result file."""

    root = Path(prepared_root).expanduser().resolve()
    plan = load_prepared(root)
    destination = Path(output_path).expanduser().resolve()
    result_paths = {
        (root / str(contract["result_path"])).resolve() for contract in plan.runs
    }
    if destination in result_paths:
        raise MultimodalAuditError("refusing to overwrite a Stage-0 result artifact")
    if destination.exists() and destination.is_dir():
        raise MultimodalAuditError("audit output path is a directory")

    destination.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(dict(report), indent=2, ensure_ascii=False) + "\n"
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination
