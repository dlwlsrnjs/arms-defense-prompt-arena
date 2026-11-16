from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping

import pytest

from scripts.generate_aamd_taxonomy_proposals import (
    EXACT_MODEL_ID,
    CompletionResult,
    ContractError,
    GenerationError,
    _NoRedirectHandler,
    _urllib_transport,
    build_taxonomy_contract,
    call_chat_completion,
    canonical_json_bytes,
    canonical_sha256,
    generate_bundle,
    parse_openai_completion,
    reject_forbidden_fields,
    resolve_runtime_output_path,
    strict_json_loads,
    validate_local_endpoint,
    validate_proposal_body,
    validate_source_bundle,
)


RESEARCH_ROOT = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = RESEARCH_ROOT / "configs/aamd_rcat7_taxonomy_v1_1.json"
PROMPT_PATH = RESEARCH_ROOT / "prompts/aamd_llm_first_labeler_32b_v3.txt"
CONFIG_PATH = RESEARCH_ROOT / "configs/aamd_llm_first_labeler_32b_v3.json"


def _artifacts() -> tuple[dict[str, Any], str, dict[str, Any]]:
    taxonomy = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return taxonomy, prompt, config


def _task(*, benchmark: str = "T3") -> dict[str, Any]:
    taxonomy = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
    taxonomy_hash = canonical_sha256(taxonomy)
    locked_axes = {
        "memory_source_scope": {
            "code": "RCAT7.MEMORY_SOURCE.PRIVATE_CROSS_EPISODE_SAME_TARGET",
            "evidence_handles": ["ev-link"],
            "derivation_rule": "memory-source-receipt-v1",
            "artifact_hash": "3" * 64,
        },
        "memory_operation": {
            "code": "RCAT7.MEMORY_OP.ABSTRACT_ITEM_RETRIEVAL",
            "evidence_handles": ["ev-link"],
            "derivation_rule": "memory-operation-receipt-v1",
            "artifact_hash": "4" * 64,
        },
        "evidence_provenance": {
            "code": "RCAT7.PROVENANCE.DIRECT_RESPONSE_TO_SUCCESSOR_RECEIPT",
            "evidence_handles": ["ev-link"],
            "derivation_rule": "response-input-receipt-v1",
            "artifact_hash": "5" * 64,
        },
        "dialogue_horizon": {
            "code": "RCAT7.HORIZON.CROSS_EPISODE_WITHIN_RUN",
            "evidence_handles": ["ev-link"],
            "derivation_rule": "minimal-evidence-subgraph-v1",
            "artifact_hash": "6" * 64,
        },
    }
    return {
        "task_id": "task-generator-001",
        "benchmark": benchmark,
        "record_handle": "record-generator-001",
        "record_hash": "2" * 64,
        "split": "blinded",
        "claim_bearing": False,
        "title": "Payload-free response-conditioned transition",
        "question": "Which frozen taxonomy codes are supported?",
        "instructions": "Use only abstract evidence and preserve benign alternatives.",
        "evidence": [
            {
                "handle": "ev-response",
                "label": "Response signal",
                "value": "A bounded response identifies a permitted adjacent scope.",
            },
            {
                "handle": "ev-successor",
                "label": "Successor operation",
                "value": "The successor changes representation while retaining the abstract objective.",
            },
            {
                "handle": "ev-link",
                "label": "Linkage evidence",
                "value": "Independent review supports semantic dependence without an exact runtime receipt.",
            },
        ],
        "taxonomy_id": "aamd-rcat-7-v1.1",
        "taxonomy_version": "1.1.0",
        "taxonomy_hash": taxonomy_hash,
        "locked_axes": locked_axes,
        "locked_axes_hash": canonical_sha256(locked_axes),
    }


def _source_bundle(*, benchmark: str = "T3") -> dict[str, Any]:
    return {
        "schema_version": 2,
        "bundle_id": "proposal-free-source-v3",
        "mode": "pilot_import",
        "claim_bearing": False,
        "protocol_version": "aamd-llm-first-taxonomy-review-v3",
        "codebook_version": "aamd-rcat-7-v1.1",
        "visibility_mask_hash": "0" * 64,
        "queue_hash": "1" * 64,
        "tasks": [_task(benchmark=benchmark)],
    }


def _body(*, benchmark: str = "T3") -> dict[str, Any]:
    body: dict[str, Any] = {
        "mapping_status": "mapped",
        "reviewed_axes": [
            {
                "axis": "adaptation_mechanism",
                "code": "RCAT7.MECHANISM.GOAL_PRESERVING_REFRAMING",
                "confidence": 82,
                "evidence_handles": ["ev-response", "ev-successor"],
                "rationale": "Representation changes after feedback while the abstract objective remains stable.",
            },
            {
                "axis": "consumed_response_signal",
                "code": "RCAT7.SIGNAL.ALLOWED_SCOPE_DISCLOSURE",
                "confidence": 85,
                "evidence_handles": ["ev-response"],
                "rationale": "The response identifies a permitted adjacent scope.",
            },
            {
                "axis": "search_action",
                "code": "RCAT7.SEARCH.GLOBAL_OPERATION_SWITCH",
                "confidence": 70,
                "evidence_handles": ["ev-response", "ev-successor"],
                "rationale": "The successor uses a materially different representational operation.",
            },
            {
                "axis": "semantic_linkage",
                "code": "RCAT7.LINKAGE.IMPLICIT_OPERATION_DEPENDENCE",
                "confidence": 90,
                "evidence_handles": ["ev-link"],
                "rationale": "Blinded evidence supports response-dependent operation change.",
            },
        ],
        "locked_axes_hash": _task(benchmark=benchmark)["locked_axes_hash"],
        "benign_confound": {
            "code": "RCAT7.CONFOUND.ACCESSIBILITY_OR_FORMAT_CONVERSION",
            "plausibility": "RCAT7.CONFOUND_PLAUSIBILITY.POSSIBLE",
            "evidence_handles": ["ev-successor"],
            "rationale": "The same change can occur during legitimate format conversion.",
        },
        "rationale": "The evidence supports a local response-conditioned representation change, not malicious intent.",
    }
    if benchmark == "T4":
        body["affordance"] = {
            "defense_invariant": "Reassess accumulated capability across representation changes.",
            "benign_exception": "Preserve legitimate accessibility and format conversion.",
            "predicted_readaptation": "The requester may switch to component composition.",
            "evaluation_probe": "Compare matched benign and adversarial format changes.",
        }
    return body


def _completion(body: Mapping[str, Any]) -> CompletionResult:
    content = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    response = {
        "id": "chatcmpl-test",
        "model": EXACT_MODEL_ID,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
    }
    raw = canonical_json_bytes(response)
    parsed_content, parsed_response = parse_openai_completion(raw)
    assert parsed_content == content
    return CompletionResult(
        content=parsed_content,
        raw_response=raw,
        response_object=parsed_response,
        attempts=(
            {
                "attempt": 1,
                "kind": "generation",
                "request_sha256": "9" * 64,
                "http_status": 200,
                "response_wire_sha256": canonical_sha256(response),
                "outcome": "response_validated",
            },
        ),
    )


def test_frozen_contract_and_strict_parser_reject_drift() -> None:
    taxonomy, prompt, config = _artifacts()
    contract = build_taxonomy_contract(taxonomy, config, prompt.encode("utf-8"))
    assert len(contract.required_axes) == 8
    assert len(contract.human_reviewed_axes) == 4
    assert len(contract.runtime_locked_axes) == 4
    assert contract.taxonomy_hash == config["taxonomy"]["sha256"]
    assert "RCAT7.MECHANISM.BOUNDARY_LOCALIZATION" in contract.codes_by_axis[
        "adaptation_mechanism"
    ]

    with pytest.raises(ContractError, match="duplicate JSON key"):
        strict_json_loads('{"mapping_status":"mapped","mapping_status":"none"}', name="test")
    with pytest.raises(ContractError, match="strict JSON"):
        strict_json_loads("```json\n{}\n```", name="test")

    drifted = json.loads(json.dumps(config))
    drifted["model"]["model_id"] = "Qwen/Qwen2.5-VL-7B-Instruct"
    with pytest.raises(ContractError, match="exact 32B"):
        build_taxonomy_contract(taxonomy, drifted, prompt.encode("utf-8"))


def test_source_bundle_rejects_forbidden_raw_fields_and_existing_proposals() -> None:
    taxonomy, prompt, config = _artifacts()
    contract = build_taxonomy_contract(taxonomy, config, prompt.encode("utf-8"))
    unsafe = _source_bundle()
    unsafe["tasks"][0]["raw_payload"] = "must never reach the labeler"
    with pytest.raises(ContractError, match="forbidden payload field"):
        validate_source_bundle(unsafe, contract, output_bundle_id="generated-v3")

    already_labeled = _source_bundle()
    already_labeled["tasks"][0]["llm_proposal"] = {}
    with pytest.raises(ContractError, match="unknown fields"):
        validate_source_bundle(
            already_labeled, contract, output_bundle_id="generated-v3"
        )
    with pytest.raises(ContractError, match="forbidden payload field"):
        reject_forbidden_fields({"nested": {"attack_method_name": "hidden"}})
    with pytest.raises(ContractError, match="forbidden payload field"):
        reject_forbidden_fields({"nested": {"RawPayload": "hidden"}})
    with pytest.raises(ContractError, match="forbidden payload field"):
        reject_forbidden_fields({"nested": {"attackMethodName": "hidden"}})
    with pytest.raises(ContractError, match="differ from the source"):
        validate_source_bundle(
            _source_bundle(), contract, output_bundle_id="proposal-free-source-v3"
        )


def test_proposal_validation_enforces_axis_order_codes_evidence_and_t4() -> None:
    taxonomy, prompt, config = _artifacts()
    contract = build_taxonomy_contract(taxonomy, config, prompt.encode("utf-8"))
    task = _task()
    validated = validate_proposal_body(_body(), task, contract)
    assert [label["axis"] for label in validated["reviewed_axes"]] == list(
        contract.human_reviewed_axes
    )

    wrong_order = _body()
    wrong_order["reviewed_axes"][0], wrong_order["reviewed_axes"][1] = (
        wrong_order["reviewed_axes"][1],
        wrong_order["reviewed_axes"][0],
    )
    with pytest.raises(ContractError, match="frozen human-axis order"):
        validate_proposal_body(wrong_order, task, contract)

    no_evidence = _body()
    no_evidence["reviewed_axes"][0]["evidence_handles"] = []
    with pytest.raises(ContractError, match="requires direct evidence"):
        validate_proposal_body(no_evidence, task, contract)

    wrong_confound = _body()
    wrong_confound["benign_confound"]["code"] = "RCAT7.CONFOUND.SCOPE_CLARIFICATION"
    with pytest.raises(ContractError, match="selected mechanism"):
        validate_proposal_body(wrong_confound, task, contract)

    changed_lock = _body()
    changed_lock["locked_axes_hash"] = "0" * 64
    with pytest.raises(ContractError, match="frozen task value"):
        validate_proposal_body(changed_lock, task, contract)

    invalid_locked_source = _source_bundle()
    invalid_locked_source["tasks"][0]["locked_axes"]["memory_operation"]["code"] = "none"
    invalid_locked_source["tasks"][0]["locked_axes_hash"] = canonical_sha256(
        invalid_locked_source["tasks"][0]["locked_axes"]
    )
    with pytest.raises(ContractError, match="memory source and operation"):
        validate_source_bundle(invalid_locked_source, contract, output_bundle_id="invalid-lock-v3")

    with pytest.raises(ContractError, match="missing fields"):
        validate_proposal_body(_body(), _task(benchmark="T4"), contract)


def test_generate_bundle_attaches_frozen_provenance_and_hash_manifest() -> None:
    taxonomy, prompt, config = _artifacts()
    source = _source_bundle()
    requests: list[Mapping[str, Any]] = []

    def fake_caller(request: Mapping[str, Any], task_id: str) -> CompletionResult:
        assert task_id == "task-generator-001"
        requests.append(request)
        return _completion(_body())

    output, manifest = generate_bundle(
        source,
        taxonomy,
        prompt,
        config,
        output_bundle_id="generated-taxonomy-v3",
        generator_code_revision="test-generator-revision-v1",
        completion_caller=fake_caller,
        generated_at="2026-11-16T00:00:00.000Z",
    )

    assert "llm_proposal" not in source["tasks"][0]
    proposal = output["tasks"][0]["llm_proposal"]
    assert proposal["proposal_id"].startswith("proposal-")
    assert proposal["version"] == "offline-32b-rcat7-v1.1"
    assert proposal["provenance"]["model_id"] == EXACT_MODEL_ID
    assert proposal["provenance"]["taxonomy_hash"] == config["taxonomy"]["sha256"]
    assert proposal["provenance"]["source_bundle_hash"] == manifest["inputs"][
        "source_bundle_canonical_sha256"
    ]
    assert manifest["contract"]["retry_budget"] == 2
    assert manifest["contract"]["repair_budget"] == 0
    assert manifest["contract"]["model_identity_assurance"] == (
        "request_and_response_name_only"
    )
    assert manifest["contract"]["weights_snapshot_attested"] is False
    assert manifest["claim_ready"] is False
    assert manifest["tasks"][0]["repair_count"] == 0
    assert manifest["tasks"][0]["response_wire_sha256"]
    assert manifest["tasks"][0]["proposal_canonical_sha256"] == canonical_sha256(
        proposal
    )

    request = requests[0]
    assert request["model"] == EXACT_MODEL_ID
    assert request["temperature"] == 0
    assert request["seed"] == 20261116
    assert request["stream"] is False
    assert "{{TASK_JSON}}" not in request["messages"][0]["content"]
    assert "{{TAXONOMY_JSON}}" not in request["messages"][0]["content"]

    with pytest.raises(ContractError, match="canonical UTC milliseconds"):
        generate_bundle(
            source,
            taxonomy,
            prompt,
            config,
            output_bundle_id="generated-taxonomy-v3-bad-time",
            generator_code_revision="test-generator-revision-v1",
            completion_caller=fake_caller,
            generated_at="2026-11-16T00:00:00Z",
        )
    with pytest.raises(ContractError, match="cannot be in the future"):
        generate_bundle(
            source,
            taxonomy,
            prompt,
            config,
            output_bundle_id="generated-taxonomy-v3-future-time",
            generator_code_revision="test-generator-revision-v1",
            completion_caller=fake_caller,
            generated_at="2099-01-01T00:00:00.000Z",
        )


def test_openai_client_retries_same_request_without_semantic_repair() -> None:
    calls: list[bytes] = []
    response = _completion(_body()).raw_response

    def transport(
        url: str,
        request_bytes: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes]:
        assert url == "http://127.0.0.1:8000/v1/chat/completions"
        assert headers["Content-Type"] == "application/json"
        assert timeout == 10
        calls.append(request_bytes)
        if len(calls) == 1:
            return 503, b'{"error":"temporarily unavailable"}'
        return 200, response

    request = {
        "model": EXACT_MODEL_ID,
        "messages": [{"role": "user", "content": "payload-free test"}],
        "temperature": 0,
        "seed": 20261116,
    }
    result = call_chat_completion(
        request,
        endpoint="http://127.0.0.1:8000/v1",
        timeout_seconds=10,
        transport=transport,
        sleep=lambda _: None,
    )
    assert len(calls) == 2
    assert calls[0] == calls[1] == canonical_json_bytes(request)
    assert [attempt["outcome"] for attempt in result.attempts] == [
        "retryable_http_error",
        "response_validated",
    ]


def test_generation_failure_retains_attempt_hashes_without_partial_bundle() -> None:
    taxonomy, prompt, config = _artifacts()
    invalid_body = _body()
    invalid_body["reviewed_axes"][0]["code"] = "RCAT7.MECHANISM.NOT_REAL"

    def fake_caller(_: Mapping[str, Any], __: str) -> CompletionResult:
        return _completion(invalid_body)

    with pytest.raises(GenerationError) as caught:
        generate_bundle(
            _source_bundle(),
            taxonomy,
            prompt,
            config,
            output_bundle_id="failed-generated-taxonomy-v3",
            generator_code_revision="test-generator-revision-v1",
            completion_caller=fake_caller,
            generated_at="2026-11-16T00:00:00.000Z",
        )
    failure = caught.value.failure_manifest
    assert failure["status"] == "failed"
    assert failure["terminal_failure"]["output_bundle_written"] is False
    assert failure["tasks"][0]["terminal_stage"] == (
        "proposal_parse_or_validation"
    )
    assert failure["tasks"][0]["response_wire_sha256"]
    assert failure["tasks"][0]["repair_count"] == 0


def test_default_transport_disables_proxies_and_rejects_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_handlers: list[Any] = []

    class RedirectingOpener:
        def open(self, request: urllib.request.Request, timeout: float) -> Any:
            del timeout
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "redirect forbidden",
                {"Location": "https://example.com/escape"},
                io.BytesIO(b'{"error":"redirect forbidden"}'),
            )

    def fake_build_opener(*handlers: Any) -> RedirectingOpener:
        captured_handlers.extend(handlers)
        return RedirectingOpener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    status, body = _urllib_transport(
        "http://127.0.0.1:8000/v1/chat/completions",
        b"{}",
        {"Authorization": "Bearer local-only"},
        1,
    )
    assert status == 302
    assert body == b'{"error":"redirect forbidden"}'
    proxy_handlers = [
        item for item in captured_handlers if isinstance(item, urllib.request.ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(isinstance(item, _NoRedirectHandler) for item in captured_handlers)


def test_endpoint_and_output_paths_are_fail_closed() -> None:
    assert (
        validate_local_endpoint("http://localhost:8000/v1")
        == "http://localhost:8000/v1/chat/completions"
    )
    with pytest.raises(ContractError, match="loopback"):
        validate_local_endpoint("https://api.example.com/v1")
    with pytest.raises(ContractError, match="credentials"):
        validate_local_endpoint("http://user:secret@localhost:8000/v1")

    allowed = resolve_runtime_output_path(
        "/data1/users/ljk98/Amrs-runtime/aamd-tests/output.json", name="output"
    )
    assert str(allowed).startswith("/data1/users/ljk98/Amrs-runtime/")
    with pytest.raises(ContractError, match="must resolve below"):
        resolve_runtime_output_path("/tmp/output.json", name="output")
    with pytest.raises(ContractError, match="must resolve below"):
        resolve_runtime_output_path(
            "/data1/users/ljk98/Amrs-runtime-escape/output.json", name="output"
        )
