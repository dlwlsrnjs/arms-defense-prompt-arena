from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/import_aamd_review_bundles.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("aamd_import_client_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


client_module = _load()


def _validated_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    runtime = tmp_path / "runtime"
    bundle_dir = runtime / "run/generated"
    bundle_dir.mkdir(parents=True)
    monkeypatch.setattr(client_module, "RUNTIME_ROOT", runtime)
    source_dir = runtime / "run/source"
    source_dir.mkdir()
    source_manifest = {
        "schema_version": 1,
        "status": "pilot_only",
        "claim_bearing": False,
    }
    source_manifest_raw = (
        json.dumps(source_manifest, sort_keys=True, indent=2) + "\n"
    ).encode()
    (source_dir / "source-manifest.json").write_bytes(source_manifest_raw)

    service_dir = runtime / "run/service"
    service_dir.mkdir()
    runtime_provenance = {
        "model_id": client_module.EXPECTED_MODEL_ID,
        "model_revision": client_module.EXPECTED_MODEL_REVISION,
        "model_tree_attestation": "hf_revision_object_ids_plus_local_sizes",
    }
    service_identity = {
        "run_id": "test-run",
        "pid": 2201,
        "process_start_ticks": 10000,
        "process_group_id": 2201,
        "session_id": 2201,
        "gpu_index": 6,
        "gpu_uuid": "GPU-test",
        "cuda_visible_devices": "6",
        "port": 18066,
        "model_id": client_module.EXPECTED_MODEL_ID,
        "hard_deadline_seconds": 3600,
        "runtime_provenance": runtime_provenance,
    }
    identity_raw = (
        json.dumps(service_identity, sort_keys=True, indent=2) + "\n"
    ).encode()
    (service_dir / "identity.json").write_bytes(identity_raw)
    attestation = {
        "schema_version": 1,
        "attestation_type": "aamd-managed-vllm-runtime-v1",
        "run_id": "test-run",
        "manager_script_file_sha256": "a" * 64,
        "service_identity": service_identity,
        "service_identity_file_sha256": hashlib.sha256(identity_raw).hexdigest(),
        "service_identity_canonical_sha256": client_module.canonical_hash(
            service_identity
        ),
        "runtime_provenance": runtime_provenance,
        "runtime_provenance_canonical_sha256": client_module.canonical_hash(
            runtime_provenance
        ),
        "lifecycle": {
            "model_server_lifecycle_managed": True,
            "gpu_lifecycle_managed": True,
            "identity_captured_before_service_release": True,
            "watchdog_identity_captured_before_service_release": True,
            "hard_deadline_watchdog_armed": True,
            "cleanup_verification_state": "pending_at_generation",
        },
        "weights": {
            "provenance_attested": True,
            "snapshot_content_hashed": False,
            "attestation_method": "hf_revision_object_ids_plus_local_sizes",
            "model_revision": client_module.EXPECTED_MODEL_REVISION,
        },
    }
    attestation_raw = (
        json.dumps(attestation, sort_keys=True, indent=2) + "\n"
    ).encode()
    attestation_path = runtime / "run/runtime-attestation.json"
    attestation_path.write_bytes(attestation_raw)
    binding = {
        "schema_version": 1,
        "file_sha256": hashlib.sha256(attestation_raw).hexdigest(),
        "canonical_sha256": client_module.canonical_hash(attestation),
        "attestation": attestation,
    }
    public_task = {
        "benchmark": "T3",
        "record_handle": "record-1",
        "title": "Abstract transition",
        "question": "Which mechanism is supported?",
        "instructions": "Use abstract evidence only.",
        "evidence": [{"handle": "ev-1", "label": "Evidence", "value": "Abstract"}],
        "taxonomy_id": client_module.EXPECTED_CODEBOOK,
        "taxonomy_version": "1.1.0",
        "taxonomy_hash": client_module.EXPECTED_TAXONOMY_HASH,
        "locked_axes": {"dialogue_horizon": {"code": "single_edge"}},
        "locked_axes_hash": "b" * 64,
    }
    source_projection_hash = "c" * 64
    task = {
        "task_id": "task-1",
        **public_task,
        "split": "blinded",
        "claim_bearing": False,
    }
    task["record_hash"] = client_module.canonical_hash(public_task)
    task["llm_proposal"] = {
        "proposal_id": "proposal-1",
        "provenance": {
            "model_id": client_module.EXPECTED_MODEL_ID,
            "model_revision": client_module.EXPECTED_MODEL_REVISION,
            "source_bundle_hash": source_projection_hash,
        },
    }
    queue = [
        {
            "ordinal": 0,
            "task_id": task["task_id"],
            "record_handle": task["record_handle"],
            "record_hash": task["record_hash"],
        }
    ]
    bundle = {
        "schema_version": 2,
        "bundle_id": "review-test-000",
        "mode": "pilot_import",
        "claim_bearing": False,
        "protocol_version": client_module.EXPECTED_PROTOCOL,
        "codebook_version": client_module.EXPECTED_CODEBOOK,
        "visibility_mask_hash": client_module.canonical_hash(
            client_module.EXPECTED_VISIBILITY_MASK
        ),
        "queue_hash": client_module.canonical_hash(queue),
        "tasks": [task],
    }
    payload = (json.dumps(bundle, indent=2) + "\n").encode()
    path = bundle_dir / "review-bundle-000.json"
    path.write_bytes(payload)
    generation_path = bundle_dir / "generation-manifest-000.json"
    generation = {
        "schema_version": 1,
        "status": "complete",
        "claim_ready": False,
        "generator": {
            "code_revision": "sha256:" + "d" * 64,
            "model_server_lifecycle_managed": True,
            "gpu_lifecycle_managed": True,
        },
        "contract": {
            "model_id": client_module.EXPECTED_MODEL_ID,
            "model_revision": client_module.EXPECTED_MODEL_REVISION,
            "weights_provenance_attested": True,
            "weights_snapshot_attested": False,
            "weights_snapshot_content_hashed": False,
        },
        "inputs": {
            "source_bundle_projection_canonical_sha256": source_projection_hash,
        },
        "tasks": [{"task_id": "task-1"}],
        "output": {
            "bundle_id": bundle["bundle_id"],
            "bundle_canonical_sha256": client_module.canonical_hash(bundle),
            "task_count": 1,
        },
        "runtime_attestation": binding,
        "artifacts": {
            "output_bundle": {
                "path": str(path),
                "file_sha256": hashlib.sha256(payload).hexdigest(),
                "canonical_sha256": client_module.canonical_hash(bundle),
            },
            "generation_manifest": {"path": str(generation_path)},
        },
    }
    generation_raw = (json.dumps(generation, indent=2) + "\n").encode()
    generation_path.write_bytes(generation_raw)
    manifest = {
        "schema_version": 2,
        "run_id": "test-run",
        "status": "validated_for_pilot_import",
        "claim_bearing": False,
        "source_manifest_file_sha256": hashlib.sha256(
            source_manifest_raw
        ).hexdigest(),
        "generator_code_revision": "sha256:" + "d" * 64,
        "runtime_attestation_path": str(attestation_path),
        "runtime_attestation": binding,
        "bundle_count": 1,
        "task_count": 1,
        "bundles": [
            {
                "bundle_id": bundle["bundle_id"],
                "task_count": 1,
                "bundle_canonical_sha256": client_module.canonical_hash(bundle),
                "bundle_file_sha256": hashlib.sha256(payload).hexdigest(),
                "manifest_file_sha256": hashlib.sha256(generation_raw).hexdigest(),
                "manifest_canonical_sha256": client_module.canonical_hash(generation),
                "runtime_attestation_file_sha256": binding["file_sha256"],
                "runtime_attestation_canonical_sha256": binding[
                    "canonical_sha256"
                ],
                "source_bundle_projection_canonical_sha256": source_projection_hash,
            }
        ],
    }
    manifest_path = bundle_dir / "review-bundle-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir, manifest_path


def test_validated_manifest_binds_every_bundle_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle_dir, manifest_path = _validated_run(tmp_path, monkeypatch)
    assert len(client_module.load_validated_run(bundle_dir, manifest_path)) == 1
    path = bundle_dir / "review-bundle-000.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(client_module.ImportErrorSafe, match="commitment mismatch"):
        client_module.load_validated_run(bundle_dir, manifest_path)


def test_validated_manifest_rejects_generation_and_identity_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle_dir, manifest_path = _validated_run(tmp_path, monkeypatch)
    generation = bundle_dir / "generation-manifest-000.json"
    generation.write_bytes(generation.read_bytes() + b" ")
    with pytest.raises(client_module.ImportErrorSafe, match="generation manifest"):
        client_module.load_validated_run(bundle_dir, manifest_path)

    bundle_dir, manifest_path = _validated_run(tmp_path / "second", monkeypatch)
    identity = bundle_dir.parent / "service" / "identity.json"
    value = json.loads(identity.read_text(encoding="utf-8"))
    value["port"] += 1
    identity.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(client_module.ImportErrorSafe, match="service identity"):
        client_module.load_validated_run(bundle_dir, manifest_path)


def test_service_import_signature_binds_body_path_time_and_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "s" * 32
    client = client_module.SiteClient(
        client_module.EXPECTED_SITE_ORIGIN, "sites-token", secret
    )
    bundle: dict[str, Any] = {"bundle_id": "review-test-000", "tasks": []}
    payload = json.dumps(bundle).encode()
    bundle_hash = client_module.canonical_hash(bundle)
    captured: dict[str, Any] = {}

    def request(method: str, path: str, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
        captured.update(method=method, path=path, body=body, headers=headers)
        key = headers["Idempotency-Key"]
        return {
            "ok": True,
            "bundle_id": bundle["bundle_id"],
            "bundle_hash": bundle_hash,
            "task_count": 0,
            "status": "active",
            "activation_policy": "validated_import",
            "replayed": False,
            "importer": {
                "principal_type": "service",
                "identity_hash": "a" * 64,
                "principal_id": "service:aamd-offline-bundle-importer:v1",
            },
            "authentication": {
                "signature_version": "aamd-service-import-v1",
                "idempotency_key_hash": hashlib.sha256(
                    ("aamd-service-import-idempotency-v1\n" + key).encode()
                ).hexdigest(),
                "request_hash": bundle_hash,
            },
        }

    monkeypatch.setattr(client_module.time, "time", lambda: 1_763_456_789)
    monkeypatch.setattr(client, "request", request)
    response = client.import_bundle(bundle, payload, bundle_hash)
    assert response["ok"] is True
    key = f"bundle-{bundle_hash[:40]}"
    message = {
        "body_sha256": bundle_hash,
        "idempotency_key": key,
        "method": "POST",
        "path": "/api/service/import",
        "timestamp": "1763456789",
        "version": "aamd-service-import-v1",
    }
    expected = hmac.new(
        secret.encode(), client_module.canonical_bytes(message), hashlib.sha256
    ).hexdigest()
    assert captured == {
        "method": "POST",
        "path": "/api/service/import",
        "body": payload,
        "headers": {
            "Idempotency-Key": key,
            "X-AAMD-Import-Timestamp": "1763456789",
            "X-AAMD-Import-Signature": expected,
        },
    }


def test_client_rejects_unpinned_origin_and_incomplete_success_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(client_module.ImportErrorSafe, match="pinned"):
        client_module.SiteClient(
            "https://private.example.chatgpt.site", "sites-token", "s" * 32
        )
    client = client_module.SiteClient(
        client_module.EXPECTED_SITE_ORIGIN, "sites-token", "s" * 32
    )
    monkeypatch.setattr(client, "request", lambda *_args, **_kwargs: {"ok": True})
    bundle = {"bundle_id": "review-test-000", "tasks": []}
    with pytest.raises(client_module.ImportErrorSafe, match="schema"):
        client.import_bundle(
            bundle, json.dumps(bundle).encode(), client_module.canonical_hash(bundle)
        )


def test_client_source_never_falls_back_to_browser_admin_flow() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"/api/service/import"' in source
    assert '"/api/admin/import"' not in source
    assert '"/api/me"' not in source
