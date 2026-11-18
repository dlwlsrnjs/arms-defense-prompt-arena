#!/usr/bin/env python3
"""Import validated AAMD review bundles through the private Site service API.

The Sites bearer token and the distinct service HMAC key are read with ``getpass``
and are never written, logged, echoed, or included in an exception. Redirects are
disabled so credentials cannot be forwarded to another origin. The endpoint is
idempotent: an exact bundle replay succeeds, while an ID/hash conflict fails.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


RUNTIME_ROOT = Path("/data1/users/ljk98/Amrs-runtime")
MAX_IMPORT_BYTES = 1024 * 1024
EXPECTED_SITE_ORIGIN = "https://aamd-human-annotation-workspace-2026.feyllama7.chatgpt.site"
EXPECTED_MODEL_ID = "Qwen/Qwen2.5-VL-32B-Instruct"
EXPECTED_MODEL_REVISION = "7cfb30d71a1f4f49a57592323337a4a4727301da"
EXPECTED_PROTOCOL = "aamd-llm-first-taxonomy-review-v3"
EXPECTED_CODEBOOK = "aamd-rcat-7-v1.1"
EXPECTED_TAXONOMY_HASH = "2f8512333c90888aa640e8432ec262cdd452adbae3d1e8df5c96c5654a5c816c"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
PUBLIC_RECORD_FIELDS = (
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
EXPECTED_VISIBILITY_MASK = {
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
    "visible": [*PUBLIC_RECORD_FIELDS, "llm_proposal"],
}
FORBIDDEN_KEYS = frozenset(EXPECTED_VISIBILITY_MASK["forbidden"])


class ImportErrorSafe(RuntimeError):
    """An import error whose message contains no credential material."""


@dataclass(frozen=True)
class ValidatedRun:
    bundles: tuple[tuple[Path, Mapping[str, Any], bytes, str], ...]
    manifest_file_sha256: str
    manifest: Mapping[str, Any]
    runtime_attestation: Mapping[str, Any]

    def __iter__(self) -> Iterator[tuple[Path, Mapping[str, Any], bytes, str]]:
        return iter(self.bundles)

    def __len__(self) -> int:
        return len(self.bundles)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ImportErrorSafe(f"refusing HTTP redirect with status {code}")


def runtime_path(value: str | Path, *, name: str) -> Path:
    path = Path(value).expanduser().resolve(strict=False)
    runtime = RUNTIME_ROOT.resolve(strict=False)
    try:
        path.relative_to(runtime)
    except ValueError as exc:
        raise ImportErrorSafe(f"{name} must resolve below {runtime}") from exc
    if path == runtime:
        raise ImportErrorSafe(f"{name} must be below {runtime}")
    return path


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def require_sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ImportErrorSafe(f"{name} must be a lowercase SHA-256")
    return value


def reject_forbidden_keys(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_KEYS:
                raise ImportErrorSafe(f"forbidden field in {path}: {key}")
            reject_forbidden_keys(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_forbidden_keys(child, path=f"{path}[{index}]")


def validate_runtime_attestation(
    bundle_dir: Path, manifest: Mapping[str, Any]
) -> Mapping[str, Any]:
    binding = manifest.get("runtime_attestation")
    if not isinstance(binding, dict) or binding.get("schema_version") != 1:
        raise ImportErrorSafe("review manifest lacks a runtime attestation binding")
    record = binding.get("attestation")
    if not isinstance(record, dict) or (
        record.get("schema_version") != 1
        or record.get("attestation_type") != "aamd-managed-vllm-runtime-v1"
        or record.get("run_id") != manifest.get("run_id")
    ):
        raise ImportErrorSafe("runtime attestation record is invalid")
    canonical = require_sha256(
        binding.get("canonical_sha256"), name="runtime attestation canonical hash"
    )
    file_hash = require_sha256(
        binding.get("file_sha256"), name="runtime attestation file hash"
    )
    if canonical != canonical_hash(record):
        raise ImportErrorSafe("runtime attestation canonical hash mismatch")

    expected_attestation_path = (bundle_dir.parent / "runtime-attestation.json").resolve(
        strict=False
    )
    declared_path = runtime_path(
        str(manifest.get("runtime_attestation_path", "")),
        name="runtime_attestation_path",
    )
    if declared_path != expected_attestation_path:
        raise ImportErrorSafe("runtime attestation path is not the run artifact")
    raw = declared_path.read_bytes()
    persisted = strict_json(raw, name="runtime-attestation.json")
    if (
        persisted != record
        or hashlib.sha256(raw).hexdigest() != file_hash
        or canonical_hash(persisted) != canonical
    ):
        raise ImportErrorSafe("runtime attestation artifact mismatch")

    service = record.get("service_identity")
    provenance = record.get("runtime_provenance")
    lifecycle = record.get("lifecycle")
    weights = record.get("weights")
    if not all(
        isinstance(value, dict)
        for value in (service, provenance, lifecycle, weights)
    ):
        raise ImportErrorSafe("runtime attestation sections are invalid")
    identity_path = (bundle_dir.parent / "service" / "identity.json").resolve(
        strict=False
    )
    identity_raw = identity_path.read_bytes()
    persisted_identity = strict_json(identity_raw, name="service identity")
    if persisted_identity != service or service.get("runtime_provenance") != provenance:
        raise ImportErrorSafe("runtime service identity mismatch")
    if hashlib.sha256(identity_raw).hexdigest() != require_sha256(
        record.get("service_identity_file_sha256"),
        name="service identity file hash",
    ) or canonical_hash(service) != require_sha256(
        record.get("service_identity_canonical_sha256"),
        name="service identity canonical hash",
    ):
        raise ImportErrorSafe("runtime service identity commitment mismatch")
    if canonical_hash(provenance) != require_sha256(
        record.get("runtime_provenance_canonical_sha256"),
        name="runtime provenance canonical hash",
    ):
        raise ImportErrorSafe("runtime provenance commitment mismatch")
    if (
        service.get("run_id") != manifest.get("run_id")
        or service.get("model_id") != EXPECTED_MODEL_ID
        or provenance.get("model_id") != EXPECTED_MODEL_ID
        or provenance.get("model_revision") != EXPECTED_MODEL_REVISION
    ):
        raise ImportErrorSafe("runtime model/run identity mismatch")
    if lifecycle != {
        "model_server_lifecycle_managed": True,
        "gpu_lifecycle_managed": True,
        "identity_captured_before_service_release": True,
        "watchdog_identity_captured_before_service_release": True,
        "hard_deadline_watchdog_armed": True,
        "cleanup_verification_state": "pending_at_generation",
    }:
        raise ImportErrorSafe("runtime lifecycle claim is invalid")
    if (
        weights.get("provenance_attested") is not True
        or weights.get("snapshot_content_hashed") is not False
        or weights.get("model_revision") != EXPECTED_MODEL_REVISION
        or weights.get("attestation_method")
        != provenance.get("model_tree_attestation")
    ):
        raise ImportErrorSafe("runtime weight provenance claim is invalid")
    require_sha256(
        record.get("manager_script_file_sha256"), name="manager script file hash"
    )
    return binding


def validate_review_bundle(bundle: Mapping[str, Any], *, name: str) -> None:
    reject_forbidden_keys(bundle, path=name)
    if (
        bundle.get("schema_version") != 2
        or bundle.get("mode") != "pilot_import"
        or bundle.get("claim_bearing") is not False
        or bundle.get("protocol_version") != EXPECTED_PROTOCOL
        or bundle.get("codebook_version") != EXPECTED_CODEBOOK
        or bundle.get("visibility_mask_hash")
        != canonical_hash(EXPECTED_VISIBILITY_MASK)
    ):
        raise ImportErrorSafe(f"review bundle boundary mismatch: {name}")
    tasks = bundle.get("tasks")
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= 500:
        raise ImportErrorSafe(f"review bundle tasks are invalid: {name}")
    queue: list[dict[str, Any]] = []
    for ordinal, task in enumerate(tasks):
        if not isinstance(task, dict) or task.get("claim_bearing") is not False:
            raise ImportErrorSafe(f"review task boundary mismatch: {name}")
        try:
            public_record = {field: task[field] for field in PUBLIC_RECORD_FIELDS}
        except KeyError as exc:
            raise ImportErrorSafe(f"review task public record is incomplete: {name}") from exc
        if (
            canonical_hash(public_record) != task.get("record_hash")
            or task.get("taxonomy_hash") != EXPECTED_TAXONOMY_HASH
            or not isinstance(task.get("llm_proposal"), dict)
        ):
            raise ImportErrorSafe(f"review task commitment mismatch: {name}")
        queue.append(
            {
                "ordinal": ordinal,
                "task_id": task.get("task_id"),
                "record_handle": task.get("record_handle"),
                "record_hash": task.get("record_hash"),
            }
        )
    if canonical_hash(queue) != bundle.get("queue_hash"):
        raise ImportErrorSafe(f"review bundle queue hash mismatch: {name}")


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise ImportErrorSafe(f"refusing to overwrite receipt: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.link(temporary, path)
    temporary.unlink(missing_ok=True)


def strict_json(payload: bytes, *, name: str) -> Any:
    def pairs(values: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ImportErrorSafe(f"duplicate JSON key in {name}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ImportErrorSafe(f"non-finite JSON number in {name}: {value}")

    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorSafe(f"invalid UTF-8 JSON: {name}") from exc


def load_bundle(path: Path) -> tuple[Mapping[str, Any], bytes, str]:
    payload = path.read_bytes()
    if not payload or len(payload) > MAX_IMPORT_BYTES:
        raise ImportErrorSafe(f"bundle size is outside the Site limit: {path.name}")
    value = strict_json(payload, name=path.name)
    if not isinstance(value, dict) or not isinstance(value.get("bundle_id"), str):
        raise ImportErrorSafe(f"bundle has no valid bundle_id: {path.name}")
    return value, payload, canonical_hash(value)


def load_validated_run(
    bundle_dir: Path, manifest_path: Path
) -> ValidatedRun:
    manifest_raw = manifest_path.read_bytes()
    manifest = strict_json(manifest_raw, name=manifest_path.name)
    if not isinstance(manifest, dict) or (
        manifest.get("schema_version") != 2
        or manifest.get("status") != "validated_for_pilot_import"
        or manifest.get("claim_bearing") is not False
    ):
        raise ImportErrorSafe("review manifest is not a validated pilot import")
    if not isinstance(manifest.get("run_id"), str):
        raise ImportErrorSafe("review manifest has no run identity")
    generator_revision = manifest.get("generator_code_revision")
    if not isinstance(generator_revision, str) or not re.fullmatch(
        r"sha256:[a-f0-9]{64}", generator_revision
    ):
        raise ImportErrorSafe("review manifest generator revision is invalid")
    source_manifest_hash = require_sha256(
        manifest.get("source_manifest_file_sha256"), name="source manifest file hash"
    )
    source_manifest_path = bundle_dir.parent / "source" / "source-manifest.json"
    source_manifest_raw = source_manifest_path.read_bytes()
    source_manifest = strict_json(source_manifest_raw, name="source-manifest.json")
    if (
        hashlib.sha256(source_manifest_raw).hexdigest() != source_manifest_hash
        or not isinstance(source_manifest, dict)
        or source_manifest.get("status") != "pilot_only"
        or source_manifest.get("claim_bearing") is not False
    ):
        raise ImportErrorSafe("source manifest commitment mismatch")
    runtime_binding = validate_runtime_attestation(bundle_dir, manifest)
    entries = manifest.get("bundles")
    if not isinstance(entries, list) or manifest.get("bundle_count") != len(entries):
        raise ImportErrorSafe("review manifest bundle count is invalid")
    paths = sorted(
        path
        for path in bundle_dir.iterdir()
        if path.is_file() and re.fullmatch(r"review-bundle-\d{3}\.json", path.name)
    )
    if len(paths) != len(entries):
        raise ImportErrorSafe("review bundle directory does not match its manifest")
    validated: list[tuple[Path, Mapping[str, Any], bytes, str]] = []
    total_tasks = 0
    for index, (path, entry) in enumerate(zip(paths, entries)):
        if path.name != f"review-bundle-{index:03d}.json" or not isinstance(entry, dict):
            raise ImportErrorSafe("review manifest order is not canonical")
        bundle, payload, bundle_hash = load_bundle(path)
        validate_review_bundle(bundle, name=path.name)
        file_hash = hashlib.sha256(payload).hexdigest()
        if (
            entry.get("bundle_id") != bundle.get("bundle_id")
            or entry.get("bundle_canonical_sha256") != bundle_hash
            or entry.get("bundle_file_sha256") != file_hash
            or entry.get("task_count") != len(bundle.get("tasks", []))
        ):
            raise ImportErrorSafe(f"review bundle commitment mismatch: {path.name}")

        generation_path = bundle_dir / f"generation-manifest-{index:03d}.json"
        generation_raw = generation_path.read_bytes()
        generation = strict_json(generation_raw, name=generation_path.name)
        if not isinstance(generation, dict):
            raise ImportErrorSafe("generation manifest must be an object")
        if hashlib.sha256(generation_raw).hexdigest() != require_sha256(
            entry.get("manifest_file_sha256"),
            name=f"{generation_path.name} file hash",
        ) or canonical_hash(generation) != require_sha256(
            entry.get("manifest_canonical_sha256"),
            name=f"{generation_path.name} canonical hash",
        ):
            raise ImportErrorSafe(
                f"generation manifest commitment mismatch: {generation_path.name}"
            )
        if generation.get("runtime_attestation") != runtime_binding or (
            entry.get("runtime_attestation_file_sha256")
            != runtime_binding.get("file_sha256")
            or entry.get("runtime_attestation_canonical_sha256")
            != runtime_binding.get("canonical_sha256")
        ):
            raise ImportErrorSafe(
                f"generation runtime binding mismatch: {generation_path.name}"
            )
        generator = generation.get("generator")
        contract = generation.get("contract")
        output = generation.get("output")
        inputs = generation.get("inputs")
        artifacts = generation.get("artifacts")
        if not all(
            isinstance(value, dict)
            for value in (generator, contract, output, inputs, artifacts)
        ):
            raise ImportErrorSafe(
                f"generation manifest sections are invalid: {generation_path.name}"
            )
        if (
            generation.get("status") != "complete"
            or generation.get("claim_ready") is not False
            or generator.get("code_revision") != generator_revision
            or generator.get("model_server_lifecycle_managed") is not True
            or generator.get("gpu_lifecycle_managed") is not True
            or contract.get("model_id") != EXPECTED_MODEL_ID
            or contract.get("model_revision") != EXPECTED_MODEL_REVISION
            or contract.get("weights_provenance_attested") is not True
            or contract.get("weights_snapshot_attested") is not False
            or contract.get("weights_snapshot_content_hashed") is not False
        ):
            raise ImportErrorSafe(
                f"generation provenance claim is invalid: {generation_path.name}"
            )
        output_artifact = artifacts.get("output_bundle")
        generation_artifact = artifacts.get("generation_manifest")
        if not isinstance(output_artifact, dict) or not isinstance(
            generation_artifact, dict
        ):
            raise ImportErrorSafe(
                f"generation artifact projection is invalid: {generation_path.name}"
            )
        if (
            Path(str(output_artifact.get("path", ""))).resolve(strict=False)
            != path.resolve(strict=False)
            or Path(str(generation_artifact.get("path", ""))).resolve(strict=False)
            != generation_path.resolve(strict=False)
            or output_artifact.get("file_sha256") != file_hash
            or output_artifact.get("canonical_sha256") != bundle_hash
            or output.get("bundle_id") != bundle.get("bundle_id")
            or output.get("bundle_canonical_sha256") != bundle_hash
            or output.get("task_count") != len(bundle.get("tasks", []))
        ):
            raise ImportErrorSafe(
                f"generation output projection mismatch: {generation_path.name}"
            )
        source_projection_hash = require_sha256(
            inputs.get("source_bundle_projection_canonical_sha256"),
            name=f"{generation_path.name} source projection hash",
        )
        if entry.get("source_bundle_projection_canonical_sha256") != (
            source_projection_hash
        ):
            raise ImportErrorSafe(
                f"generation source projection mismatch: {generation_path.name}"
            )
        manifest_tasks = generation.get("tasks")
        bundle_tasks = bundle.get("tasks", [])
        if not isinstance(manifest_tasks, list) or len(manifest_tasks) != len(
            bundle_tasks
        ):
            raise ImportErrorSafe(
                f"generation task receipts are incomplete: {generation_path.name}"
            )
        receipt_ids = [
            item.get("task_id") if isinstance(item, dict) else None
            for item in manifest_tasks
        ]
        if receipt_ids != [task.get("task_id") for task in bundle_tasks]:
            raise ImportErrorSafe(
                f"generation task order mismatch: {generation_path.name}"
            )
        for task in bundle_tasks:
            proposal = task["llm_proposal"]
            provenance = proposal.get("provenance")
            if not isinstance(provenance, dict) or (
                provenance.get("model_id") != EXPECTED_MODEL_ID
                or provenance.get("model_revision") != EXPECTED_MODEL_REVISION
                or provenance.get("source_bundle_hash") != source_projection_hash
            ):
                raise ImportErrorSafe(
                    f"proposal runtime provenance mismatch: {generation_path.name}"
                )
        total_tasks += len(bundle.get("tasks", []))
        validated.append((path, bundle, payload, bundle_hash))
    if manifest.get("task_count") != total_tasks:
        raise ImportErrorSafe("review manifest task count is invalid")
    return ValidatedRun(
        bundles=tuple(validated),
        manifest_file_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        manifest=manifest,
        runtime_attestation=runtime_binding,
    )


class SiteClient:
    def __init__(self, base_url: str, bearer: str, service_key: str) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ImportErrorSafe("base URL must be the pinned HTTPS origin")
        if parsed.path not in {"", "/"}:
            raise ImportErrorSafe("base URL must not contain a path")
        if not bearer or any(character.isspace() for character in bearer):
            raise ImportErrorSafe("Sites bearer token is missing or malformed")
        if len(service_key) < 32:
            raise ImportErrorSafe("service HMAC key must contain at least 32 characters")
        self.origin = f"https://{parsed.netloc}"
        if self.origin != EXPECTED_SITE_ORIGIN:
            raise ImportErrorSafe("base URL is not the pinned private Site origin")
        self.authorization = "Bearer " + bearer
        self.service_key = service_key.encode("utf-8")
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise ImportErrorSafe("API path must be same-origin absolute")
        headers = {
            "Accept": "application/json",
            "OAI-Sites-Authorization": self.authorization,
            "User-Agent": "aamd-private-import-client/1",
            "Origin": self.origin,
        }
        if extra_headers:
            headers.update(extra_headers)
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        request = urllib.request.Request(
            self.origin + path, data=body, headers=headers, method=method
        )
        try:
            with self.opener.open(request, timeout=120) as response:
                payload = response.read(MAX_IMPORT_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            payload = exc.read(64 * 1024)
            try:
                detail = json.loads(payload.decode("utf-8"))
                safe_detail = detail.get("error", {}).get("code", "http_error")
            except (UnicodeError, json.JSONDecodeError, AttributeError):
                safe_detail = "http_error"
            raise ImportErrorSafe(
                f"Site API returned HTTP {exc.code} ({safe_detail}) for {path}"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise ImportErrorSafe(f"Site API transport failed for {path}") from exc
        if status < 200 or status >= 300 or len(payload) > MAX_IMPORT_BYTES:
            raise ImportErrorSafe(f"invalid Site API response for {path}")
        try:
            value = strict_json(payload, name=f"Site API response for {path}")
        except ImportErrorSafe as exc:
            raise ImportErrorSafe(f"Site API returned invalid JSON for {path}") from exc
        if not isinstance(value, dict):
            raise ImportErrorSafe(f"Site API returned a non-object for {path}")
        return value

    def import_bundle(
        self, bundle: Mapping[str, Any], payload: bytes, bundle_hash: str
    ) -> Mapping[str, Any]:
        path = "/api/service/import"
        timestamp = str(int(time.time()))
        idempotency_key = f"bundle-{bundle_hash[:40]}"
        message = {
            "body_sha256": bundle_hash,
            "idempotency_key": idempotency_key,
            "method": "POST",
            "path": path,
            "timestamp": timestamp,
            "version": "aamd-service-import-v1",
        }
        signature = hmac.new(
            self.service_key, canonical_bytes(message), hashlib.sha256
        ).hexdigest()
        response = self.request(
            "POST",
            path,
            payload,
            {
                "Idempotency-Key": idempotency_key,
                "X-AAMD-Import-Timestamp": timestamp,
                "X-AAMD-Import-Signature": signature,
            },
        )
        expected_keys = {
            "ok",
            "bundle_id",
            "bundle_hash",
            "task_count",
            "status",
            "activation_policy",
            "replayed",
            "importer",
            "authentication",
        }
        if set(response) != expected_keys:
            raise ImportErrorSafe("Site import response schema is invalid")
        importer = response.get("importer")
        authentication = response.get("authentication")
        expected_idempotency_hash = hashlib.sha256(
            ("aamd-service-import-idempotency-v1\n" + idempotency_key).encode(
                "utf-8"
            )
        ).hexdigest()
        if (
            response.get("ok") is not True
            or response.get("bundle_id") != bundle.get("bundle_id")
            or response.get("bundle_hash") != bundle_hash
            or response.get("task_count") != len(bundle.get("tasks", []))
            or response.get("status") != "active"
            or response.get("activation_policy") != "validated_import"
            or not isinstance(response.get("replayed"), bool)
            or not isinstance(importer, dict)
            or set(importer)
            != {"principal_type", "identity_hash", "principal_id"}
            or importer.get("principal_type") != "service"
            or importer.get("principal_id")
            != "service:aamd-offline-bundle-importer:v1"
            or not SHA256_RE.fullmatch(str(importer.get("identity_hash", "")))
            or not isinstance(authentication, dict)
            or set(authentication)
            != {"signature_version", "idempotency_key_hash", "request_hash"}
            or authentication.get("signature_version") != "aamd-service-import-v1"
            or authentication.get("idempotency_key_hash")
            != expected_idempotency_hash
            or authentication.get("request_hash") != bundle_hash
        ):
            raise ImportErrorSafe("Site import response provenance is invalid")
        return response


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--import-manifest", required=True)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args(argv)
    bundle_dir = runtime_path(args.bundle_dir, name="bundle_dir")
    manifest_path = runtime_path(args.import_manifest, name="import_manifest")
    receipt_path = runtime_path(args.receipt, name="receipt")
    if receipt_path.exists():
        raise ImportErrorSafe("receipt path must be unused")
    bundles = load_validated_run(bundle_dir, manifest_path)

    bearer = getpass.getpass("Sites bearer token: ")
    service_key = getpass.getpass("AAMD service import HMAC key: ")
    try:
        client = SiteClient(args.base_url, bearer, service_key)
        imported: list[dict[str, Any]] = []
        replayed: list[dict[str, Any]] = []
        for path, bundle, payload, local_hash in bundles:
            bundle_id = str(bundle["bundle_id"])
            response = client.import_bundle(bundle, payload, local_hash)
            if (
                response.get("bundle_hash") != local_hash
                or response.get("bundle_id") != bundle_id
                or response.get("task_count") != len(bundle.get("tasks", []))
            ):
                raise ImportErrorSafe(f"import hash mismatch for {bundle_id}")
            item = {
                "bundle_id": bundle_id,
                "bundle_hash": local_hash,
                "task_count": response.get("task_count"),
                "status": response.get("status"),
                "activation_policy": response.get("activation_policy"),
                "source_file": path.name,
                "importer_principal_type": response.get("importer", {}).get(
                    "principal_type"
                ),
                "importer_identity_hash": response.get("importer", {}).get(
                    "identity_hash"
                ),
                "request_hash": response.get("authentication", {}).get(
                    "request_hash"
                ),
            }
            (replayed if response.get("replayed") else imported).append(item)
        receipt = {
            "schema_version": 1,
            "site_origin": client.origin,
            "transport": "private_sites_bearer_plus_service_hmac_v1",
            "imported": imported,
            "replayed": replayed,
            "bundle_count": len(bundles),
            "task_count": sum(len(bundle["tasks"]) for _, bundle, _, _ in bundles),
            "import_manifest_file_sha256": bundles.manifest_file_sha256,
            "runtime_attestation_file_sha256": bundles.runtime_attestation[
                "file_sha256"
            ],
            "runtime_attestation_canonical_sha256": bundles.runtime_attestation[
                "canonical_sha256"
            ],
        }
        atomic_json(receipt_path, receipt)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    finally:
        bearer = ""
        service_key = ""


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ImportErrorSafe as exc:
        print(f"import error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
