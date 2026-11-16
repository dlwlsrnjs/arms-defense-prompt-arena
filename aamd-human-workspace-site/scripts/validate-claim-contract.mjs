import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const sourcePath = resolve(projectRoot, process.argv[2] || "worker/index.js");
const source = await readFile(sourcePath, "utf8");
const inlinePageScript = source.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(inlinePageScript, "claim worker must contain the reviewer UI script");
assert.doesNotThrow(() => new Function(inlinePageScript[1]), "reviewer UI script must parse as JavaScript");

function requiresAll(label, values) {
  const missing = values.filter((value) => !source.includes(value));
  assert.deepEqual(missing, [], `${label}: missing ${missing.join(", ")}`);
}

function requiresPatterns(label, patterns) {
  const missing = patterns.filter((pattern) => !pattern.test(source)).map(String);
  assert.deepEqual(missing, [], `${label}: missing ${missing.join(", ")}`);
}

requiresAll("claim API routes", [
  "/api/me",
  "/api/bootstrap",
  "/api/tasks",
  "/api/admin/import",
  "/api/admin/approve",
  "/api/admin/roles",
  "/api/admin/export",
]);
requiresAll("stage handlers", ["handleInitial", "handleReveal", "handleFinal", "handleSecondary", "handleAdjudicate"]);

requiresAll("trusted identity contract", [
  "oai-authenticated-user-id",
  "oai-authenticated-user-email",
]);

requiresAll("runtime bindings", [
  "AAMD_BOOTSTRAP_ADMIN_IDS",
  "AAMD_BOOTSTRAP_ADMIN_EMAILS",
  "AAMD_RECEIPT_HMAC_KEY",
  "AAMD_CLAIM_COLLECTION_ENABLED",
]);
requiresAll("claim collection gate", ["claim_collection_disabled", "claim_collection_enabled"]);
requiresAll("permanent role separation", ["admin_tainted", "role_separation"]);

requiresAll("reviewer roles", ["primary", "secondary", "adjudicator", "admin"]);
requiresPatterns("stage machine", [
  /const STAGES\s*=\s*\[\s*"initial",\s*"reveal",\s*"final",\s*"secondary",\s*"adjudicate"\s*\]/,
  /const LLM_FIRST_STAGES\s*=\s*\[\s*"final",\s*"secondary",\s*"adjudicate"\s*\]/,
  /events\.adjudicate\s*\?\s*"adjudicated"/,
]);
requiresAll("LLM-first human-review contract", [
  "aamd-llm-first-human-review-v2",
  "aamd-llm-first-labeler-32b-v1",
  "Qwen/Qwen2.5-VL-32B-Instruct",
  "32B",
  "labeler_revision_unattested",
  "labeler_g0_unconfigured",
  "TRUSTED_LABELER_G0_ATTESTATION_SHA256",
  "TRUSTED_LABELER_CLAIM_BUNDLE_SHA256",
  "legacy_claim_import_disabled",
  "future_generation_timestamp",
  "llm_first_human_review",
  "available_to_assigned_reviewers_before_human_review",
  "accept_requires_unchanged_proposal",
  "unsupported_protocol",
  "queue-bundle",
  "wireLlmFirstDecision",
  "같은 LLM proposal",
]);

requiresAll("V3 RCAT-7 taxonomy-review contract", [
  "aamd-llm-first-taxonomy-review-v3",
  "aamd-llm-first-labeler-32b-v3",
  "aamd-rcat-7-v1.1",
  "2f8512333c90888aa640e8432ec262cdd452adbae3d1e8df5c96c5654a5c816c",
  "27cf07fb7c46f8885282c62e99dd4ac9f9e80669b129bf8bf0178a18a0958abe",
  "llm_first_taxonomy_review",
  "aamd-stage-chain-v3",
  "adaptation_mechanism",
  "consumed_response_signal",
  "search_action",
  "semantic_linkage",
  "memory_source_scope",
  "memory_operation",
  "evidence_provenance",
  "dialogue_horizon",
  "human_reviewed_axes",
  "runtime_locked_axes",
  "locked_axes_hash",
  "locked_axes_hash_mismatch",
  "proposal_version_mismatch",
  "proposal_id_mismatch",
  "provenance_dispute",
  "RCAT7.MECHANISM.BOUNDARY_LOCALIZATION",
  "taxonomy_contract_mismatch",
  "taxonomy_axis_coverage",
  "missing_category_evidence",
  "mapping_mechanism_mismatch",
  "benign_confound",
]);

requiresAll("T4 affordance contract", [
  "defense_invariant",
  "benign_exception",
  "predicted_readaptation",
  "evaluation_probe",
]);

requiresAll("write-origin controls", ["origin", "sec-fetch-site", "application/json"]);
requiresPatterns("request bounds", [/MAX_JSON_BYTES\s*=\s*64\s*\*\s*1024/, /MAX_IMPORT_BYTES\s*=\s*1024\s*\*\s*1024/]);
requiresAll("receipt contract", [
  "event_id",
  "event_hash",
  "previous_event_hash",
  "server_received_at",
  "chain_version",
]);

requiresAll("sensitive-field denylist", [
  "raw_payload",
  "attack_text",
  "target_response",
  "harmful_request",
]);

assert.doesNotMatch(
  source,
  /access-control-allow-origin["'\s:]*["']\*["']/i,
  "claim worker must not enable wildcard CORS",
);
assert.doesNotMatch(
  source,
  /AAMD_(?:UPSTREAM|AICA)_(?:URL|TOKEN|KEY)|\/api\/admin\/upstream\/sync/i,
  "experiment worker must have no runtime AICA/upstream dependency",
);
assert.match(source, /runtime_dependency:\s*"Sites Worker \+ D1 only/, "API must declare its offline runtime dependency");
const fetchCalls = [...source.matchAll(/\bfetch\s*\(([^\n)]*)/g)].map((match) => match[1].trim());
assert.equal(fetchCalls.filter((entry) => entry === "path,init").length, 1, "one relative browser API fetch is required");
assert.ok(
  fetchCalls.every((entry) => entry === "path,init" || entry === "request, env"),
  "only the browser's relative same-origin API call and the Worker handler declaration are allowed; server-side outbound fetch is forbidden",
);
assert.match(
  source,
  /(?:async fetch\(request, env\)|worker\["fetch"\]\s*=\s*async function\s*\(request, env\))/,
  "Worker fetch handler must remain locally implemented",
);
assert.match(source, /\bDB\b/, "worker must use the D1 DB binding");
assert.doesNotMatch(source, /UPDATE\s+stage_events|DELETE\s+FROM\s+stage_events/i, "stage ledger must be insert-only");

console.log(`Claim-worker source contract is present: ${sourcePath}`);
