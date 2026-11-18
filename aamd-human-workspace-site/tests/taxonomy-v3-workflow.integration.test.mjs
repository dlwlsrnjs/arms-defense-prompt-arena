import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import worker, { __test } from "../worker/index.js";
import { MockD1 } from "./mock-d1.mjs";

const ORIGIN = "https://workspace.example";
const fixtureUrl = new URL("../fixtures/pilot-bundle.taxonomy-v3.synthetic.json", import.meta.url);
const bundle = JSON.parse(await readFile(fixtureUrl, "utf8"));
const fixtureTask = bundle.tasks[0];
const proposal = fixtureTask.llm_proposal;
const db = new MockD1();
const env = {
  DB: db,
  AAMD_RECEIPT_HMAC_KEY: "test-only-receipt-key-32-characters-minimum",
  AAMD_BOOTSTRAP_ADMIN_IDS: "admin-upload-v3,admin-approve-v3",
  AAMD_BOOTSTRAP_ADMIN_EMAILS: "",
};
const people = {
  uploader: ["admin-upload-v3", "uploader-v3@example.test"],
  approver: ["admin-approve-v3", "approver-v3@example.test"],
  primary: ["reviewer-primary-v3", "primary-v3@example.test"],
  secondary: ["reviewer-secondary-v3", "secondary-v3@example.test"],
  adjudicator: ["reviewer-adjudicator-v3", "adjudicator-v3@example.test"],
};

function identity(person) {
  return { "oai-authenticated-user-id": person[0], "oai-authenticated-user-email": person[1] };
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

async function call(path, { person, method = "GET", body, idempotencyKey } = {}) {
  const headers = person ? identity(person) : {};
  let encodedBody;
  if (body !== undefined) {
    encodedBody = JSON.stringify(body);
    headers.origin = ORIGIN;
    headers["sec-fetch-site"] = "same-origin";
    headers["content-type"] = "application/json";
  }
  if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
  const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers, body: encodedBody }), env, { waitUntil() {} });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: response.status, text, json };
}

async function expect(path, status, options) {
  const result = await call(path, options);
  assert.equal(result.status, status, `${options?.method || "GET"} ${path}: ${result.text}`);
  return result;
}

function proposalJudgment() {
  const judgment = {
    mapping_status: proposal.mapping_status,
    reviewed_axes: proposal.reviewed_axes.map((entry) => ({ ...entry, evidence_handles: [...entry.evidence_handles] })),
    locked_axes_hash: proposal.locked_axes_hash,
    benign_confound: { ...proposal.benign_confound, evidence_handles: [...proposal.benign_confound.evidence_handles] },
    rationale: proposal.rationale,
    abstain: false,
    provenance_dispute: null,
  };
  if (proposal.affordance) judgment.affordance = { ...proposal.affordance };
  return judgment;
}

for (const person of Object.values(people)) await expect("/api/me", 200, { person });
for (const [person, roles] of [[people.primary, ["primary"]], [people.secondary, ["secondary"]], [people.adjudicator, ["adjudicator"]]]) {
  await expect("/api/admin/roles", 200, { person: people.uploader, method: "POST", body: { auth_user_id: person[0], roles } });
}

for (const [name, mutate, code] of [
  ["public record", (copy) => { copy.tasks[0].title = "Crafted public title with a stale commitment"; }, "record_hash_mismatch"],
  ["visibility mask", (copy) => { copy.visibility_mask_hash = "f".repeat(64); }, "visibility_mask_hash_mismatch"],
  ["ordered queue", (copy) => { copy.queue_hash = "f".repeat(64); }, "queue_hash_mismatch"],
]) {
  const tampered = clone(bundle);
  mutate(tampered);
  const rejected = await expect("/api/admin/import", 400, { person: people.uploader, method: "POST", body: tampered });
  assert.equal(rejected.json.error.code, code, name);
  assert.equal(db.bundles.length, 0, name);
  assert.equal(db.tasks.length, 0, name);
}

const tamperedProposalIdBundle = JSON.parse(JSON.stringify(bundle));
tamperedProposalIdBundle.tasks[0].llm_proposal.proposal_id = "proposal-000000000000000000000000";
let result = await expect("/api/admin/import", 400, { person: people.uploader, method: "POST", body: tamperedProposalIdBundle });
assert.equal(result.json.error.code, "proposal_id_mismatch");
assert.equal(db.bundles.length, 0);
assert.equal(db.tasks.length, 0);

const tamperedLockBundle = JSON.parse(JSON.stringify(bundle));
tamperedLockBundle.tasks[0].locked_axes.evidence_provenance.derivation_rule = "tampered_receipt_parser_v1";
result = await expect("/api/admin/import", 400, { person: people.uploader, method: "POST", body: tamperedLockBundle });
assert.equal(result.json.error.code, "locked_axes_hash_mismatch");
assert.equal(db.bundles.length, 0);
assert.equal(db.tasks.length, 0);

result = await expect("/api/admin/import", 201, { person: people.uploader, method: "POST", body: bundle });
assert.equal(result.json.status, "active");
assert.equal(result.json.activation_policy, "validated_import");
await expect("/api/admin/approve", 404, { person: people.approver, method: "POST", body: { bundle_id: bundle.bundle_id } });

await expect("/api/tasks", 201, { person: people.primary, method: "POST", body: { role: "primary", bundle_id: bundle.bundle_id } });
result = await expect("/api/tasks/task-taxonomy-v3-001?role=primary", 200, { person: people.primary });
assert.equal(result.json.workflow, "llm_first_taxonomy_review");
assert.equal(result.json.proposal.reviewed_axes.length, 4);
assert.equal(result.json.task.taxonomy_hash, proposal.provenance.taxonomy_hash);
assert.deepEqual(Object.keys(result.json.task.locked_axes).sort(), ["dialogue_horizon", "evidence_provenance", "memory_operation", "memory_source_scope"]);
assert.equal(result.json.task.locked_axes_hash, proposal.locked_axes_hash);
assert.equal(result.json.task.locked_axes.evidence_provenance.code, "RCAT7.PROVENANCE.DIRECT_RESPONSE_TO_SUCCESSOR_RECEIPT");

const attemptedOverwrite = proposalJudgment();
attemptedOverwrite.locked_axes = fixtureTask.locked_axes;
result = await expect("/api/tasks/task-taxonomy-v3-001/final", 400, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v3-lock-overwrite",
  body: { expected_version: 0, decision: "accept", judgment: attemptedOverwrite },
});
assert.equal(result.json.error.code, "unknown_field");

const wrongLockBinding = proposalJudgment();
wrongLockBinding.locked_axes_hash = "f".repeat(64);
result = await expect("/api/tasks/task-taxonomy-v3-001/final", 400, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v3-lock-hash-mismatch",
  body: { expected_version: 0, decision: "accept", judgment: wrongLockBinding },
});
assert.equal(result.json.error.code, "locked_axes_hash_mismatch");

const invalidAccept = proposalJudgment();
invalidAccept.rationale = "Changed while claiming exact acceptance";
result = await expect("/api/tasks/task-taxonomy-v3-001/final", 400, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v3-invalid-accept",
  body: { expected_version: 0, decision: "accept", judgment: invalidAccept },
});
assert.equal(result.json.error.code, "accept_requires_unchanged_proposal");

const primaryJudgment = proposalJudgment();
const search = primaryJudgment.reviewed_axes.find((entry) => entry.axis === "search_action");
search.code = "RCAT7.SEARCH.LOCAL_PARAMETER_CHANGE";
search.rationale = "Primary review finds a bounded local parameter change rather than a global operation switch.";
primaryJudgment.provenance_dispute = {
  axis: "evidence_provenance",
  evidence_handles: ["ev-v3-linkage"],
  rationale: "Primary disputes the receipt parser classification while preserving the immutable locked value.",
};
result = await expect("/api/tasks/task-taxonomy-v3-001/final", 201, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v3-primary-edit",
  body: { expected_version: 0, decision: "edit", judgment: primaryJudgment },
});
const primaryReceipt = result.json.receipt;
assert.equal(primaryReceipt.chain_version, "aamd-stage-chain-v3");
assert.equal(primaryReceipt.previous_event_hash, "GENESIS");

await expect("/api/tasks", 201, { person: people.secondary, method: "POST", body: { role: "secondary", bundle_id: bundle.bundle_id } });
result = await expect("/api/tasks/task-taxonomy-v3-001?role=secondary", 200, { person: people.secondary });
assert.equal(result.json.workflow, "llm_first_taxonomy_review");
assert.equal(result.json.final, undefined);
assert.equal(result.json.votes, undefined);
assert.doesNotMatch(result.text, /Primary review finds a bounded local parameter change/);
assert.doesNotMatch(result.text, /Primary disputes the receipt parser classification/);
assert.equal(result.json.task.locked_axes_hash, fixtureTask.locked_axes_hash);
assert.deepEqual(result.json.task.locked_axes, fixtureTask.locked_axes);
result = await expect("/api/tasks/task-taxonomy-v3-001/secondary", 201, {
  person: people.secondary,
  method: "POST",
  idempotencyKey: "v3-secondary-accept",
  body: { expected_version: 1, decision: "accept", judgment: proposalJudgment() },
});
const secondaryReceipt = result.json.receipt;
assert.equal(secondaryReceipt.previous_event_hash, primaryReceipt.event_hash);

await expect("/api/tasks", 201, { person: people.adjudicator, method: "POST", body: { role: "adjudicator", bundle_id: bundle.bundle_id } });
result = await expect("/api/tasks/task-taxonomy-v3-001/adjudicate", 400, {
  person: people.adjudicator,
  method: "POST",
  idempotencyKey: "v3-invalid-agreement",
  body: { expected_version: 2, resolution: "agreement", judgment: primaryJudgment },
});
assert.equal(result.json.error.code, "invalid_agreement");
result = await expect("/api/tasks/task-taxonomy-v3-001/adjudicate", 201, {
  person: people.adjudicator,
  method: "POST",
  idempotencyKey: "v3-adjudication",
  body: { expected_version: 2, resolution: "resolved", judgment: primaryJudgment },
});
assert.equal(result.json.receipt.previous_event_hash, secondaryReceipt.event_hash);

result = await expect(`/api/admin/export?bundle_id=${bundle.bundle_id}`, 200, { person: people.uploader });
const exported = result.json.export;
assert.equal(exported.schema_version, 3);
assert.equal(exported.workflow, "llm_first_taxonomy_review");
assert.equal(exported.tasks[0].proposal.provenance.taxonomy_hash, proposal.provenance.taxonomy_hash);
assert.equal(exported.tasks[0].proposal_hash, await __test.sha256Hex(proposal));
assert.equal(exported.tasks[0].task.locked_axes_hash, fixtureTask.locked_axes_hash);
assert.deepEqual(exported.tasks[0].task.locked_axes, fixtureTask.locked_axes);
assert.equal(exported.tasks[0].proposal.locked_axes_hash, fixtureTask.locked_axes_hash);
assert.deepEqual(exported.events.map((event) => event.expected_version), [0, 1, 2]);
assert.deepEqual(exported.events.map((event) => event.stage), ["final", "secondary", "adjudicate"]);
assert.deepEqual(exported.events[0].payload.judgment.provenance_dispute, primaryJudgment.provenance_dispute);
assert.equal(exported.events[1].payload.judgment.provenance_dispute, null);
assert.deepEqual(exported.events.map((event) => event.receipt.chain_version), ["aamd-stage-chain-v3", "aamd-stage-chain-v3", "aamd-stage-chain-v3"]);

console.log("V3 RCAT-7 V1.1 LLM-first human-review workflow integration tests passed");
