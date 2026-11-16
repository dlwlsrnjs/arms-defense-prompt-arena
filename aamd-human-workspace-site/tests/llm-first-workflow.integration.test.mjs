import assert from "node:assert/strict";
import worker, { __test } from "../worker/index.js";
import { MockD1 } from "./mock-d1.mjs";

const ORIGIN = "https://workspace.example";
const RECEIPT_KEY = "test-only-receipt-key-32-characters-minimum";
const nativeFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error("Runtime outbound fetch is forbidden in the offline experiment workflow"); };

const db = new MockD1();
const env = {
  DB: db,
  AAMD_RECEIPT_HMAC_KEY: RECEIPT_KEY,
  AAMD_BOOTSTRAP_ADMIN_IDS: "admin-upload-v2,admin-approve-v2",
  AAMD_BOOTSTRAP_ADMIN_EMAILS: "",
};
const people = {
  uploader: ["admin-upload-v2", "uploader-v2@example.test"],
  approver: ["admin-approve-v2", "approver-v2@example.test"],
  primary: ["reviewer-primary-v2", "primary-v2@example.test"],
  secondary: ["reviewer-secondary-v2", "secondary-v2@example.test"],
  adjudicator: ["reviewer-adjudicator-v2", "adjudicator-v2@example.test"],
};

function identity(person) {
  return { "oai-authenticated-user-id": person[0], "oai-authenticated-user-email": person[1] };
}

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

const proposalRationale = "LLM_PROPOSAL_VISIBLE_FROM_START_v2";
const proposalProvenance = {
  labeler_config_id: "aamd-llm-first-labeler-32b-v1",
  model_id: "Qwen/Qwen2.5-VL-32B-Instruct",
  parameters: "32B",
  model_revision: "7cfb30d71a1f4f49a57592323337a4a4727301da",
  model_revision_status: "candidate_needs_G0_attestation",
  prompt_template_hash: "cfad4c64a0f0afa97db52b779e29f86220df6fd8b6a7fb6f5989f1d8bf27eab2",
  decoding_config_hash: "3725e1f6f82d2a4b469375f668431fd7c406314f0e3b57ac6d02b7af9e887add",
  seed: 20261116,
  generator_code_revision: "synthetic-integration-fixture-v1",
  generated_at: "2026-11-16T00:00:00.000Z",
  source_bundle_hash: "3".repeat(64),
};
const proposal = {
  proposal_id: "proposal-v2-001",
  version: "offline-frozen-v2",
  label: "actionable",
  confidence: 80,
  evidence_handles: ["ev-v2-001"],
  rationale: proposalRationale,
  provenance: proposalProvenance,
  affordance: {
    defense_invariant: "Reassess cross-turn goal drift before answering.",
    benign_exception: "Allow ordinary clarification when the accumulated goal remains benign.",
    predicted_readaptation: "The requester may split the same objective into apparently harmless subtasks.",
    evaluation_probe: "Compare matched benign and adversarial continuations.",
  },
};
const bundle = {
  schema_version: 1,
  bundle_id: "llm-first-bundle-v2",
  mode: "pilot_import",
  claim_bearing: false,
  protocol_version: "aamd-llm-first-human-review-v2",
  codebook_version: "cb-v2",
  visibility_mask_hash: "0".repeat(64),
  queue_hash: "1".repeat(64),
  tasks: [{
    task_id: "task-v2-001",
    benchmark: "T4",
    record_handle: "record-v2-001",
    record_hash: "2".repeat(64),
    split: "blinded",
    claim_bearing: false,
    title: "LLM-first defense-affordance review",
    question: "Does the proposal faithfully summarize the abstract evidence?",
    instructions: "Review the frozen LLM proposal against payload-free evidence.",
    evidence: [{ handle: "ev-v2-001", label: "Transition", value: "The next operation changes after a bounded response." }],
    label_options: [
      { value: "actionable", label: "Actionable", help: "Supports a reusable defense rule." },
      { value: "unsupported", label: "Unsupported", help: "Does not support the proposed rule." },
    ],
    llm_proposal: proposal,
  }],
};

const typoProtocolBundle = JSON.parse(JSON.stringify(bundle));
typoProtocolBundle.bundle_id = "llm-first-bundle-v2-typo";
typoProtocolBundle.protocol_version = "aamd-llm-first-human-review-v2-typo";
assert.throws(
  () => __test.validateBundle(typoProtocolBundle),
  (error) => error?.code === "unsupported_protocol",
);

const wrongModelBundle = JSON.parse(JSON.stringify(bundle));
wrongModelBundle.bundle_id = "llm-first-bundle-v2-wrong-model";
wrongModelBundle.tasks[0].llm_proposal.provenance.model_id = "Qwen/Qwen2.5-VL-7B-Instruct";
assert.throws(
  () => __test.validateBundle(wrongModelBundle),
  (error) => error?.code === "labeler_contract_mismatch",
);

for (const [field, replacement, errorCode] of [
  ["labeler_config_id", "aamd-llm-first-labeler-7b-v1", "labeler_contract_mismatch"],
  ["parameters", "7B", "labeler_contract_mismatch"],
  ["model_revision", "0".repeat(40), "labeler_contract_mismatch"],
  ["prompt_template_hash", "a".repeat(64), "labeler_contract_mismatch"],
  ["decoding_config_hash", "b".repeat(64), "labeler_contract_mismatch"],
  ["seed", 1, "labeler_seed_mismatch"],
]) {
  const drifted = JSON.parse(JSON.stringify(bundle));
  drifted.bundle_id = `llm-first-bundle-v2-drift-${field}`;
  drifted.tasks[0].llm_proposal.provenance[field] = replacement;
  assert.throws(() => __test.validateBundle(drifted), (error) => error?.code === errorCode);
}

const futureGeneratedBundle = JSON.parse(JSON.stringify(bundle));
futureGeneratedBundle.bundle_id = "llm-first-bundle-v2-future-generated";
futureGeneratedBundle.tasks[0].llm_proposal.provenance.generated_at = "2099-01-01T00:00:00.000Z";
assert.throws(
  () => __test.validateBundle(futureGeneratedBundle),
  (error) => error?.code === "future_generation_timestamp",
);

for (const [mutate, errorCode] of [
  [(provenance) => { provenance.model_revision_status = "self_attested"; }, "invalid_revision_status"],
  [(provenance) => { provenance.generated_at = "2026-11-16T00:00:00.000+00:00"; }, "invalid_timestamp"],
  [(provenance) => { provenance.source_bundle_hash = "not-a-hash"; }, "invalid_hash"],
  [(provenance) => { provenance.generator_code_revision = "contains spaces"; }, "invalid_identifier"],
  [(provenance) => { provenance.g0_attestation_hash = "4".repeat(64); }, "unexpected_g0_attestation"],
  [(provenance) => { provenance.unexpected = "field"; }, "unknown_field"],
  [(provenance) => { delete provenance.labeler_config_id; }, "missing_field"],
]) {
  const invalid = JSON.parse(JSON.stringify(bundle));
  mutate(invalid.tasks[0].llm_proposal.provenance);
  assert.throws(() => __test.validateBundle(invalid), (error) => error?.code === errorCode);
}

const unattestedClaimBundle = JSON.parse(JSON.stringify(bundle));
unattestedClaimBundle.bundle_id = "llm-first-bundle-v2-unattested-claim";
unattestedClaimBundle.mode = "claim_bearing_candidate";
unattestedClaimBundle.claim_bearing = true;
unattestedClaimBundle.tasks[0].claim_bearing = true;
assert.throws(
  () => __test.validateBundle(unattestedClaimBundle),
  (error) => error?.code === "labeler_revision_unattested",
);

const attestedClaimBundle = JSON.parse(JSON.stringify(unattestedClaimBundle));
attestedClaimBundle.bundle_id = "llm-first-bundle-v2-attested-claim";
attestedClaimBundle.tasks[0].llm_proposal.provenance.model_revision_status = "g0_attested";
attestedClaimBundle.tasks[0].llm_proposal.provenance.g0_attestation_hash = "4".repeat(64);
assert.throws(
  () => __test.validateBundle(attestedClaimBundle),
  (error) => error?.code === "labeler_g0_unconfigured",
);

function proposalJudgment() {
  return { label: proposal.label, confidence: proposal.confidence, rationale: proposal.rationale, abstain: false, affordance: { ...proposal.affordance } };
}

for (const person of Object.values(people)) await expect("/api/me", 200, { person });
for (const [person, roles] of [[people.primary, ["primary"]], [people.secondary, ["secondary"]], [people.adjudicator, ["adjudicator"]]]) {
  await expect("/api/admin/roles", 200, { person: people.uploader, method: "POST", body: { auth_user_id: person[0], roles } });
}
let result = await expect("/api/admin/import", 409, { person: people.uploader, method: "POST", body: unattestedClaimBundle });
assert.equal(result.json.error.code, "labeler_revision_unattested");
assert.equal(db.bundles.length, 0);
await expect("/api/admin/import", 201, { person: people.uploader, method: "POST", body: bundle });
result = await expect("/api/admin/export?bundle_id=llm-first-bundle-v2", 200, { person: people.uploader });
assert.equal(result.json.export.tasks[0].proposal_release_status, "sealed_unapproved");
assert.equal(result.json.export.tasks[0].proposal, null);
await expect("/api/admin/approve", 201, { person: people.approver, method: "POST", body: { bundle_id: bundle.bundle_id } });

await expect("/api/tasks", 201, { person: people.primary, method: "POST", body: { role: "primary", bundle_id: bundle.bundle_id } });
const primaryView = await expect("/api/tasks/task-v2-001?role=primary", 200, { person: people.primary });
assert.equal(primaryView.json.workflow, "llm_first_human_review");
assert.equal(primaryView.json.status, "awaiting_primary_review");
assert.equal(primaryView.json.proposal.rationale, proposalRationale);
assert.equal(primaryView.json.proposal.provenance.model_id, "Qwen/Qwen2.5-VL-32B-Instruct");
assert.equal(primaryView.json.proposal.provenance.parameters, "32B");
assert.deepEqual(primaryView.json.proposal.provenance, proposalProvenance);
assert.ok(!("initial" in primaryView.json));
assert.ok(!("reveal_receipt" in primaryView.json));

result = await expect("/api/tasks/task-v2-001/initial", 409, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v2-initial-disabled",
  body: { expected_version: 0, judgment: proposalJudgment() },
});
assert.equal(result.json.error.code, "protocol_stage_disabled");
result = await expect("/api/tasks/task-v2-001/reveal", 409, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v2-reveal-disabled",
  body: { expected_version: 0, initial_event_hash: "f".repeat(64) },
});
assert.equal(result.json.error.code, "protocol_stage_disabled");
assert.equal(db.events.length, 0);

const primaryJudgment = proposalJudgment();
primaryJudgment.rationale = "PRIMARY_REVIEW_EDIT_v2";
result = await expect("/api/tasks/task-v2-001/final", 400, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v2-invalid-accept",
  body: { expected_version: 0, decision: "accept", judgment: primaryJudgment },
});
assert.equal(result.json.error.code, "accept_requires_unchanged_proposal");
result = await expect("/api/tasks/task-v2-001/final", 400, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v2-invalid-edit",
  body: { expected_version: 0, decision: "edit", judgment: proposalJudgment() },
});
assert.equal(result.json.error.code, "review_decision_mismatch");
assert.equal(db.events.length, 0);

result = await expect("/api/tasks/task-v2-001/final", 201, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "v2-primary-review",
  body: { expected_version: 0, decision: "edit", judgment: primaryJudgment },
});
const primaryReceipt = result.json.receipt;
assert.equal(primaryReceipt.previous_event_hash, "GENESIS");
assert.equal(primaryReceipt.chain_version, "aamd-stage-chain-v2");

await expect("/api/tasks", 201, { person: people.secondary, method: "POST", body: { role: "secondary", bundle_id: bundle.bundle_id } });
const secondaryView = await expect("/api/tasks/task-v2-001?role=secondary", 200, { person: people.secondary });
assert.equal(secondaryView.json.proposal.rationale, proposalRationale);
assert.doesNotMatch(secondaryView.text, /PRIMARY_REVIEW_EDIT_v2/);
assert.ok(!("final" in secondaryView.json));
result = await expect("/api/tasks/task-v2-001/secondary", 201, {
  person: people.secondary,
  method: "POST",
  idempotencyKey: "v2-secondary-review",
  body: { expected_version: 1, decision: "accept", judgment: proposalJudgment() },
});
const secondaryReceipt = result.json.receipt;
assert.equal(secondaryReceipt.previous_event_hash, primaryReceipt.event_hash);

await expect("/api/tasks", 201, { person: people.adjudicator, method: "POST", body: { role: "adjudicator", bundle_id: bundle.bundle_id } });
const adjudicatorView = await expect("/api/tasks/task-v2-001?role=adjudicator", 200, { person: people.adjudicator });
assert.equal(adjudicatorView.json.proposal.rationale, proposalRationale);
assert.equal(adjudicatorView.json.votes.primary_final.decision, "edit");
assert.equal(adjudicatorView.json.votes.secondary.decision, "accept");
result = await expect("/api/tasks/task-v2-001/adjudicate", 400, {
  person: people.adjudicator,
  method: "POST",
  idempotencyKey: "v2-invalid-agreement",
  body: { expected_version: 2, resolution: "agreement", judgment: primaryJudgment },
});
assert.equal(result.json.error.code, "invalid_agreement");
assert.equal(db.events.length, 2);
result = await expect("/api/tasks/task-v2-001/adjudicate", 201, {
  person: people.adjudicator,
  method: "POST",
  idempotencyKey: "v2-adjudication",
  body: { expected_version: 2, resolution: "resolved", judgment: primaryJudgment },
});
assert.equal(result.json.receipt.previous_event_hash, secondaryReceipt.event_hash);
assert.equal(db.events.length, 3);

result = await expect("/api/admin/export?bundle_id=llm-first-bundle-v2", 200, { person: people.uploader });
const exported = result.json.export;
assert.equal(exported.schema_version, 2);
assert.equal(exported.workflow, "llm_first_human_review");
assert.equal(exported.tasks[0].proposal_release_status, "available_to_assigned_reviewers_before_human_review");
assert.equal(exported.tasks[0].proposal.rationale, proposalRationale);
assert.equal(exported.tasks[0].proposal.provenance.labeler_config_id, "aamd-llm-first-labeler-32b-v1");
assert.deepEqual(exported.tasks[0].proposal.provenance, proposalProvenance);
assert.equal(exported.tasks[0].proposal_hash, await __test.sha256Hex(proposal));
for (const event of exported.events.filter((entry) => entry.stage === "final" || entry.stage === "secondary")) {
  assert.equal(event.payload.proposal_hash, exported.tasks[0].proposal_hash);
}
assert.deepEqual(exported.events.map((event) => event.expected_version), [0, 1, 2]);
assert.deepEqual(exported.events.map((event) => event.stage), ["final", "secondary", "adjudicate"]);

globalThis.fetch = nativeFetch;
console.log("LLM-first human-review workflow integration tests passed");
