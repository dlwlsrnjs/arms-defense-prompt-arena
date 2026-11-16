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
  AAMD_BOOTSTRAP_ADMIN_IDS: "admin-upload,admin-approve",
  AAMD_BOOTSTRAP_ADMIN_EMAILS: "",
};

const people = {
  uploader: ["admin-upload", "uploader@example.test"],
  approver: ["admin-approve", "approver@example.test"],
  primary: ["reviewer-primary", "primary@example.test"],
  secondary: ["reviewer-secondary", "secondary@example.test"],
  adjudicator: ["reviewer-adjudicator", "adjudicator@example.test"],
};

function identity(person) {
  return {
    "oai-authenticated-user-id": person[0],
    "oai-authenticated-user-email": person[1],
  };
}

async function call(path, { person, method = "GET", body, idempotencyKey, headers = {} } = {}) {
  const finalHeaders = { ...(person ? identity(person) : {}), ...headers };
  let encodedBody;
  if (body !== undefined) {
    encodedBody = typeof body === "string" ? body : JSON.stringify(body);
    finalHeaders.origin = ORIGIN;
    finalHeaders["sec-fetch-site"] = "same-origin";
    finalHeaders["content-type"] = "application/json";
  }
  if (idempotencyKey) finalHeaders["idempotency-key"] = idempotencyKey;
  const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: finalHeaders, body: encodedBody }), env, { waitUntil() {} });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { response, status: response.status, text, json };
}

async function expect(path, status, options) {
  const result = await call(path, options);
  assert.equal(result.status, status, `${options?.method || "GET"} ${path}: ${result.text}`);
  return result;
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

const proposalSentinel = "SEALED_PROPOSAL_SENTINEL_a8477d";
const bundle = {
  schema_version: 1,
  bundle_id: "claim-bundle-v1",
  mode: "pilot_import",
  claim_bearing: false,
  protocol_version: "aamd-v1",
  codebook_version: "cb-v1",
  visibility_mask_hash: "0".repeat(64),
  queue_hash: "1".repeat(64),
  tasks: [{
    task_id: "task-001",
    benchmark: "T4",
    record_handle: "record-001",
    record_hash: "2".repeat(64),
    split: "blinded",
    claim_bearing: false,
    title: "Abstract defense-affordance review",
    question: "Does this abstract trajectory support a compact defense rule?",
    instructions: "Use only abstract, payload-free evidence.",
    evidence: [{ handle: "ev-001", label: "Transition status", value: "context-reframing followed a bounded refusal" }],
    label_options: [
      { value: "actionable", label: "Actionable", help: "The evidence supports a defense invariant." },
      { value: "unsupported", label: "Unsupported", help: "The evidence is insufficient." },
    ],
    llm_proposal: {
      proposal_id: "proposal-001",
      version: "precomputed-v1",
      label: "actionable",
      confidence: 80,
      evidence_handles: ["ev-001"],
      rationale: proposalSentinel,
      affordance: {
        defense_invariant: "Reassess goal drift across turns.",
        benign_exception: "Allow bounded benign transformations.",
        predicted_readaptation: "The attacker may restate earlier context.",
        evaluation_probe: "Test paraphrased benign and adversarial continuations.",
      },
    },
  }],
};

function judgment(rationale, label = "actionable") {
  return {
    label,
    confidence: 76,
    rationale,
    abstain: false,
    affordance: {
      defense_invariant: "Track whether the apparent local request advances a disallowed cross-turn goal.",
      benign_exception: "Permit harmless follow-ups when the accumulated goal remains benign.",
      predicted_readaptation: "The attacker may quote prior safe outputs to normalize the next step.",
      evaluation_probe: "Contrast matched benign and goal-drifting continuations.",
    },
  };
}

async function registerAndGrant() {
  for (const person of Object.values(people)) await expect("/api/me", 200, { person });

  const grants = [
    [people.primary, ["primary", "secondary"]],
    [people.secondary, ["secondary"]],
    [people.adjudicator, ["adjudicator"]],
  ];
  for (const [target, roles] of grants) {
    await expect("/api/admin/roles", 200, {
      person: people.uploader,
      method: "POST",
      body: { auth_user_id: target[0], roles },
    });
  }
}

await registerAndGrant();
let result = await expect("/api/me", 200, { person: people.uploader });
assert.equal(result.json.runtime_dependency, "Sites Worker + D1 only");
assert.equal(result.json.claim_collection_enabled, false);

// Admin identity is intentionally not a reviewer identity.
result = await expect("/api/tasks", 409, { person: people.uploader, method: "POST", body: { role: "primary" } });
assert.equal(result.json.error.code, "role_separation");
result = await expect("/api/admin/roles", 400, {
  person: people.uploader,
  method: "POST",
  body: { auth_user_id: people.approver[0], roles: ["admin", "primary"] },
});
assert.equal(result.json.error.code, "invalid_roles");

// Bootstrap-admin taint is permanent: another admin cannot reclassify it as a reviewer.
result = await expect("/api/admin/roles", 409, {
  person: people.uploader,
  method: "POST",
  body: { auth_user_id: people.approver[0], roles: ["adjudicator"] },
});
assert.equal(result.json.error.code, "role_separation");
const approverRow = db.users.find((entry) => entry.auth_user_id === people.approver[0]);
assert.equal(approverRow.admin_tainted, 1);
assert.deepEqual(db.roles.filter((entry) => entry.user_id === approverRow.id).map((entry) => entry.role), ["admin"]);

// Conversely, an existing reviewer cannot be promoted through the bootstrap-admin list.
env.AAMD_BOOTSTRAP_ADMIN_IDS += `,${people.secondary[0]}`;
result = await expect("/api/me", 409, { person: people.secondary });
assert.equal(result.json.error.code, "role_separation");
env.AAMD_BOOTSTRAP_ADMIN_IDS = "admin-upload,admin-approve";

// Claim-bearing import is fail-closed until the preregistered collection gate is explicit.
const disabledBundle = clone(bundle);
disabledBundle.bundle_id = "disabled-claim-bundle";
disabledBundle.mode = "claim_bearing_candidate";
disabledBundle.claim_bearing = true;
disabledBundle.tasks[0].task_id = "disabled-task-001";
disabledBundle.tasks[0].record_handle = "disabled-record-001";
disabledBundle.tasks[0].claim_bearing = true;
result = await expect("/api/admin/import", 409, { person: people.uploader, method: "POST", body: disabledBundle });
assert.equal(result.json.error.code, "claim_collection_disabled");
assert.equal(db.bundles.length, 0);
env.AAMD_CLAIM_COLLECTION_ENABLED = "true";
result = await expect("/api/me", 200, { person: people.uploader });
assert.equal(result.json.claim_collection_enabled, true);

// Legacy protocols remain readable and pilot-runnable, but cannot create new
// claim-bearing rows that bypass the V2 32B/G0 provenance contract.
result = await expect("/api/admin/import", 409, { person: people.uploader, method: "POST", body: disabledBundle });
assert.equal(result.json.error.code, "legacy_claim_import_disabled");
assert.equal(db.bundles.length, 0);

// Import rejects sensitive/raw fields recursively before persistence.
const unsafeBundle = clone(bundle);
unsafeBundle.bundle_id = "unsafe-bundle";
unsafeBundle.tasks[0].evidence[0].attack_text = "must never enter D1";
result = await expect("/api/admin/import", 400, { person: people.uploader, method: "POST", body: unsafeBundle });
assert.equal(result.json.error.code, "forbidden_payload_field");
assert.equal(db.bundles.length, 0);

// The uploader can quarantine but cannot self-approve.
result = await expect("/api/admin/import", 201, { person: people.uploader, method: "POST", body: bundle });
assert.equal(result.json.status, "quarantined");
assert.equal(db.bundles.length, 1);
assert.equal(db.tasks.length, 1);
assert.doesNotMatch(db.tasks[0].public_task_json, new RegExp(proposalSentinel));
assert.match(db.tasks[0].proposal_json, new RegExp(proposalSentinel));

// Bundle-uploader history is also non-reclassifiable by the other admin.
result = await expect("/api/admin/roles", 409, {
  person: people.approver,
  method: "POST",
  body: { auth_user_id: people.uploader[0], roles: ["primary"] },
});
assert.equal(result.json.error.code, "role_separation");
const uploaderRow = db.users.find((entry) => entry.auth_user_id === people.uploader[0]);
assert.equal(uploaderRow.admin_tainted, 1);
assert.deepEqual(db.roles.filter((entry) => entry.user_id === uploaderRow.id).map((entry) => entry.role), ["admin"]);

result = await expect("/api/admin/approve", 409, { person: people.uploader, method: "POST", body: { bundle_id: bundle.bundle_id } });
assert.equal(result.json.error.code, "two_person_rule");
result = await expect("/api/tasks", 404, { person: people.primary, method: "POST", body: { role: "primary", bundle_id: bundle.bundle_id } });
assert.equal(result.json.error.code, "bundle_not_found");

result = await expect("/api/admin/approve", 201, { person: people.approver, method: "POST", body: { bundle_id: bundle.bundle_id } });
assert.equal(result.json.status, "approved");

// Primary assignment and task projection are blind-first.
result = await expect("/api/tasks", 201, { person: people.primary, method: "POST", body: { role: "primary", bundle_id: bundle.bundle_id } });
assert.equal(result.json.assignment.task_id, "task-001");
const primaryViewBefore = await expect("/api/tasks/task-001?role=primary", 200, { person: people.primary });
assert.equal(primaryViewBefore.json.proposal, null);
assert.doesNotMatch(primaryViewBefore.text, new RegExp(proposalSentinel));
assert.equal(primaryViewBefore.json.task.split, "blinded");
for (const key of ["llm_proposal", "attack_text", "raw_payload", "real_split", "outcome"]) assert.ok(!(key in primaryViewBefore.json.task));

// Stage order cannot be skipped.
result = await expect("/api/tasks/task-001/reveal", 409, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "reveal-too-early-001",
  body: { expected_version: 1, initial_event_hash: "f".repeat(64) },
});
assert.equal(result.json.error.code, "initial_receipt_mismatch");
assert.equal(db.events.length, 0);

// T4 requires exactly all four affordance fields.
const incomplete = judgment("Incomplete T4 attempt");
delete incomplete.affordance.evaluation_probe;
result = await expect("/api/tasks/task-001/initial", 400, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "initial-incomplete-001",
  body: { expected_version: 0, judgment: incomplete },
});
assert.equal(result.json.error.code, "missing_field");
assert.equal(db.events.length, 0);

const initialBody = { expected_version: 0, judgment: judgment("PRIMARY_INITIAL_SENTINEL") };
result = await expect("/api/tasks/task-001/initial", 201, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "initial-idempotent-001",
  body: initialBody,
});
const initialReceipt = result.json.receipt;
assert.equal(result.json.replayed, false);
for (const key of ["event_id", "event_hash", "previous_event_hash", "server_received_at", "chain_version", "server_signature"]) assert.ok(initialReceipt[key], `receipt.${key}`);
assert.equal(initialReceipt.previous_event_hash, "GENESIS");
assert.equal(db.events.length, 1);
assert.ok(db.events[0].idempotency_key_hash);
assert.notEqual(db.events[0].idempotency_key_hash, "initial-idempotent-001");

const firstEventSnapshot = clone(db.events[0]);
result = await expect("/api/tasks/task-001/initial", 200, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "initial-idempotent-001",
  body: initialBody,
});
assert.equal(result.json.replayed, true);
assert.deepEqual(result.json.receipt, initialReceipt);
assert.equal(db.events.length, 1);
assert.deepEqual(db.events[0], firstEventSnapshot);

const conflictingInitial = clone(initialBody);
conflictingInitial.judgment.confidence = 75;
result = await expect("/api/tasks/task-001/initial", 409, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "initial-idempotent-001",
  body: conflictingInitial,
});
assert.equal(result.json.error.code, "idempotency_conflict");
assert.deepEqual(db.events[0], firstEventSnapshot);

const primaryAfterInitial = await expect("/api/tasks/task-001?role=primary", 200, { person: people.primary });
assert.equal(primaryAfterInitial.json.proposal, null);
assert.doesNotMatch(primaryAfterInitial.text, new RegExp(proposalSentinel));

result = await expect("/api/tasks/task-001/reveal", 201, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "proposal-reveal-001",
  body: { expected_version: 1, initial_event_hash: initialReceipt.event_hash },
});
assert.equal(result.json.proposal.rationale, proposalSentinel);
const revealReceipt = result.json.receipt;
assert.equal(revealReceipt.previous_event_hash, initialReceipt.event_hash);

result = await expect("/api/tasks/task-001/final", 201, {
  person: people.primary,
  method: "POST",
  idempotencyKey: "primary-final-001",
  body: {
    expected_version: 2,
    reveal_event_hash: revealReceipt.event_hash,
    decision: "edit_after_proposal",
    judgment: judgment("PRIMARY_FINAL_SENTINEL"),
  },
});
const finalReceipt = result.json.receipt;
assert.equal(finalReceipt.previous_event_hash, revealReceipt.event_hash);

// Even when someone has both reviewer roles, they cannot review their own primary task again.
result = await expect("/api/tasks", 409, { person: people.primary, method: "POST", body: { role: "secondary", bundle_id: bundle.bundle_id } });
assert.equal(result.json.error.code, "no_eligible_task");

// The independent secondary sees neither proposal nor primary judgment.
await expect("/api/tasks", 201, { person: people.secondary, method: "POST", body: { role: "secondary", bundle_id: bundle.bundle_id } });
const secondaryView = await expect("/api/tasks/task-001?role=secondary", 200, { person: people.secondary });
for (const secret of [proposalSentinel, "PRIMARY_INITIAL_SENTINEL", "PRIMARY_FINAL_SENTINEL"]) assert.doesNotMatch(secondaryView.text, new RegExp(secret));
for (const key of ["proposal", "initial", "final", "votes", "reveal_receipt"]) assert.ok(!(key in secondaryView.json));

result = await expect("/api/tasks/task-001/secondary", 201, {
  person: people.secondary,
  method: "POST",
  idempotencyKey: "secondary-vote-001",
  body: { expected_version: 3, judgment: judgment("SECONDARY_SENTINEL") },
});
const secondaryReceipt = result.json.receipt;
assert.equal(secondaryReceipt.previous_event_hash, finalReceipt.event_hash);

await expect("/api/tasks", 201, { person: people.adjudicator, method: "POST", body: { role: "adjudicator", bundle_id: bundle.bundle_id } });
const adjudicatorView = await expect("/api/tasks/task-001?role=adjudicator", 200, { person: people.adjudicator });
assert.equal(adjudicatorView.json.votes.primary_final.judgment.rationale, "PRIMARY_FINAL_SENTINEL");
assert.equal(adjudicatorView.json.votes.secondary.judgment.rationale, "SECONDARY_SENTINEL");
assert.doesNotMatch(adjudicatorView.text, new RegExp(proposalSentinel));

result = await expect("/api/tasks/task-001/adjudicate", 201, {
  person: people.adjudicator,
  method: "POST",
  idempotencyKey: "adjudication-001",
  body: { expected_version: 4, resolution: "agreement", judgment: judgment("ADJUDICATION_SENTINEL") },
});
assert.equal(result.json.receipt.previous_event_hash, secondaryReceipt.event_hash);
assert.equal(db.events.length, 5);

// Admin-only export contains the complete verifiable chain but no direct identity or raw idempotency keys.
result = await expect("/api/admin/export?bundle_id=claim-bundle-v1", 403, { person: people.primary });
assert.equal(result.json.error.code, "role_required");
result = await expect("/api/admin/export?bundle_id=claim-bundle-v1", 200, { person: people.uploader });
const exported = result.json.export;
assert.equal(exported.events.length, 5);
assert.equal(exported.tasks[0].proposal_release_status, "released_after_initial_lock");
assert.equal(exported.tasks[0].proposal.rationale, proposalSentinel);
assert.equal(exported.events[0].previous_event_hash, "GENESIS");
for (let index = 1; index < exported.events.length; index += 1) assert.equal(exported.events[index].previous_event_hash, exported.events[index - 1].event_hash);
for (const event of exported.events) {
  assert.match(event.actor_hash, /^[a-f0-9]{64}$/);
  assert.match(event.idempotency_key_hash, /^[a-f0-9]{64}$/);
  assert.equal(event.receipt.event_hash, event.event_hash);
  assert.equal(event.receipt.previous_event_hash, event.previous_event_hash);
  const { server_signature: receiptSignature, ...receiptBase } = event.receipt;
  assert.equal(receiptSignature, await __test.hmacHex(RECEIPT_KEY, receiptBase));
}
const exportPayload = clone(exported);
delete exportPayload.export_hash;
delete exportPayload.signature_algorithm;
delete exportPayload.export_signature;
assert.equal(exported.export_hash, await __test.sha256Hex(exportPayload));
assert.equal(exported.export_signature, await __test.hmacHex(RECEIPT_KEY, {
  export_hash: exported.export_hash,
  bundle_id: exported.bundle.bundle_id,
  generated_at: exported.generated_at,
}));
for (const secret of [...Object.values(people).flat(), "initial-idempotent-001", RECEIPT_KEY]) assert.doesNotMatch(JSON.stringify(exported), new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

globalThis.fetch = nativeFetch;
console.log("Claim-worker offline workflow integration tests passed");
