import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import worker, { __test } from "../worker/index.js";
import { MockD1 } from "./mock-d1.mjs";

const ORIGIN = "https://workspace.example";
const RECEIPT_KEY = "test-only-receipt-key-32-characters-minimum";
const SERVICE_KEY = "test-only-service-import-key-32-characters";
const WRONG_KEY = "test-only-wrong-service-key-32-characters";
const ADMIN = ["service-test-admin", "service-test-admin@example.test"];
const fixtureUrl = new URL("../fixtures/pilot-bundle.synthetic.json", import.meta.url);
const bundle = JSON.parse(await readFile(fixtureUrl, "utf8"));
const v3FixtureUrl = new URL("../fixtures/pilot-bundle.taxonomy-v3.synthetic.json", import.meta.url);
const v3Bundle = JSON.parse(await readFile(v3FixtureUrl, "utf8"));

function clone(value) { return JSON.parse(JSON.stringify(value)); }
function identity(person) { return { "oai-authenticated-user-id": person[0], "oai-authenticated-user-email": person[1] }; }

function makeEnv(db, overrides = {}) {
  return {
    DB: db,
    AAMD_RECEIPT_HMAC_KEY: RECEIPT_KEY,
    AAMD_SERVICE_IMPORT_HMAC_KEY: SERVICE_KEY,
    AAMD_BOOTSTRAP_ADMIN_IDS: ADMIN[0],
    AAMD_BOOTSTRAP_ADMIN_EMAILS: "",
    ...overrides,
  };
}

async function serviceHeaders(body, { key = SERVICE_KEY, timestamp = Math.floor(Date.now() / 1000), idempotencyKey = "service-import-fixture-001" } = {}) {
  const bodyHash = await __test.sha256Hex(body);
  const message = __test.serviceImportSignatureMessage({ bodyHash, idempotencyKey, timestamp });
  return {
    origin: ORIGIN,
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "x-aamd-import-timestamp": String(timestamp),
    "x-aamd-import-signature": await __test.hmacHex(key, message),
  };
}

async function call(path, { env, method = "GET", body, headers = {}, person } = {}) {
  const finalHeaders = { ...(person ? identity(person) : {}), ...headers };
  const encodedBody = body === undefined ? undefined : JSON.stringify(body);
  const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: finalHeaders, body: encodedBody }), env, { waitUntil() {} });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: response.status, text, json };
}

async function serviceCall(body, { db, env = makeEnv(db), ...signatureOptions } = {}) {
  return call("/api/service/import", { env, method: "POST", body, headers: await serviceHeaders(body, signatureOptions) });
}

class DifferentHashRaceD1 extends MockD1 {
  constructor(bundleId) {
    super();
    this.raceBundleId = bundleId;
    this.raceInjected = false;
  }

  async batch(statements) {
    const bundleInsert = statements.some((statement) => statement.sql.startsWith("INSERT INTO task_bundles"));
    if (!this.raceInjected && bundleInsert) {
      this.raceInjected = true;
      const actor = this.users.find((entry) => entry.auth_user_id === "service:aamd-offline-bundle-importer:v1");
      this.bundles.push({ bundle_id: this.raceBundleId, bundle_hash: "f".repeat(64), task_count: 0, imported_by: actor.id });
      throw new Error("UNIQUE constraint failed: task_bundles.bundle_id");
    }
    return super.batch(statements);
  }
}

// Authentication failures happen before any service actor or bundle mutation.
{
  const db = new MockD1(); const env = makeEnv(db);
  let result = await call("/api/service/import", {
    env,
    method: "POST",
    body: bundle,
    headers: { origin: ORIGIN, "content-type": "application/json", "idempotency-key": "service-import-missing-signature", "x-aamd-import-timestamp": String(Math.floor(Date.now() / 1000)) },
  });
  assert.equal(result.status, 401);
  assert.equal(result.json.error.code, "service_import_authentication_failed");
  assert.equal(db.users.length, 0);
  assert.equal(db.bundles.length, 0);

  result = await serviceCall(bundle, { db, env, key: WRONG_KEY, idempotencyKey: "service-import-wrong-signature" });
  assert.equal(result.status, 401);
  assert.equal(result.json.error.code, "service_import_authentication_failed");
  assert.equal(db.users.length, 0);

  result = await serviceCall(bundle, { db, env, timestamp: Math.floor(Date.now() / 1000) - 301, idempotencyKey: "service-import-stale-signature" });
  assert.equal(result.status, 401);
  assert.equal(result.json.error.code, "service_import_timestamp_expired");
  assert.equal(db.users.length, 0);

  const missingKeyEnv = makeEnv(db, { AAMD_SERVICE_IMPORT_HMAC_KEY: undefined });
  result = await serviceCall(bundle, { db, env: missingKeyEnv, idempotencyKey: "service-import-missing-key" });
  assert.equal(result.status, 503);
  assert.equal(result.json.error.code, "service_import_key_unavailable");
  assert.equal(db.users.length, 0);

  const reusedKeyEnv = makeEnv(db, { AAMD_SERVICE_IMPORT_HMAC_KEY: RECEIPT_KEY });
  result = await serviceCall(bundle, { db, env: reusedKeyEnv, key: RECEIPT_KEY, idempotencyKey: "service-import-reused-key" });
  assert.equal(result.status, 503);
  assert.equal(result.json.error.code, "service_import_key_reuse");
  assert.equal(db.users.length, 0);
}

// A correctly authenticated but invalid body fails before creating provenance rows.
{
  const db = new MockD1(); const invalid = clone(bundle);
  invalid.tasks[0].attack_text = "forbidden payload";
  const result = await serviceCall(invalid, { db, idempotencyKey: "service-import-invalid-body" });
  assert.equal(result.status, 400);
  assert.equal(result.json.error.code, "forbidden_payload_field");
  assert.equal(db.users.length, 0);
  assert.equal(db.bundles.length, 0);
  assert.equal(db.tasks.length, 0);
}

// V3/V1.1 service imports recompute all public commitments after shape
// normalization, just like the browser-admin path. A correctly signed crafted
// body cannot smuggle stale record, visibility, or ordered-queue commitments.
{
  const db = new MockD1(); const env = makeEnv(db);
  for (const [name, mutate, code] of [
    ["record", (copy) => { copy.tasks[0].title = "Crafted public title with a stale commitment"; }, "record_hash_mismatch"],
    ["visibility", (copy) => { copy.visibility_mask_hash = "f".repeat(64); }, "visibility_mask_hash_mismatch"],
    ["queue", (copy) => { copy.queue_hash = "f".repeat(64); }, "queue_hash_mismatch"],
  ]) {
    const tampered = clone(v3Bundle);
    mutate(tampered);
    const result = await serviceCall(tampered, { db, env, idempotencyKey: `service-import-v3-${name}-tamper` });
    assert.equal(result.status, 400, result.text);
    assert.equal(result.json.error.code, code, name);
    assert.equal(db.users.length, 0, name);
    assert.equal(db.bundles.length, 0, name);
    assert.equal(db.tasks.length, 0, name);
  }

  const accepted = await serviceCall(v3Bundle, { db, env, idempotencyKey: "service-import-v3-valid" });
  assert.equal(accepted.status, 201, accepted.text);
  assert.equal(db.users.length, 1);
  assert.equal(db.bundles.length, 1);
  assert.equal(db.tasks.length, v3Bundle.tasks.length);
}

// Valid service import creates a distinct non-human FK actor and is safely retryable.
{
  const db = new MockD1(); const env = makeEnv(db);
  let result = await serviceCall(bundle, { db, env, idempotencyKey: "service-import-success-001" });
  assert.equal(result.status, 201, result.text);
  assert.equal(result.json.replayed, false);
  assert.equal(result.json.importer.principal_type, "service");
  assert.equal(result.json.importer.principal_id, "service:aamd-offline-bundle-importer:v1");
  assert.equal(result.json.authentication.signature_version, "aamd-service-import-v1");
  assert.match(result.json.authentication.idempotency_key_hash, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(result.text, new RegExp(SERVICE_KEY));
  assert.equal(db.users.length, 1);
  assert.equal(db.bundles.length, 1);
  assert.equal(db.tasks.length, bundle.tasks.length);
  const actor = db.users[0];
  assert.equal(actor.auth_user_id, "service:aamd-offline-bundle-importer:v1");
  assert.equal(actor.principal_type, "service");
  assert.equal(actor.admin_tainted, 1);
  assert.equal(db.roles.length, 0);
  assert.equal(db.bundles[0].imported_by, actor.id, "task_bundles.imported_by must satisfy the workspace_users FK");

  result = await serviceCall(bundle, { db, env, idempotencyKey: "service-import-success-retry" });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.replayed, true);
  assert.equal(db.users.length, 1);
  assert.equal(db.bundles.length, 1);
  assert.equal(db.tasks.length, bundle.tasks.length);

  const conflicting = clone(bundle);
  conflicting.queue_hash = "f".repeat(64);
  result = await serviceCall(conflicting, { db, env, idempotencyKey: "service-import-hash-conflict" });
  assert.equal(result.status, 409, result.text);
  assert.equal(result.json.error.code, "bundle_id_hash_conflict");
  assert.equal(db.bundles.length, 1);
  assert.equal(db.tasks.length, bundle.tasks.length);

  // The service principal cannot be converted into any human workspace role.
  await call("/api/me", { env, person: ADMIN });
  result = await call("/api/admin/roles", {
    env,
    person: ADMIN,
    method: "POST",
    body: { auth_user_id: actor.auth_user_id, roles: ["primary"] },
    headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" },
  });
  assert.equal(result.status, 409, result.text);
  assert.equal(result.json.error.code, "role_separation");
  assert.equal(db.roles.filter((entry) => entry.user_id === actor.id).length, 0);

  const exported = await call(`/api/admin/export?bundle_id=${encodeURIComponent(bundle.bundle_id)}`, { env, person: ADMIN });
  assert.equal(exported.status, 200, exported.text);
  assert.equal(exported.json.export.bundle.importer_type, "service");
  assert.equal(exported.json.export.bundle.importer_hash, actor.identity_hash);
  assert.ok(!("auth_user_id" in exported.json.export.bundle));
}

// An exact retry is idempotent even if the identical bundle was originally
// imported by a human admin; provenance reports the original actor accurately.
{
  const db = new MockD1(); const env = makeEnv(db);
  await call("/api/me", { env, person: ADMIN });
  let result = await call("/api/admin/import", {
    env,
    person: ADMIN,
    method: "POST",
    body: bundle,
    headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" },
  });
  assert.equal(result.status, 201, result.text);
  result = await serviceCall(bundle, { db, env, idempotencyKey: "service-import-retry-human-origin" });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.replayed, true);
  assert.equal(result.json.importer.principal_type, "human");
  assert.ok(!("principal_id" in result.json.importer));
  assert.equal(db.users.filter((entry) => entry.principal_type === "service").length, 0, "an idempotent readback must not create a false service actor");
  assert.equal(db.bundles.length, 1);
}

// A later task collision rolls the whole bundle batch back; only the explicit
// service principal from the earlier successful import remains.
{
  const db = new MockD1(); const env = makeEnv(db);
  const first = clone(bundle);
  let result = await serviceCall(first, { db, env, idempotencyKey: "service-import-atomic-first" });
  assert.equal(result.status, 201, result.text);
  const second = clone(bundle);
  second.bundle_id = "pilot-synthetic-t4-v2-collision";
  second.tasks[0].record_handle = "pilot-v2-record-collision";
  result = await serviceCall(second, { db, env, idempotencyKey: "service-import-atomic-second" });
  assert.equal(result.status, 500, result.text);
  assert.equal(result.json.error.code, "internal_error");
  assert.equal(db.bundles.length, 1, "failed batch must not leave the second bundle row");
  assert.equal(db.tasks.length, first.tasks.length, "failed batch must not leave partial tasks");
}

// If another transaction wins the same bundle ID after the optimistic read,
// a different canonical hash is still reported as a stable API conflict rather
// than leaking a provider-specific UNIQUE error as an internal failure.
{
  const db = new DifferentHashRaceD1(bundle.bundle_id); const env = makeEnv(db);
  const result = await serviceCall(bundle, { db, env, idempotencyKey: "service-import-different-hash-race" });
  assert.equal(result.status, 409, result.text);
  assert.equal(result.json.error.code, "bundle_id_hash_conflict");
  assert.equal(db.bundles.length, 1);
  assert.equal(db.bundles[0].bundle_hash, "f".repeat(64));
  assert.equal(db.tasks.length, 0);
}

console.log("Service import authentication, provenance, idempotency, and atomicity tests passed");
