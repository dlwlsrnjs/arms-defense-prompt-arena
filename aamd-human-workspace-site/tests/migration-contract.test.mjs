import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";

const [baseSql, taintSql, bundleSchemaSql, servicePrincipalSql, journal] = await Promise.all([
  readFile(new URL("../drizzle/0000_aamd_workspace.sql", import.meta.url), "utf8"),
  readFile(new URL("../drizzle/0001_admin_taint.sql", import.meta.url), "utf8"),
  readFile(new URL("../drizzle/0002_bundle_schema_v2.sql", import.meta.url), "utf8"),
  readFile(new URL("../drizzle/0003_service_principals.sql", import.meta.url), "utf8"),
  readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8").then(JSON.parse),
]);
const sql = `${baseSql}\n${taintSql}\n${bundleSchemaSql}\n${servicePrincipalSql}`;

function requirePattern(source, pattern, message) {
  assert.match(source, pattern, message);
}

function triggerNames(database) {
  return new Set(database.prepare("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name").all().map((row) => row.name));
}

function column(database, table, name) {
  return database.prepare(`PRAGMA table_info(${table})`).all().find((entry) => entry.name === name);
}

function insertUser(database, authUserId) {
  database.prepare("INSERT INTO workspace_users (auth_user_id,email,email_normalized,identity_hash,created_at,last_seen_at) VALUES (?,?,?,?,?,?)")
    .run(authUserId, `${authUserId}@example.test`, `${authUserId}@example.test`, `${authUserId}-identity-hash`, "2026-11-16T00:00:00.000Z", "2026-11-16T00:00:00.000Z");
  return Number(database.prepare("SELECT id FROM workspace_users WHERE auth_user_id=?").get(authUserId).id);
}

function insertRole(database, userId, role) {
  database.prepare("INSERT INTO user_roles (user_id,role,granted_by,created_at) VALUES (?,?,NULL,?)")
    .run(userId, role, "2026-11-16T00:00:00.000Z");
}

function insertBundle(database, userId, bundleId, schemaVersion) {
  database.prepare("INSERT INTO task_bundles (bundle_id,schema_version,mode,claim_bearing,protocol_version,codebook_version,visibility_mask_hash,queue_hash,bundle_hash,task_count,imported_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(bundleId, schemaVersion, "pilot_import", 0, schemaVersion === 2 ? "aamd-llm-first-taxonomy-review-v3" : "aamd-llm-first-human-review-v2", schemaVersion === 2 ? "aamd-rcat-7-v1.1" : "legacy", `${schemaVersion}`.repeat(64), `${schemaVersion + 2}`.repeat(64), `${bundleId}-bundle-hash`, 1, userId, "2026-11-16T00:00:00.000Z");
}

function applyTransactionalMigration(database, migrationSql) {
  database.exec("BEGIN");
  try {
    database.exec(migrationSql);
    database.exec("COMMIT");
  } catch (error) {
    try { database.exec("ROLLBACK"); } catch {}
    throw error;
  }
}

const taintTriggers = [
  "workspace_users_admin_taint_no_reset",
  "workspace_users_admin_taint_no_reviewer_mix",
  "user_roles_admin_taint_required",
  "user_roles_tainted_reviewer_forbidden",
];
const servicePrincipalTriggers = [
  "workspace_users_principal_type_no_update",
  "user_roles_service_principal_forbidden",
  "user_roles_service_principal_update_forbidden",
];

// 0000 is immutable provenance. The security change must remain an additive 0001 migration.
assert.doesNotMatch(baseSql, /admin_tainted|admin_taint/i, "0000 must not be rewritten with the later admin-taint feature");
assert.deepEqual(
  journal.entries.map((entry) => [entry.idx, entry.tag]),
  [[0, "0000_aamd_workspace"], [1, "0001_admin_taint"], [2, "0002_bundle_schema_v2"], [3, "0003_service_principals"]],
  "migration journal must apply 0000, 0001, 0002, then 0003",
);
requirePattern(taintSql, /ALTER TABLE workspace_users[\s\S]*?ADD COLUMN admin_tainted\s+INTEGER\s+NOT NULL\s+DEFAULT\s+0[\s\S]*?CHECK\s*\(admin_tainted IN \(0, 1\)\)/i, "0001 must add a constrained permanent admin-taint bit");
requirePattern(taintSql, /UPDATE workspace_users[\s\S]*?SET admin_tainted\s*=\s*1[\s\S]*?SELECT user_id FROM user_roles WHERE role\s*=\s*'admin'/i, "0001 must backfill every existing admin before installing enforcement triggers");
assert.ok(taintSql.indexOf("SET admin_tainted = 1") < taintSql.indexOf("CREATE TRIGGER"), "existing admins must be backfilled before triggers are created");
requirePattern(bundleSchemaSql, /schema_version\s+INTEGER\s+NOT NULL\s+CHECK\s*\(schema_version IN \(1, 2\)\)/i, "0002 must admit both historical V1/V2 and RCAT V3 bundle schemas");
requirePattern(bundleSchemaSql, /PRAGMA defer_foreign_keys\s*=\s*ON/i, "0002 must defer foreign keys inside D1's implicit migration transaction");
assert.doesNotMatch(bundleSchemaSql, /PRAGMA foreign_keys\s*=\s*OFF/i, "D1 migrations cannot disable foreign keys inside their implicit transaction");
requirePattern(bundleSchemaSql, /INSERT INTO task_bundles_schema_v2[\s\S]*?SELECT[\s\S]*?FROM task_bundles[\s\S]*?DROP TABLE task_bundles[\s\S]*?ALTER TABLE task_bundles_schema_v2 RENAME TO task_bundles/i, "0002 must copy historical bundle rows before replacing the old table");
requirePattern(bundleSchemaSql, /PRAGMA foreign_key_check[\s\S]*?PRAGMA defer_foreign_keys\s*=\s*OFF/i, "0002 must inspect the restored graph before clearing the transient deferred violation");
requirePattern(bundleSchemaSql, /CREATE TRIGGER task_bundles_no_update[\s\S]*?CREATE TRIGGER task_bundles_no_delete/i, "0002 must restore bundle immutability triggers");
requirePattern(servicePrincipalSql, /ADD COLUMN principal_type\s+TEXT\s+NOT NULL\s+DEFAULT\s+'human'[\s\S]*?CHECK\s*\(principal_type IN \('human', 'service'\)\)/i, "0003 must distinguish historical humans from service actors");
requirePattern(servicePrincipalSql, /CREATE TRIGGER workspace_users_principal_type_no_update[\s\S]*?RAISE\(ABORT, 'principal type is immutable'\)/i, "0003 must make principal type immutable");
requirePattern(servicePrincipalSql, /CREATE TRIGGER user_roles_service_principal_forbidden[\s\S]*?principal_type[\s\S]*?RAISE\(ABORT, 'service principals cannot receive human workspace roles'\)/i, "0003 must keep service actors out of human review roles");
requirePattern(servicePrincipalSql, /CREATE TRIGGER user_roles_service_principal_update_forbidden[\s\S]*?BEFORE UPDATE OF user_id, role ON user_roles[\s\S]*?principal_type[\s\S]*?RAISE\(ABORT, 'service principals cannot receive human workspace roles'\)/i, "0003 must prevent moving or rewriting a human role row onto a service principal");

requirePattern(sql, /CREATE TABLE workspace_users\b/i, "workspace identity table is required");
requirePattern(sql, /auth_user_id\s+TEXT\s+NOT NULL\s+UNIQUE/i, "trusted identity must be unique");
requirePattern(sql, /identity_hash\s+TEXT\s+NOT NULL\s+UNIQUE/i, "pseudonymous identity hash must be unique");
requirePattern(sql, /admin_tainted\s+INTEGER\s+NOT NULL\s+DEFAULT\s+0[\s\S]*?CHECK\s*\(admin_tainted IN \(0, 1\)\)/i, "permanent admin-taint bit is required");
requirePattern(sql, /CHECK\s*\(role IN \('admin', 'primary', 'secondary', 'adjudicator'\)\)/i, "roles must be closed");
requirePattern(sql, /CREATE TRIGGER workspace_users_admin_taint_no_reset[\s\S]*?OLD\.admin_tainted\s*=\s*1[\s\S]*?NEW\.admin_tainted\s*<>\s*1[\s\S]*?RAISE\(ABORT, 'admin taint is irreversible'\)/i, "admin taint must never transition from 1 to 0");
requirePattern(sql, /CREATE TRIGGER workspace_users_admin_taint_no_reviewer_mix[\s\S]*?role IN \('primary', 'secondary', 'adjudicator'\)[\s\S]*?RAISE\(ABORT, 'admin and reviewer roles are separated'\)/i, "reviewer identities cannot be newly admin-tainted");
requirePattern(sql, /CREATE TRIGGER user_roles_admin_taint_required[\s\S]*?NEW\.role\s*=\s*'admin'[\s\S]*?admin_tainted[\s\S]*?RAISE\(ABORT, 'admin role requires permanent admin taint'\)/i, "admin role insertion must require taint first");
requirePattern(sql, /CREATE TRIGGER user_roles_tainted_reviewer_forbidden[\s\S]*?NEW\.role IN \('primary', 'secondary', 'adjudicator'\)[\s\S]*?admin_tainted[\s\S]*?RAISE\(ABORT, 'admin-tainted users cannot become reviewers'\)/i, "admin-tainted identities cannot receive reviewer roles");

requirePattern(sql, /CREATE TABLE stage_events\b/i, "append-only event ledger is required");
for (const field of [
  "event_id", "bundle_id", "task_id", "stage", "actor_user_id", "actor_role", "idempotency_key_hash",
  "request_hash", "expected_version", "payload_hash", "previous_event_hash", "event_hash", "server_received_at", "receipt_json",
]) requirePattern(sql, new RegExp(`\\b${field}\\b`, "i"), `stage_events.${field} is required`);
requirePattern(sql, /UNIQUE\s*\(task_id, stage\)/i, "a stage must be committed at most once per task");
requirePattern(sql, /CREATE TRIGGER stage_events_no_update[\s\S]*?RAISE\(ABORT, 'stage events are immutable'\)/i, "ledger UPDATE must be blocked");
requirePattern(sql, /CREATE TRIGGER stage_events_no_delete[\s\S]*?RAISE\(ABORT, 'stage events are immutable'\)/i, "ledger DELETE must be blocked");
requirePattern(sql, /CREATE TABLE tasks[\s\S]*?public_task_json\s+TEXT\s+NOT NULL[\s\S]*?proposal_json\s+TEXT\s+NOT NULL/i, "public task and sealed proposal must be persisted separately");
requirePattern(sql, /CREATE TRIGGER tasks_no_update/i, "imported tasks must be immutable");
requirePattern(sql, /CREATE TRIGGER tasks_no_delete/i, "imported tasks must not be deleted");
requirePattern(sql, /UNIQUE\s*\(task_id, role\)/i, "each task/role assignment must be unique");
for (const forbidden of ["raw_payload", "attack_text", "target_response", "harmful_request"]) assert.doesNotMatch(sql, new RegExp(`\\b${forbidden}\\b`, "i"), `${forbidden} must not be a database column`);

// Fresh installation: all migrations apply in order and every trigger enforces its invariant.
{
  const database = new DatabaseSync(":memory:");
  try {
    database.exec(baseSql);
    assert.equal(column(database, "workspace_users", "admin_tainted"), undefined, "0000 alone must retain the historical schema");
    database.exec(taintSql);
    applyTransactionalMigration(database, bundleSchemaSql);
    database.exec(servicePrincipalSql);
    const taintColumn = column(database, "workspace_users", "admin_tainted");
    assert.ok(taintColumn, "0001 must add admin_tainted on a fresh database");
    assert.equal(taintColumn.notnull, 1);
    assert.equal(String(taintColumn.dflt_value), "0");
    const triggers = triggerNames(database);
    for (const name of taintTriggers) assert.ok(triggers.has(name), `fresh database missing trigger ${name}`);
    for (const name of servicePrincipalTriggers) assert.ok(triggers.has(name), `fresh database missing trigger ${name}`);
    const principalTypeColumn = column(database, "workspace_users", "principal_type");
    assert.ok(principalTypeColumn, "0003 must add principal_type on a fresh database");
    assert.equal(principalTypeColumn.notnull, 1);
    assert.equal(String(principalTypeColumn.dflt_value), "'human'");

    const adminId = insertUser(database, "fresh-admin");
    database.prepare("UPDATE workspace_users SET admin_tainted=1 WHERE id=?").run(adminId);
    insertRole(database, adminId, "admin");
    assert.throws(() => database.prepare("UPDATE workspace_users SET admin_tainted=0 WHERE id=?").run(adminId), /admin taint is irreversible/);
    database.prepare("DELETE FROM user_roles WHERE user_id=? AND role='admin'").run(adminId);
    assert.throws(() => insertRole(database, adminId, "primary"), /admin-tainted users cannot become reviewers/);

    const reviewerId = insertUser(database, "fresh-reviewer");
    insertRole(database, reviewerId, "secondary");
    assert.throws(() => database.prepare("UPDATE workspace_users SET admin_tainted=1 WHERE id=?").run(reviewerId), /admin and reviewer roles are separated/);
    const untaintedId = insertUser(database, "fresh-untainted-admin");
    assert.throws(() => insertRole(database, untaintedId, "admin"), /admin role requires permanent admin taint/);

    database.prepare("INSERT INTO workspace_users (auth_user_id,email,email_normalized,identity_hash,created_at,last_seen_at,admin_tainted,principal_type) VALUES (?,?,?,?,?,?,1,'service')")
      .run("service:fixture", "fixture@service.invalid", "fixture@service.invalid", "service-fixture-identity-hash", "2026-11-16T00:00:00.000Z", "2026-11-16T00:00:00.000Z");
    const serviceId = Number(database.prepare("SELECT id FROM workspace_users WHERE auth_user_id='service:fixture'").get().id);
    assert.equal(database.prepare("SELECT admin_tainted,principal_type FROM workspace_users WHERE id=?").get(serviceId).admin_tainted, 1);
    assert.throws(() => insertRole(database, serviceId, "primary"), /service principals cannot receive human workspace roles|admin-tainted users cannot become reviewers/);
    assert.throws(
      () => database.prepare("UPDATE user_roles SET user_id=?, role='primary' WHERE user_id=? AND role='secondary'").run(serviceId, reviewerId),
      /service principals cannot receive human workspace roles/,
      "UPDATE must not bypass the service-principal role boundary",
    );
    assert.deepEqual(
      database.prepare("SELECT user_id,role FROM user_roles WHERE user_id=? ORDER BY role").all(reviewerId).map((row) => ({ ...row })),
      [{ user_id: reviewerId, role: "secondary" }],
      "a rejected role transfer must leave the human review assignment intact",
    );
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM user_roles WHERE user_id=?").get(serviceId).count, 0, "service principal must remain role-free");
    assert.throws(() => database.prepare("UPDATE workspace_users SET principal_type='human' WHERE id=?").run(serviceId), /principal type is immutable/);

    insertBundle(database, reviewerId, "fresh-schema-v1", 1);
    insertBundle(database, reviewerId, "fresh-schema-v2", 2);
    insertBundle(database, serviceId, "fresh-service-schema-v2", 2);
    assert.throws(() => insertBundle(database, 999999, "fresh-orphan-schema-v2", 2), /FOREIGN KEY constraint failed/);
    assert.throws(() => insertBundle(database, reviewerId, "fresh-schema-v3", 3), /CHECK constraint failed/);
    assert.throws(() => database.prepare("UPDATE task_bundles SET task_count=2 WHERE bundle_id='fresh-schema-v2'").run(), /task bundles are immutable/);
    assert.throws(() => database.prepare("DELETE FROM task_bundles WHERE bundle_id='fresh-schema-v2'").run(), /task bundles are immutable/);
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    database.close();
  }
}

// Upgrade installation: apply 0001 to a populated historical 0000 DB and preserve fail-closed provenance.
{
  const database = new DatabaseSync(":memory:");
  try {
    database.exec(baseSql);
    const oldAdminId = insertUser(database, "old-admin");
    const oldReviewerId = insertUser(database, "old-reviewer");
    const oldMixedId = insertUser(database, "old-mixed");
    insertRole(database, oldAdminId, "admin");
    insertRole(database, oldReviewerId, "primary");
    insertRole(database, oldMixedId, "admin");
    insertRole(database, oldMixedId, "secondary");

    insertBundle(database, oldAdminId, "historical-schema-v1", 1);
    database.prepare("INSERT INTO tasks (task_id,bundle_id,ordinal,benchmark,record_handle,record_hash,public_task_json,proposal_json,proposal_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .run("historical-task", "historical-schema-v1", 0, "T1", "historical-record", "a".repeat(64), "{}", "{}", "b".repeat(64), "2026-11-16T00:00:00.000Z");

    database.exec(taintSql);
    applyTransactionalMigration(database, bundleSchemaSql);
    database.exec(servicePrincipalSql);
    assert.ok(column(database, "workspace_users", "admin_tainted"), "0001 must upgrade an existing 0000 database");
    for (const name of taintTriggers) assert.ok(triggerNames(database).has(name), `upgraded database missing trigger ${name}`);
    for (const name of servicePrincipalTriggers) assert.ok(triggerNames(database).has(name), `upgraded database missing trigger ${name}`);
    assert.equal(database.prepare("SELECT principal_type FROM workspace_users WHERE id=?").get(oldAdminId).principal_type, "human", "0003 must backfill historical identities as human");
    assert.equal(database.prepare("SELECT admin_tainted FROM workspace_users WHERE id=?").get(oldAdminId).admin_tainted, 1, "historical admin must be backfilled");
    assert.equal(database.prepare("SELECT admin_tainted FROM workspace_users WHERE id=?").get(oldReviewerId).admin_tainted, 0, "historical reviewer must remain untainted");
    assert.equal(database.prepare("SELECT admin_tainted FROM workspace_users WHERE id=?").get(oldMixedId).admin_tainted, 1, "historical mixed-role identity must fail closed as admin-tainted");
    assert.equal(database.prepare("SELECT schema_version FROM task_bundles WHERE bundle_id='historical-schema-v1'").get().schema_version, 1, "0002 must preserve historical bundle rows");
    assert.equal(database.prepare("SELECT bundle_id FROM tasks WHERE task_id='historical-task'").get().bundle_id, "historical-schema-v1", "0002 must preserve child task references");
    insertBundle(database, oldReviewerId, "upgraded-schema-v2", 2);
    assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);

    assert.throws(() => database.prepare("UPDATE workspace_users SET admin_tainted=0 WHERE id=?").run(oldAdminId), /admin taint is irreversible/);
    database.prepare("DELETE FROM user_roles WHERE user_id=? AND role='admin'").run(oldAdminId);
    assert.throws(() => insertRole(database, oldAdminId, "adjudicator"), /admin-tainted users cannot become reviewers/);
    database.prepare("DELETE FROM user_roles WHERE user_id=? AND role='secondary'").run(oldMixedId);
    assert.throws(() => insertRole(database, oldMixedId, "primary"), /admin-tainted users cannot become reviewers/);
    assert.throws(() => database.prepare("UPDATE workspace_users SET admin_tainted=1 WHERE id=?").run(oldReviewerId), /admin and reviewer roles are separated/);
  } finally {
    database.close();
  }
}

console.log("D1 fresh-install and incremental-upgrade migration tests passed");
