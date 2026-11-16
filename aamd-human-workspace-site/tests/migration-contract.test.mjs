import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";

const [baseSql, taintSql, journal] = await Promise.all([
  readFile(new URL("../drizzle/0000_aamd_workspace.sql", import.meta.url), "utf8"),
  readFile(new URL("../drizzle/0001_admin_taint.sql", import.meta.url), "utf8"),
  readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8").then(JSON.parse),
]);
const sql = `${baseSql}\n${taintSql}`;

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

const taintTriggers = [
  "workspace_users_admin_taint_no_reset",
  "workspace_users_admin_taint_no_reviewer_mix",
  "user_roles_admin_taint_required",
  "user_roles_tainted_reviewer_forbidden",
];

// 0000 is immutable provenance. The security change must remain an additive 0001 migration.
assert.doesNotMatch(baseSql, /admin_tainted|admin_taint/i, "0000 must not be rewritten with the later admin-taint feature");
assert.deepEqual(
  journal.entries.map((entry) => [entry.idx, entry.tag]),
  [[0, "0000_aamd_workspace"], [1, "0001_admin_taint"]],
  "migration journal must apply 0000 then 0001",
);
requirePattern(taintSql, /ALTER TABLE workspace_users[\s\S]*?ADD COLUMN admin_tainted\s+INTEGER\s+NOT NULL\s+DEFAULT\s+0[\s\S]*?CHECK\s*\(admin_tainted IN \(0, 1\)\)/i, "0001 must add a constrained permanent admin-taint bit");
requirePattern(taintSql, /UPDATE workspace_users[\s\S]*?SET admin_tainted\s*=\s*1[\s\S]*?SELECT user_id FROM user_roles WHERE role\s*=\s*'admin'/i, "0001 must backfill every existing admin before installing enforcement triggers");
assert.ok(taintSql.indexOf("SET admin_tainted = 1") < taintSql.indexOf("CREATE TRIGGER"), "existing admins must be backfilled before triggers are created");

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

// Fresh installation: both migrations apply in order and every trigger enforces its invariant.
{
  const database = new DatabaseSync(":memory:");
  try {
    database.exec(baseSql);
    assert.equal(column(database, "workspace_users", "admin_tainted"), undefined, "0000 alone must retain the historical schema");
    database.exec(taintSql);
    const taintColumn = column(database, "workspace_users", "admin_tainted");
    assert.ok(taintColumn, "0001 must add admin_tainted on a fresh database");
    assert.equal(taintColumn.notnull, 1);
    assert.equal(String(taintColumn.dflt_value), "0");
    const triggers = triggerNames(database);
    for (const name of taintTriggers) assert.ok(triggers.has(name), `fresh database missing trigger ${name}`);

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

    database.exec(taintSql);
    assert.ok(column(database, "workspace_users", "admin_tainted"), "0001 must upgrade an existing 0000 database");
    for (const name of taintTriggers) assert.ok(triggerNames(database).has(name), `upgraded database missing trigger ${name}`);
    assert.equal(database.prepare("SELECT admin_tainted FROM workspace_users WHERE id=?").get(oldAdminId).admin_tainted, 1, "historical admin must be backfilled");
    assert.equal(database.prepare("SELECT admin_tainted FROM workspace_users WHERE id=?").get(oldReviewerId).admin_tainted, 0, "historical reviewer must remain untainted");
    assert.equal(database.prepare("SELECT admin_tainted FROM workspace_users WHERE id=?").get(oldMixedId).admin_tainted, 1, "historical mixed-role identity must fail closed as admin-tainted");

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
