function normalized(sql) { return sql.replace(/\s+/g, " ").trim(); }
function copy(value) { return value === undefined ? undefined : JSON.parse(JSON.stringify(value)); }

class MockStatement {
  constructor(database, sql) { this.database = database; this.sql = normalized(sql); this.values = []; }
  bind(...values) { this.values = values; return this; }
  async first(column) {
    const row = this.database.select(this.sql, this.values)[0] ?? null;
    return column && row ? row[column] : copy(row);
  }
  async all() { return { success: true, results: copy(this.database.select(this.sql, this.values)) }; }
  async run() { return this.database.mutate(this.sql, this.values); }
}

export class MockD1 {
  constructor() {
    this.users = [];
    this.roles = [];
    this.bundles = [];
    this.tasks = [];
    this.assignments = [];
    this.events = [];
    this.nextUserId = 1;
  }

  prepare(sql) { return new MockStatement(this, sql); }
  async batch(statements) {
    const snapshot = copy({
      users: this.users, roles: this.roles, bundles: this.bundles,
      tasks: this.tasks, assignments: this.assignments, events: this.events, nextUserId: this.nextUserId,
    });
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      return results;
    } catch (error) {
      Object.assign(this, snapshot);
      throw error;
    }
  }

  mutate(sql, values) {
    if (sql.startsWith("INSERT INTO workspace_users")) {
      const [auth_user_id, email, email_normalized, identity_hash, created_at, last_seen_at] = values;
      let user = this.users.find((entry) => entry.auth_user_id === auth_user_id);
      if (user) Object.assign(user, { email, email_normalized, last_seen_at });
      else {
        user = { id: this.nextUserId++, auth_user_id, email, email_normalized, identity_hash, admin_tainted: 0, created_at, last_seen_at };
        this.users.push(user);
      }
      return { success: true, meta: { changes: 1 } };
    }

    if (sql.startsWith("INSERT OR IGNORE INTO user_roles")) {
      const [user_id, created_at] = values;
      const user = this.users.find((entry) => entry.id === user_id);
      if (!user || user.admin_tainted !== 1) throw new Error("admin role requires permanent admin taint");
      if (!this.roles.some((entry) => entry.user_id === user_id && entry.role === "admin")) {
        this.roles.push({ user_id, role: "admin", granted_by: null, created_at });
        return { success: true, meta: { changes: 1 } };
      }
      return { success: true, meta: { changes: 0 } };
    }

    if (sql.startsWith("INSERT INTO user_roles")) {
      const [user_id, role, granted_by, created_at] = values;
      const user = this.users.find((entry) => entry.id === user_id);
      if (role === "admin" && (!user || user.admin_tainted !== 1)) throw new Error("admin role requires permanent admin taint");
      if (["primary", "secondary", "adjudicator"].includes(role) && user?.admin_tainted === 1) throw new Error("admin-tainted users cannot become reviewers");
      if (this.roles.some((entry) => entry.user_id === user_id && entry.role === role)) throw new Error("UNIQUE constraint failed: user_roles");
      this.roles.push({ user_id, role, granted_by, created_at });
      return { success: true, meta: { changes: 1 } };
    }

    if (sql.startsWith("DELETE FROM user_roles")) {
      const [userId] = values; const before = this.roles.length;
      this.roles = this.roles.filter((entry) => entry.user_id !== userId);
      return { success: true, meta: { changes: before - this.roles.length } };
    }

    if (sql === "UPDATE workspace_users SET admin_tainted=1 WHERE id=? AND admin_tainted=0") {
      const user = this.users.find((entry) => entry.id === values[0]);
      if (!user || user.admin_tainted === 1) return { success: true, meta: { changes: 0 } };
      if (this.roles.some((entry) => entry.user_id === user.id && ["primary", "secondary", "adjudicator"].includes(entry.role))) throw new Error("admin and reviewer roles are separated");
      user.admin_tainted = 1;
      return { success: true, meta: { changes: 1 } };
    }

    if (sql.startsWith("INSERT INTO task_bundles")) {
      const columns = ["bundle_id", "schema_version", "mode", "claim_bearing", "protocol_version", "codebook_version", "visibility_mask_hash", "queue_hash", "bundle_hash", "task_count", "imported_by", "created_at"];
      const row = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
      if (this.bundles.some((entry) => entry.bundle_id === row.bundle_id || entry.bundle_hash === row.bundle_hash)) throw new Error("UNIQUE constraint failed: task_bundles");
      this.bundles.push(row); return { success: true, meta: { changes: 1 } };
    }

    if (sql.startsWith("INSERT INTO tasks")) {
      const columns = ["task_id", "bundle_id", "ordinal", "benchmark", "record_handle", "record_hash", "public_task_json", "proposal_json", "proposal_hash", "created_at"];
      const row = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
      if (this.tasks.some((entry) => entry.task_id === row.task_id)) throw new Error("UNIQUE constraint failed: tasks");
      this.tasks.push(row); return { success: true, meta: { changes: 1 } };
    }

    if (sql.startsWith("INSERT OR IGNORE INTO task_assignments")) {
      const columns = ["assignment_id", "bundle_id", "task_id", "role", "user_id", "assignment_hash", "assigned_at"];
      const row = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
      if (this.assignments.some((entry) => entry.task_id === row.task_id && entry.role === row.role)) return { success: true, meta: { changes: 0 } };
      this.assignments.push(row); return { success: true, meta: { changes: 1 } };
    }

    if (sql.startsWith("INSERT INTO stage_events")) {
      const columns = ["event_id", "bundle_id", "task_id", "stage", "actor_user_id", "actor_role", "idempotency_key_hash", "request_hash", "expected_version", "payload_json", "payload_hash", "previous_event_hash", "event_hash", "server_received_at", "receipt_json"];
      const row = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
      if (this.events.some((entry) => entry.task_id === row.task_id && entry.stage === row.stage)) throw new Error("UNIQUE constraint failed: stage_events.task_id, stage_events.stage");
      this.events.push(row); return { success: true, meta: { changes: 1 } };
    }

    throw new Error(`MockD1 unsupported mutation: ${sql}`);
  }

  select(sql, values) {
    if (sql === "SELECT id,auth_user_id,email,identity_hash,admin_tainted,created_at FROM workspace_users WHERE auth_user_id=?") {
      const row = this.users.find((entry) => entry.auth_user_id === values[0]); return row ? [pick(row, ["id", "auth_user_id", "email", "identity_hash", "admin_tainted", "created_at"])] : [];
    }
    if (sql === "SELECT role FROM user_roles WHERE user_id=? ORDER BY role") {
      return this.roles.filter((entry) => entry.user_id === values[0]).sort(by("role")).map((entry) => ({ role: entry.role }));
    }
    if (sql === "SELECT id,identity_hash,admin_tainted FROM workspace_users WHERE auth_user_id=?") {
      const row = this.users.find((entry) => entry.auth_user_id === values[0]); return row ? [pick(row, ["id", "identity_hash", "admin_tainted"])] : [];
    }
    if (sql === "SELECT role FROM user_roles WHERE user_id=? AND role IN ('primary','secondary','adjudicator') LIMIT 1") {
      const role = this.roles.find((entry) => entry.user_id === values[0] && ["primary", "secondary", "adjudicator"].includes(entry.role));
      return role ? [{ role: role.role }] : [];
    }
    if (sql === "SELECT COUNT(*) AS count FROM task_assignments WHERE user_id=?") return [{ count: this.assignments.filter((entry) => entry.user_id === values[0]).length }];
    if (sql === "SELECT bundle_id FROM task_bundles WHERE bundle_id=?") return this.bundles.filter((entry) => entry.bundle_id === values[0]).map((entry) => ({ bundle_id: entry.bundle_id }));
    if (sql === "SELECT protocol_version FROM task_bundles WHERE bundle_id=?") return this.bundles.filter((entry) => entry.bundle_id === values[0]).map((entry) => ({ protocol_version: entry.protocol_version }));
    if (sql === "SELECT bundle_id,bundle_hash,imported_by FROM task_bundles WHERE bundle_id=?") return this.bundles.filter((entry) => entry.bundle_id === values[0]).map((entry) => pick(entry, ["bundle_id", "bundle_hash", "imported_by"]));
    if (sql === "SELECT bundle_id FROM task_bundles ORDER BY created_at,bundle_id LIMIT 1") return this.bundles.slice().sort(by("created_at", "bundle_id")).slice(0, 1).map((entry) => ({ bundle_id: entry.bundle_id }));

    if (sql.startsWith("SELECT b.bundle_id,b.mode,b.claim_bearing,b.protocol_version,b.codebook_version") && sql.includes("GROUP BY b.bundle_id ORDER BY b.created_at,b.bundle_id")) {
      return this.bundles.slice().sort(by("created_at", "bundle_id")).map((bundle) => {
        const adjudicated = new Set(this.events.filter((entry) => entry.bundle_id === bundle.bundle_id && entry.stage === "adjudicate").map((entry) => entry.task_id)).size;
        return {
          ...pick(bundle, ["bundle_id", "mode", "claim_bearing", "protocol_version", "codebook_version", "bundle_hash", "task_count", "created_at"]),
          status: "active",
          adjudicated,
        };
      });
    }
    if (sql === "SELECT role,COUNT(*) AS assigned FROM task_assignments WHERE user_id=? GROUP BY role ORDER BY role") {
      const counts = new Map();
      for (const entry of this.assignments.filter((item) => item.user_id === values[0])) counts.set(entry.role, (counts.get(entry.role) || 0) + 1);
      return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([role, assigned]) => ({ role, assigned }));
    }

    if (sql.startsWith("SELECT stage,payload_json,receipt_json,event_hash,server_received_at FROM stage_events")) {
      return orderEvents(this.events.filter((entry) => entry.task_id === values[0])).map((entry) => pick(entry, ["stage", "payload_json", "receipt_json", "event_hash", "server_received_at"]));
    }
    if (sql.startsWith("SELECT actor_user_id,idempotency_key_hash,request_hash,receipt_json FROM stage_events")) {
      return this.events.filter((entry) => entry.task_id === values[0] && entry.stage === values[1]).map((entry) => pick(entry, ["actor_user_id", "idempotency_key_hash", "request_hash", "receipt_json"]));
    }
    if (sql === "SELECT COUNT(*) AS count FROM stage_events WHERE task_id=?") return [{ count: this.events.filter((entry) => entry.task_id === values[0]).length }];
    if (/SELECT event_hash FROM stage_events WHERE task_id=\? AND stage=(?:\?|'.+')/.test(sql)) {
      const literal = sql.match(/stage='([^']+)'/); const stage = literal ? literal[1] : values[1];
      return this.events.filter((entry) => entry.task_id === values[0] && entry.stage === stage).map((entry) => ({ event_hash: entry.event_hash }));
    }

    if (sql.startsWith("SELECT a.assignment_id,a.task_id,a.bundle_id,a.role,a.assignment_hash,a.assigned_at FROM task_assignments a LEFT JOIN stage_events e")) {
      const [completion, userId, role, bundleId] = values;
      return this.assignments.filter((entry) => entry.user_id === userId && entry.role === role && entry.bundle_id === bundleId && !this.events.some((event) => event.task_id === entry.task_id && event.stage === completion)).sort(by("assigned_at", "task_id")).slice(0, 1).map(copy);
    }

    if (sql.startsWith("SELECT t.task_id FROM tasks t LEFT JOIN task_assignments a") && sql.includes("a.role='primary'")) {
      return this.tasks.filter((task) => task.bundle_id === values[0] && !this.assignments.some((entry) => entry.task_id === task.task_id && entry.role === "primary")).sort(by("ordinal", "task_id")).map((task) => ({ task_id: task.task_id }));
    }
    if (sql.startsWith("SELECT t.task_id FROM tasks t JOIN stage_events f") && sql.includes("a.role='secondary'")) {
      const [bundleId, userId] = values;
      return this.tasks.filter((task) => task.bundle_id === bundleId && this.events.some((event) => event.task_id === task.task_id && event.stage === "final") && this.assignments.some((entry) => entry.task_id === task.task_id && entry.role === "primary" && entry.user_id !== userId) && !this.assignments.some((entry) => entry.task_id === task.task_id && entry.role === "secondary")).sort(by("ordinal", "task_id")).map((task) => ({ task_id: task.task_id }));
    }
    if (sql.startsWith("SELECT t.task_id FROM tasks t JOIN stage_events s") && sql.includes("a.role='adjudicator'")) {
      const [bundleId, userIdA, userIdB] = values;
      return this.tasks.filter((task) => task.bundle_id === bundleId && this.events.some((event) => event.task_id === task.task_id && event.stage === "secondary") && this.assignments.some((entry) => entry.task_id === task.task_id && entry.role === "primary" && entry.user_id !== userIdA) && this.assignments.some((entry) => entry.task_id === task.task_id && entry.role === "secondary" && entry.user_id !== userIdB) && !this.assignments.some((entry) => entry.task_id === task.task_id && entry.role === "adjudicator")).sort(by("ordinal", "task_id")).map((task) => ({ task_id: task.task_id }));
    }

    if (sql.startsWith("SELECT a.assignment_id,a.task_id,a.bundle_id,a.role,a.assignment_hash,a.assigned_at,t.ordinal,t.benchmark FROM task_assignments")) {
      const [userId, role, bundleId] = values;
      return this.assignments.filter((entry) => entry.user_id === userId && entry.role === role && entry.bundle_id === bundleId).map((entry) => ({ ...copy(entry), ordinal: taskById(this, entry.task_id).ordinal, benchmark: taskById(this, entry.task_id).benchmark })).sort(by("assigned_at", "task_id"));
    }
    if (sql.startsWith("SELECT a.assignment_id,a.bundle_id,a.task_id,a.role,a.assignment_hash,a.assigned_at,t.public_task_json")) {
      const [taskId, role, userId] = values; const assignment = this.assignments.find((entry) => entry.task_id === taskId && entry.role === role && entry.user_id === userId);
      if (!assignment) return [];
      const task = taskById(this, taskId); return [{ ...copy(assignment), public_task_json: task.public_task_json, proposal_json: task.proposal_json, proposal_hash: task.proposal_hash, benchmark: task.benchmark }];
    }

    if (sql.startsWith("SELECT b.bundle_id,b.schema_version,b.mode,b.claim_bearing") && sql.includes("JOIN workspace_users u ON u.id=b.imported_by")) {
      const bundle = this.bundles.find((entry) => entry.bundle_id === values[0]);
      if (!bundle) return [];
      const importer = this.users.find((entry) => entry.id === bundle.imported_by);
      return [{ ...pick(bundle, ["bundle_id", "schema_version", "mode", "claim_bearing", "protocol_version", "codebook_version", "visibility_mask_hash", "queue_hash", "bundle_hash", "task_count", "created_at"]), importer_hash: importer?.identity_hash }];
    }
    if (sql.startsWith("SELECT t.task_id,t.ordinal,t.public_task_json,t.proposal_json")) {
      return this.tasks.filter((task) => task.bundle_id === values[0]).sort(by("ordinal", "task_id")).map((task) => ({ ...pick(task, ["task_id", "ordinal", "public_task_json", "proposal_json", "proposal_hash"]), revealed: this.events.some((event) => event.task_id === task.task_id && event.stage === "reveal") ? 1 : 0 }));
    }
    if (sql.startsWith("SELECT e.event_id,e.task_id,e.stage,u.identity_hash AS actor_hash")) {
      return orderEvents(this.events.filter((event) => event.bundle_id === values[0])).map((event) => ({ ...pick(event, ["event_id", "task_id", "stage", "actor_role", "idempotency_key_hash", "request_hash", "expected_version", "payload_json", "payload_hash", "previous_event_hash", "event_hash", "server_received_at", "receipt_json"]), actor_hash: this.users.find((user) => user.id === event.actor_user_id).identity_hash }));
    }
    if (sql.startsWith("SELECT a.assignment_id,a.task_id,a.role,u.identity_hash AS actor_hash")) {
      return this.assignments.filter((entry) => entry.bundle_id === values[0]).sort(by("task_id", "role")).map((entry) => ({ ...pick(entry, ["assignment_id", "task_id", "role", "assignment_hash", "assigned_at"]), actor_hash: this.users.find((user) => user.id === entry.user_id).identity_hash }));
    }

    throw new Error(`MockD1 unsupported query: ${sql}`);
  }
}

function pick(row, keys) { return Object.fromEntries(keys.map((key) => [key, row[key]])); }
function by(...keys) { return (left, right) => { for (const key of keys) { const result = String(left[key]).localeCompare(String(right[key])); if (result) return result; } return 0; }; }
function taskById(database, id) { return database.tasks.find((entry) => entry.task_id === id); }
const STAGE_ORDER = ["initial", "reveal", "final", "secondary", "adjudicate"];
function orderEvents(events) { return events.slice().sort((left, right) => left.task_id.localeCompare(right.task_id) || STAGE_ORDER.indexOf(left.stage) - STAGE_ORDER.indexOf(right.stage)); }
