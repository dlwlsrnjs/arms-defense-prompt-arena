PRAGMA foreign_keys = ON;

CREATE TABLE workspace_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_user_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL,
  identity_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE user_roles (
  user_id INTEGER NOT NULL REFERENCES workspace_users(id),
  role TEXT NOT NULL CHECK (role IN ('admin', 'primary', 'secondary', 'adjudicator')),
  granted_by INTEGER REFERENCES workspace_users(id),
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, role)
);

CREATE TABLE task_bundles (
  bundle_id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  mode TEXT NOT NULL CHECK (mode IN ('claim_bearing_candidate', 'pilot_import')),
  claim_bearing INTEGER NOT NULL CHECK (claim_bearing IN (0, 1)),
  protocol_version TEXT NOT NULL,
  codebook_version TEXT NOT NULL,
  visibility_mask_hash TEXT NOT NULL,
  queue_hash TEXT NOT NULL,
  bundle_hash TEXT NOT NULL UNIQUE,
  task_count INTEGER NOT NULL CHECK (task_count > 0),
  imported_by INTEGER NOT NULL REFERENCES workspace_users(id),
  created_at TEXT NOT NULL
);

CREATE TABLE bundle_approvals (
  bundle_id TEXT PRIMARY KEY REFERENCES task_bundles(bundle_id),
  approved_by INTEGER NOT NULL REFERENCES workspace_users(id),
  approved_at TEXT NOT NULL,
  approval_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE tasks (
  task_id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES task_bundles(bundle_id),
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  benchmark TEXT NOT NULL CHECK (benchmark IN ('T1', 'T2', 'T3', 'T4')),
  record_handle TEXT NOT NULL,
  record_hash TEXT NOT NULL,
  public_task_json TEXT NOT NULL,
  proposal_json TEXT NOT NULL,
  proposal_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (bundle_id, ordinal),
  UNIQUE (bundle_id, record_handle)
);

CREATE TABLE task_assignments (
  assignment_id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES task_bundles(bundle_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  role TEXT NOT NULL CHECK (role IN ('primary', 'secondary', 'adjudicator')),
  user_id INTEGER NOT NULL REFERENCES workspace_users(id),
  assignment_hash TEXT NOT NULL UNIQUE,
  assigned_at TEXT NOT NULL,
  UNIQUE (task_id, role)
);

CREATE TABLE stage_events (
  event_id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES task_bundles(bundle_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  stage TEXT NOT NULL CHECK (stage IN ('initial', 'reveal', 'final', 'secondary', 'adjudicate')),
  actor_user_id INTEGER NOT NULL REFERENCES workspace_users(id),
  actor_role TEXT NOT NULL CHECK (actor_role IN ('primary', 'secondary', 'adjudicator')),
  idempotency_key_hash TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  expected_version INTEGER NOT NULL CHECK (expected_version BETWEEN 0 AND 4),
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  previous_event_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE,
  server_received_at TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  UNIQUE (task_id, stage),
  UNIQUE (actor_user_id, task_id, stage, idempotency_key_hash)
);

CREATE INDEX idx_tasks_bundle_ordinal ON tasks(bundle_id, ordinal, task_id);
CREATE INDEX idx_assignments_user_role ON task_assignments(user_id, role, assigned_at);
CREATE INDEX idx_events_task_stage ON stage_events(task_id, stage);
CREATE INDEX idx_roles_user ON user_roles(user_id, role);

CREATE TRIGGER task_bundles_no_update
BEFORE UPDATE ON task_bundles BEGIN
  SELECT RAISE(ABORT, 'task bundles are immutable');
END;

CREATE TRIGGER task_bundles_no_delete
BEFORE DELETE ON task_bundles BEGIN
  SELECT RAISE(ABORT, 'task bundles are immutable');
END;

CREATE TRIGGER tasks_no_update
BEFORE UPDATE ON tasks BEGIN
  SELECT RAISE(ABORT, 'tasks are immutable');
END;

CREATE TRIGGER bundle_approvals_no_update
BEFORE UPDATE ON bundle_approvals BEGIN
  SELECT RAISE(ABORT, 'bundle approvals are immutable');
END;

CREATE TRIGGER bundle_approvals_no_delete
BEFORE DELETE ON bundle_approvals BEGIN
  SELECT RAISE(ABORT, 'bundle approvals are immutable');
END;

CREATE TRIGGER tasks_no_delete
BEFORE DELETE ON tasks BEGIN
  SELECT RAISE(ABORT, 'tasks are immutable');
END;

CREATE TRIGGER assignments_no_update
BEFORE UPDATE ON task_assignments BEGIN
  SELECT RAISE(ABORT, 'assignments are immutable');
END;

CREATE TRIGGER assignments_no_delete
BEFORE DELETE ON task_assignments BEGIN
  SELECT RAISE(ABORT, 'assignments are immutable');
END;

CREATE TRIGGER stage_events_no_update
BEFORE UPDATE ON stage_events BEGIN
  SELECT RAISE(ABORT, 'stage events are immutable');
END;

CREATE TRIGGER stage_events_no_delete
BEFORE DELETE ON stage_events BEGIN
  SELECT RAISE(ABORT, 'stage events are immutable');
END;
