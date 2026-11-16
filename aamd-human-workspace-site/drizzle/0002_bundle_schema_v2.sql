-- RCAT-7 V1.1 bundles use schema_version=2. Rebuild only the parent table so
-- historical version-1 bundles and all child rows retain their original keys.
-- D1 runs migrations inside an implicit transaction, so foreign_keys cannot be
-- toggled. Defer checks until the rebuilt parent exists again.
PRAGMA defer_foreign_keys = ON;

DROP TRIGGER IF EXISTS task_bundles_no_update;
DROP TRIGGER IF EXISTS task_bundles_no_delete;

CREATE TABLE task_bundles_schema_v2 (
  bundle_id TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
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

INSERT INTO task_bundles_schema_v2 (
  bundle_id, schema_version, mode, claim_bearing, protocol_version,
  codebook_version, visibility_mask_hash, queue_hash, bundle_hash,
  task_count, imported_by, created_at
)
SELECT
  bundle_id, schema_version, mode, claim_bearing, protocol_version,
  codebook_version, visibility_mask_hash, queue_hash, bundle_hash,
  task_count, imported_by, created_at
FROM task_bundles;

DROP TABLE task_bundles;
ALTER TABLE task_bundles_schema_v2 RENAME TO task_bundles;

CREATE TRIGGER task_bundles_no_update
BEFORE UPDATE ON task_bundles BEGIN
  SELECT RAISE(ABORT, 'task bundles are immutable');
END;

CREATE TRIGGER task_bundles_no_delete
BEFORE DELETE ON task_bundles BEGIN
  SELECT RAISE(ABORT, 'task bundles are immutable');
END;

-- The final schema has the original parent name and copied keys. Check it, then
-- clear SQLite's transient deferred violation created by dropping the old parent.
PRAGMA foreign_key_check;
PRAGMA defer_foreign_keys = OFF;
