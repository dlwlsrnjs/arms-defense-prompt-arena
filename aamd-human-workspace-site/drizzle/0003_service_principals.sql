-- Distinguish authenticated human visitors from noninteractive service actors
-- while retaining task_bundles.imported_by's existing foreign key. Historical
-- rows default to human; the Worker creates one deterministic, HMAC-pseudonymous
-- service importer row only after a request passes service HMAC verification.
ALTER TABLE workspace_users
ADD COLUMN principal_type TEXT NOT NULL DEFAULT 'human'
CHECK (principal_type IN ('human', 'service'));

CREATE TRIGGER workspace_users_principal_type_no_update
BEFORE UPDATE OF principal_type ON workspace_users
WHEN OLD.principal_type <> NEW.principal_type BEGIN
  SELECT RAISE(ABORT, 'principal type is immutable');
END;

CREATE TRIGGER user_roles_service_principal_forbidden
BEFORE INSERT ON user_roles
WHEN (
  SELECT principal_type FROM workspace_users WHERE id = NEW.user_id
) = 'service' BEGIN
  SELECT RAISE(ABORT, 'service principals cannot receive human workspace roles');
END;

-- An existing human role row must not be movable onto a service principal.
-- SQLite's INSERT trigger does not run for UPDATE, even when the primary-key
-- user_id or role columns are replaced, so enforce the same invariant here.
CREATE TRIGGER user_roles_service_principal_update_forbidden
BEFORE UPDATE OF user_id, role ON user_roles
WHEN (
  SELECT principal_type FROM workspace_users WHERE id = NEW.user_id
) = 'service' BEGIN
  SELECT RAISE(ABORT, 'service principals cannot receive human workspace roles');
END;
