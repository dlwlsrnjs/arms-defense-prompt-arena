ALTER TABLE workspace_users
ADD COLUMN admin_tainted INTEGER NOT NULL DEFAULT 0
CHECK (admin_tainted IN (0, 1));

UPDATE workspace_users
SET admin_tainted = 1
WHERE id IN (SELECT user_id FROM user_roles WHERE role = 'admin');

CREATE TRIGGER workspace_users_admin_taint_no_reset
BEFORE UPDATE OF admin_tainted ON workspace_users
WHEN OLD.admin_tainted = 1 AND NEW.admin_tainted <> 1 BEGIN
  SELECT RAISE(ABORT, 'admin taint is irreversible');
END;

CREATE TRIGGER workspace_users_admin_taint_no_reviewer_mix
BEFORE UPDATE OF admin_tainted ON workspace_users
WHEN NEW.admin_tainted = 1 AND EXISTS (
  SELECT 1 FROM user_roles
  WHERE user_id = OLD.id AND role IN ('primary', 'secondary', 'adjudicator')
) BEGIN
  SELECT RAISE(ABORT, 'admin and reviewer roles are separated');
END;

CREATE TRIGGER user_roles_admin_taint_required
BEFORE INSERT ON user_roles
WHEN NEW.role = 'admin' AND (
  SELECT admin_tainted FROM workspace_users WHERE id = NEW.user_id
) <> 1 BEGIN
  SELECT RAISE(ABORT, 'admin role requires permanent admin taint');
END;

CREATE TRIGGER user_roles_tainted_reviewer_forbidden
BEFORE INSERT ON user_roles
WHEN NEW.role IN ('primary', 'secondary', 'adjudicator') AND (
  SELECT admin_tainted FROM workspace_users WHERE id = NEW.user_id
) = 1 BEGIN
  SELECT RAISE(ABORT, 'admin-tainted users cannot become reviewers');
END;
