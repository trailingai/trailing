ALTER TABLE action_log
ADD COLUMN IF NOT EXISTS project_id TEXT;

CREATE INDEX IF NOT EXISTS idx_action_log_project_scope
ON action_log (org_id, project_id, sequence);
