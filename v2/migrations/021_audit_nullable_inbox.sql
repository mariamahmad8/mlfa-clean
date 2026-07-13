-- Allow audit_log entries that don't belong to a specific inbox (e.g. user management).

ALTER TABLE audit_log ALTER COLUMN inbox_id DROP NOT NULL;
