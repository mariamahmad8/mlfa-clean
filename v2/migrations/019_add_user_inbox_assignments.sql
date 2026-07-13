-- Which inboxes a reviewer has access to. Admins see all; reviewers only see their assigned inboxes.
-- Stored as JSONB array of inbox IDs on the user row.

ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_inbox_ids JSONB NOT NULL DEFAULT '[]';
