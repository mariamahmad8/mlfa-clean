-- Additive foundation for a zero-downtime secure queue migration.
-- This migration deliberately does not erase or transform existing rows.

ALTER TABLE inboxes
    ADD COLUMN IF NOT EXISTS send_to_openai BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS retention_days INTEGER NOT NULL DEFAULT 30;

ALTER TABLE inboxes
    DROP CONSTRAINT IF EXISTS inboxes_retention_days_range;

ALTER TABLE inboxes
    ADD CONSTRAINT inboxes_retention_days_range
    CHECK (retention_days BETWEEN 1 AND 365);

ALTER TABLE pending_queue
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS sensitive_payload_ciphertext TEXT,
    ADD COLUMN IF NOT EXISTS encryption_key_version INTEGER;

UPDATE pending_queue pq
SET expires_at = pq.created_at + make_interval(
    days => COALESCE(
        (SELECT i.retention_days FROM inboxes i WHERE i.id = pq.inbox_id),
        30
    )
)
WHERE pq.expires_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_pending_queue_inbox_expires_at
    ON pending_queue (inbox_id, expires_at);
