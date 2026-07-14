-- Track how long each pipeline action took so we can show efficiency stats.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS duration_ms INTEGER;
