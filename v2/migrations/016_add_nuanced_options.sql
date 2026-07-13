-- Add nuanced per-inbox and per-category options extracted from the monolith.

-- Per-inbox settings
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS internal_domains JSONB NOT NULL DEFAULT '[]';
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS backfill_days INTEGER NOT NULL DEFAULT 2;
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS use_thread_context BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS internal_reply_bridge_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS internal_reply_external_prefix TEXT NOT NULL DEFAULT '[EXTERNAL]';
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS internal_reply_internal_prefix TEXT NOT NULL DEFAULT '[INTERNAL]';

-- Per-category flags
ALTER TABLE category_rules ADD COLUMN IF NOT EXISTS skip_if_internal BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE category_rules ADD COLUMN IF NOT EXISTS delete_immediately BOOLEAN NOT NULL DEFAULT false;

-- Seed MLFA's internal domain
UPDATE inboxes SET internal_domains = '["mlfa.org"]'::jsonb WHERE id = 1;

-- Seed the "delete_internal" and "auto_reply" categories to actually delete immediately
UPDATE category_rules SET delete_immediately = true WHERE key_for_category IN ('delete_internal', 'auto_reply');
