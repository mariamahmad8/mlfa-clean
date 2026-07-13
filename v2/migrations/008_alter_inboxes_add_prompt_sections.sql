-- Add columns to inboxes for the global parts of the classification prompt.
-- The prompt builder concatenates: system_preamble + each active category's rule_text + global_guidelines.

ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS system_preamble TEXT NOT NULL DEFAULT '';
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS global_guidelines TEXT NOT NULL DEFAULT '';
