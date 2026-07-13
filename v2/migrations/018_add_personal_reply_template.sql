-- Add a second reply template for cases where GPT flags needs_personal_reply=true.
-- Falls back to reply_template if empty.
ALTER TABLE category_rules ADD COLUMN IF NOT EXISTS reply_template_personal TEXT NOT NULL DEFAULT '';
