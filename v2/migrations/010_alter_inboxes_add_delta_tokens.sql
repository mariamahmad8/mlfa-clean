-- Add delta sync token columns to inboxes. Each inbox tracks its own sync state.
-- delta_token_inbox: token for the main Inbox folder
-- delta_token_junk: token for the Junk Email folder

ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS delta_token_inbox TEXT;
ALTER TABLE inboxes ADD COLUMN IF NOT EXISTS delta_token_junk TEXT;
