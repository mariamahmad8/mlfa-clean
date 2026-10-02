-- Protected inboxes are hidden from restricted administrators unless a full
-- administrator explicitly assigns that inbox to them.
ALTER TABLE inboxes
ADD COLUMN IF NOT EXISTS protected BOOLEAN NOT NULL DEFAULT FALSE;

