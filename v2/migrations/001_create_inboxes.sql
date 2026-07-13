  CREATE TABLE inboxes (
      id SERIAL PRIMARY KEY,
      email_to_watch TEXT NOT NULL,
      display_name TEXT NOT NULL,
      automation_mode BOOLEAN NOT NULL DEFAULT false,
      blocked_senders JSONB NOT NULL DEFAULT '[]',
      skip_sender_pairs JSONB NOT NULL DEFAULT '[]'
  );