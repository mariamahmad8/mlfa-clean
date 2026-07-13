CREATE TABLE pending_queue(
  id SERIAL PRIMARY KEY NOT NULL, 
  inbox_id INTEGER NOT NULL REFERENCES inboxes(id), 
  message_id TEXT NOT NULL, 
  subject_email TEXT NOT NULL, 
  body_email TEXT NOT NULL, 
  sender TEXT NOT NULL, 
  received_at TIMESTAMP NOT NULL, 
  classification  JSONB NOT NULL DEFAULT '[]', 
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);