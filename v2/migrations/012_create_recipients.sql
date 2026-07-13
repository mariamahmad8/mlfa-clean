CREATE TABLE recipients(
  id SERIAL PRIMARY KEY, 
  inbox_id INTEGER NOT NULL REFERENCES inboxes(id),
  label_recipient TEXT NOT NULL, 
  email TEXT NOT NULL,
  notes TEXT, 
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
); 