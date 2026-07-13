CREATE TABLE reply_templates(
  id SERIAL PRIMARY KEY, 
  inbox_id INTEGER NOT NULL REFERENCES inboxes(id), 
  name_template TEXT NOT NULL,
  body_html TEXT NOT NULL, 
  active BOOLEAN NOT NULL DEFAULT true, 
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
); 