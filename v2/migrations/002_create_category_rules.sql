  CREATE TABLE category_rules (
    id SERIAL PRIMARY KEY,
    inbox_id INTEGER NOT NULL REFERENCES inboxes(id),
    rule_text TEXT NOT NULL, 
    mark_read BOOLEAN NOT NULL, 
    skip_email BOOLEAN NOT NULL, 
    auto_reply_safeguard BOOLEAN NOT NULL, 
    folder_path TEXT NOT NULL, 
    reply_template TEXT, 
    amount_threshold NUMERIC,
    key_for_category TEXT NOT NULL, 
    emails_to_forward  JSONB NOT NULL DEFAULT '[]'
  ); 