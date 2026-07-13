CREATE TABLE audit_log(
  id SERIAL PRIMARY KEY, 
  actor TEXT NOT NULL, 
  email TEXT NOT NULL,
  action_taken TEXT NOT NULL, 
  inbox_id INTEGER REFERENCES inboxes(id) NOT NULL, 
  created_at TIMESTAMP NOT NULL DEFAULT NOW(), 
  comment TEXT
); 

/*Figures out which user in the admin hub took what action */