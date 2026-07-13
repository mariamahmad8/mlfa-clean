CREATE TABLE users(
  id SERIAL PRIMARY KEY, 
  email TEXT UNIQUE NOT NULL,
  display_name TEXT, 
  microsoft_oid TEXT UNIQUE, 
  role_user TEXT NOT NULL DEFAULT 'reviewer', 
  last_login_at TIMESTAMP, 
  created_at  TIMESTAMP NOT NULL DEFAULT NOW(), 
  active  BOOLEAN NOT NULL DEFAULT true
);