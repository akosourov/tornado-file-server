CREATE TABLE IF NOT EXISTS user (
  id INTEGER NOT NULL PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  hashed_password VARCHAR(100) NOT NULL
);
