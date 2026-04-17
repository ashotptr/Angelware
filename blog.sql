-- AUA CS 232/337 Honeypot Blog DB initialisation
-- Mirrors Doc 2 §3.3: "We use a blog.sql file to initialise MySQL
-- including importing initial blog and user information."
-- Deliberately includes SQL injection surface (no parameterisation).

CREATE DATABASE IF NOT EXISTS corporate_blog;
USE corporate_blog;

CREATE TABLE IF NOT EXISTS users (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  email    VARCHAR(120) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role     ENUM('admin','user') DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS posts (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  title      VARCHAR(255),
  body       TEXT,
  author_id  INT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Bait credentials that bots may try to enumerate
INSERT IGNORE INTO users (email, password, role) VALUES
  ('admin@corporate.com',  MD5('admin123'), 'admin'),
  ('webmaster@corp.com',   MD5('password'), 'admin'),
  ('support@corp.com',     MD5('support1'), 'user');

INSERT IGNORE INTO posts (title, body, author_id) VALUES
  ('Q3 Financials',    'Revenue figures for Q3 2023...', 1),
  ('Staff Directory',  'See /etc/passwd for full listing...', 1),
  ('VPN Credentials',  'Backup credentials stored in /tmp/creds.txt', 2);
