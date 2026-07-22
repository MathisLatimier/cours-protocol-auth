const Database = require('better-sqlite3');
const db = new Database('auth_demo.db');

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    two_factor_secret TEXT
  )
`).run();

// Migration : ajoute les colonnes 2FA si la table existait déjà sans elles
const userColumns = db.prepare(`PRAGMA table_info(users)`).all().map((col) => col.name);

if (!userColumns.includes('two_factor_enabled')) {
  db.prepare(`ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0`).run();
}

if (!userColumns.includes('two_factor_secret')) {
  db.prepare(`ALTER TABLE users ADD COLUMN two_factor_secret TEXT`).run();
}

db.prepare(`
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`).run();

module.exports = db;
