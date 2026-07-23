const Database = require('better-sqlite3');
const db = new Database('auth_demo.db');

/**
 * Un même provider_id (ex. "12345") sur GitHub / Google / Discord
 * désigne trois utilisateurs distincts → contrainte UNIQUE(provider, provider_id).
 * provider ∈ { local, google, github, discord }
 */
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_hash TEXT,
    provider TEXT NOT NULL DEFAULT 'local',
    provider_id TEXT NOT NULL,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    two_factor_secret TEXT,
    UNIQUE(provider, provider_id)
  )
`).run();

const userColumns = db.prepare(`PRAGMA table_info(users)`).all().map((col) => col.name);

// Migration depuis l'ancien schéma (username UNIQUE, sans provider)
if (!userColumns.includes('provider') || !userColumns.includes('provider_id')) {
  // FK refresh_tokens → users : désactiver le temps de recréer la table
  db.pragma('foreign_keys = OFF');
  db.exec(`
    BEGIN;

    CREATE TABLE users_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password_hash TEXT,
      provider TEXT NOT NULL DEFAULT 'local',
      provider_id TEXT NOT NULL,
      two_factor_enabled INTEGER NOT NULL DEFAULT 0,
      two_factor_secret TEXT,
      UNIQUE(provider, provider_id)
    );

    INSERT INTO users_new (id, username, password_hash, provider, provider_id, two_factor_enabled, two_factor_secret)
    SELECT
      id,
      username,
      password_hash,
      'local',
      username,
      COALESCE(two_factor_enabled, 0),
      two_factor_secret
    FROM users;

    DROP TABLE users;
    ALTER TABLE users_new RENAME TO users;

    COMMIT;
  `);
  db.pragma('foreign_keys = ON');
} else {
  if (!userColumns.includes('two_factor_enabled')) {
    db.prepare(`ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0`).run();
  }

  if (!userColumns.includes('two_factor_secret')) {
    db.prepare(`ALTER TABLE users ADD COLUMN two_factor_secret TEXT`).run();
  }
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

/**
 * Upsert OAuth : crée l'utilisateur ou met à jour le username
 * si le couple (provider, provider_id) existe déjà.
 *
 * Ex. github/12345 et google/12345 → deux lignes distinctes.
 */
db.upsertOAuthUser = db.prepare(`
  INSERT INTO users (username, provider, provider_id)
  VALUES (@username, @provider, @provider_id)
  ON CONFLICT(provider, provider_id) DO UPDATE SET
    username = excluded.username
  RETURNING *
`);

module.exports = db;
