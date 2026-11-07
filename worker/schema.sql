PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  metadata TEXT NOT NULL,
  nonce_prefix TEXT NOT NULL,
  chunk_size INTEGER NOT NULL,
  chunk_count INTEGER NOT NULL,
  plaintext_size INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'deleting')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipients (
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  envelope TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS uploaded_chunks (
  share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  byte_length INTEGER NOT NULL,
  PRIMARY KEY (share_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS recipients_share_id_idx ON recipients(share_id);
