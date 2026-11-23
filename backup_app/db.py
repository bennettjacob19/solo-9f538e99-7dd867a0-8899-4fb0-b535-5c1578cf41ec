"""SQLite connection helpers and schema management.

The database lives next to the master-key files (keystore volume), never on
the volume that holds ciphertext blobs.  WAL mode plus a short busy timeout
let the request workers and the background rotation thread share the file.
"""

import sqlite3

from . import crypto

SCHEMA = """
CREATE TABLE IF NOT EXISTS master_keys (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('active', 'retired'))
);

CREATE TABLE IF NOT EXISTS backups (
    id           TEXT PRIMARY KEY,
    filename     TEXT NOT NULL,
    blob_path    TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wrapped_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_id   TEXT NOT NULL REFERENCES backups(id) ON DELETE CASCADE,
    kek_id      TEXT NOT NULL REFERENCES master_keys(id),
    wrapped_dek BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (backup_id, kek_id)
);

CREATE TABLE IF NOT EXISTS rotation_jobs (
    id              TEXT PRIMARY KEY,
    old_kek_id      TEXT REFERENCES master_keys(id) ON DELETE SET NULL,
    new_kek_id      TEXT REFERENCES master_keys(id) ON DELETE SET NULL,
    state           TEXT NOT NULL CHECK (state IN ('running', 'completed')),
    total_backups   INTEGER NOT NULL,
    processed       INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    completed_at    TEXT
);

-- Per-backup "resume preparation" state.  The prepared chunk file itself
-- lives on the ciphertext volume next to the original blob; this table only
-- tracks metadata.  A backup is served from prepared chunks only while its
-- row says 'ready'.
CREATE TABLE IF NOT EXISTS resume_preps (
    backup_id    TEXT PRIMARY KEY REFERENCES backups(id) ON DELETE CASCADE,
    state        TEXT NOT NULL CHECK (state IN ('preparing', 'ready', 'failed')),
    chunk_size   INTEGER NOT NULL,
    chunk_count  INTEGER NOT NULL DEFAULT 0,
    prep_path    TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    error        TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

-- Tiny key/value store for service-wide toggles (e.g. pausing preparation).
CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wrapped_backup ON wrapped_keys(backup_id);
CREATE INDEX IF NOT EXISTS idx_wrapped_kek ON wrapped_keys(kek_id);
CREATE INDEX IF NOT EXISTS idx_prep_state ON resume_preps(state);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def check_crypto_import() -> None:
    """Fail fast at startup if the crypto backend is unusable."""
    probe = crypto.generate_key()
    blob = crypto.encrypt(probe, b"healthcheck", b"aad")
    assert crypto.decrypt(probe, blob, b"aad") == b"healthcheck"
