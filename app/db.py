"""SQLite storage for users and for the server-side state of refresh tokens."""
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
-- Only metadata is stored, never the token itself, so a leaked DB gives an
-- attacker nothing to replay. family_id links every token from one login.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti        TEXT PRIMARY KEY,
    family_id  TEXT NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
"""


def connect(path: str) -> sqlite3.Connection:
    # The timeout makes concurrent writers wait for the lock instead of failing.
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
