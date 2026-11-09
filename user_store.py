"""Registry of people who signed up with Google.

One small SQLite table: who registered, when they first came, when they
were last seen, and how many times they have signed in. Nothing else —
no passwords (Google holds those), no analysis content, no tokens.

The database path comes from TUMAR_USERS_DB (default: users.db next to
this file; *.db is git-ignored). On hosts with an ephemeral disk, such as
Streamlit Community Cloud, point it at persistent storage.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_PATH = Path(__file__).parent / "users.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email       TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    provider    TEXT NOT NULL DEFAULT 'google',
    language    TEXT NOT NULL DEFAULT 'en',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    sign_ins    INTEGER NOT NULL DEFAULT 1
)
"""


def _db_path() -> Path:
    return Path(os.environ.get("TUMAR_USERS_DB") or _DEFAULT_PATH)


def _connect(path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _db_path())
    conn.execute(_SCHEMA)
    return conn


def record_sign_in(
    email: str,
    name: str = "",
    provider: str = "google",
    language: str = "en",
    *,
    path: Path | None = None,
) -> bool:
    """Register a new user or refresh a returning one.

    Returns True when this is the person's first sign-in (a new
    registration), False for a returning user.
    """
    email = email.strip().lower()
    if not email:
        raise ValueError("email is required")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO users (email, name, provider, language, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(email) DO NOTHING",
            (email, name, provider, language, now, now),
        )
        if cur.rowcount:
            return True
        conn.execute(
            "UPDATE users SET name = ?, last_seen = ?, sign_ins = sign_ins + 1 "
            "WHERE email = ?",
            (name, now, email),
        )
        return False


def user_count(*, path: Path | None = None) -> int:
    """How many people have registered."""
    with _connect(path) as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
