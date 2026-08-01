"""API key management and usage metering, backed by SQLite.

Keys move from a static environment variable to real records that can
be issued, listed, rotated and revoked, and every call is metered so a
customer can be given a quota and, eventually, a bill.

Two decisions shape everything here.

**Keys are stored hashed, never in plaintext.** A leaked database
should not be a set of working credentials. Only a SHA-256 digest is
kept, plus a short prefix so a key can be recognized in a list without
being usable. The secret is shown once, at issue time, and cannot be
recovered afterwards — if it is lost, rotate it. A fast hash is right
here, unlike for user passwords: these keys are 256 bits of randomness
we generated, so there is no dictionary to run against them.

**The usage table has nowhere to put user content.** There is no
column for the message, the URL, or the report preview — the privacy
promise is enforced by the shape of the schema rather than by
remembering to be careful at each call site. What is recorded is
metadata: which key, when, which endpoint, what kind of subject, the
verdict, the status and the duration.

SQLite is deliberate: no server to run, no dependency to add, and
transactions that survive a crash. It is single-node, which is the
same honest limitation the rate limiter carries; the repository
functions below are the seam where Postgres would replace it.
"""

import hashlib
import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Recognizable, greppable, and obviously ours if one ever leaks into a
# log or a screenshot — which is also what makes automated secret
# scanners able to spot it.
KEY_PREFIX = "tmr_live_"

# Characters of the key kept in clear for display. Enough to identify
# a key in a list, far too few to use.
DISPLAY_LENGTH = len(KEY_PREFIX) + 6

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash      TEXT    NOT NULL UNIQUE,
    display       TEXT    NOT NULL,
    owner         TEXT    NOT NULL,
    label         TEXT    NOT NULL DEFAULT '',
    monthly_quota INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    revoked_at    TEXT,
    rotated_to    INTEGER REFERENCES api_keys(id)
);

CREATE TABLE IF NOT EXISTS usage_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id      INTEGER REFERENCES api_keys(id),
    created_at  TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL,
    kind        TEXT    NOT NULL DEFAULT '',
    verdict     TEXT    NOT NULL DEFAULT '',
    status      INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS usage_by_key_time
    ON usage_events (key_id, created_at);
"""


@dataclass(frozen=True)
class ApiKey:
    """A key record. Never carries the secret itself."""

    id: int
    display: str
    owner: str
    label: str
    monthly_quota: int  # 0 means unlimited
    created_at: str
    revoked_at: str | None
    rotated_to: int | None

    @property
    def active(self) -> bool:
        return self.revoked_at is None


@dataclass(frozen=True)
class IssuedKey:
    """A newly issued key, including the secret — shown once."""

    record: ApiKey
    secret: str


def hash_key(secret: str) -> str:
    """The stored form of a key."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def default_path() -> Path:
    """Where the database lives unless told otherwise."""
    return Path(os.environ.get("TUMAR_DB_PATH", "tumar.db"))


@contextmanager
def connect(path: Path | str | None = None):
    """Open a connection with the schema in place.

    A connection per operation: SQLite writes are sub-millisecond
    locally, and short-lived connections keep the locking story simple.
    """
    target = Path(path) if path else default_path()
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(target)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_SCHEMA)
        yield connection
        connection.commit()
    finally:
        connection.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _to_key(row: sqlite3.Row) -> ApiKey:
    return ApiKey(
        id=row["id"],
        display=row["display"],
        owner=row["owner"],
        label=row["label"],
        monthly_quota=row["monthly_quota"],
        created_at=row["created_at"],
        revoked_at=row["revoked_at"],
        rotated_to=row["rotated_to"],
    )


# --- Key lifecycle ---


def issue(
    owner: str,
    label: str = "",
    monthly_quota: int = 0,
    path: Path | str | None = None,
) -> IssuedKey:
    """Create a key and return it once, in full."""
    if not owner.strip():
        raise ValueError("a key must belong to someone")
    secret = KEY_PREFIX + secrets.token_urlsafe(32)
    with connect(path) as connection:
        cursor = connection.execute(
            "INSERT INTO api_keys (key_hash, display, owner, label, "
            "monthly_quota, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                hash_key(secret),
                secret[:DISPLAY_LENGTH] + "…",
                owner.strip(),
                label.strip(),
                max(0, monthly_quota),
                _now(),
            ),
        )
        row = connection.execute(
            "SELECT * FROM api_keys WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
    return IssuedKey(record=_to_key(row), secret=secret)


def verify(secret: str, path: Path | str | None = None) -> ApiKey | None:
    """Return the active key matching this secret, if any.

    Lookup is by hash, so a wrong key is rejected by a failed index
    lookup rather than by comparing against every record — there is no
    per-candidate timing to observe.
    """
    if not secret:
        return None
    with connect(path) as connection:
        row = connection.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            (hash_key(secret),),
        ).fetchone()
    return _to_key(row) if row else None


def revoke(key_id: int, path: Path | str | None = None) -> bool:
    """Disable a key immediately. Returns False if it was already gone."""
    with connect(path) as connection:
        cursor = connection.execute(
            "UPDATE api_keys SET revoked_at = ? "
            "WHERE id = ? AND revoked_at IS NULL",
            (_now(), key_id),
        )
        return cursor.rowcount > 0


def rotate(key_id: int, path: Path | str | None = None) -> IssuedKey | None:
    """Replace a key with a fresh one, carrying its owner and quota.

    The old key stops working at once. That is the right default for a
    key believed to be compromised — a grace period is a convenience
    for planned rotation and a liability for an urgent one. Callers who
    want overlap can issue first and revoke when ready.
    """
    with connect(path) as connection:
        row = connection.execute(
            "SELECT * FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
    if row is None:
        return None
    old = _to_key(row)
    replacement = issue(old.owner, old.label, old.monthly_quota, path)
    with connect(path) as connection:
        connection.execute(
            "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, ?), "
            "rotated_to = ? WHERE id = ?",
            (_now(), replacement.record.id, key_id),
        )
    return replacement


def list_keys(path: Path | str | None = None) -> list[ApiKey]:
    """Every key, newest first. Secrets are not recoverable."""
    with connect(path) as connection:
        rows = connection.execute(
            "SELECT * FROM api_keys ORDER BY id DESC"
        ).fetchall()
    return [_to_key(row) for row in rows]


# --- Metering ---


def record_usage(
    key_id: int | None,
    endpoint: str,
    status: int,
    kind: str = "",
    verdict: str = "",
    duration_ms: int = 0,
    path: Path | str | None = None,
) -> None:
    """Record one call. Metadata only — there is nowhere to put content."""
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO usage_events (key_id, created_at, endpoint, kind, "
            "verdict, status, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (key_id, _now(), endpoint, kind, verdict, status, duration_ms),
        )


def month_start(now: datetime | None = None) -> str:
    """First instant of the current UTC calendar month."""
    moment = now or datetime.now(timezone.utc)
    return moment.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).isoformat(timespec="seconds")


def usage_this_month(
    key_id: int, now: datetime | None = None, path: Path | str | None = None
) -> int:
    """Billable calls this key has made in the current month.

    Only successful analyses count. Charging for a request that failed
    because our provider was down would be indefensible, and counting
    rejected calls toward a quota would let one misconfigured client
    lock itself out.
    """
    with connect(path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS used FROM usage_events "
            "WHERE key_id = ? AND created_at >= ? AND status = 200",
            (key_id, month_start(now)),
        ).fetchone()
    return int(row["used"])


def over_quota(key: ApiKey, now: datetime | None = None, path=None) -> bool:
    """True when this key has spent its allowance for the month."""
    if key.monthly_quota <= 0:  # unlimited
        return False
    return usage_this_month(key.id, now, path) >= key.monthly_quota


def usage_summary(
    key_id: int | None = None, days: int = 30, path: Path | str | None = None
) -> list[dict]:
    """Per-key totals over a recent window, for support and invoicing."""
    since = datetime.now(timezone.utc).timestamp() - days * 86400
    since_iso = datetime.fromtimestamp(since, timezone.utc).isoformat(
        timespec="seconds"
    )
    query = (
        "SELECT k.id AS key_id, k.display, k.owner, k.monthly_quota, "
        "COUNT(u.id) AS calls, "
        "SUM(CASE WHEN u.status = 200 THEN 1 ELSE 0 END) AS successful, "
        "SUM(CASE WHEN u.verdict = 'danger' THEN 1 ELSE 0 END) AS dangerous, "
        "COALESCE(AVG(u.duration_ms), 0) AS avg_ms "
        "FROM api_keys k LEFT JOIN usage_events u "
        "  ON u.key_id = k.id AND u.created_at >= ? "
    )
    parameters: list = [since_iso]
    if key_id is not None:
        query += "WHERE k.id = ? "
        parameters.append(key_id)
    query += "GROUP BY k.id ORDER BY calls DESC"

    with connect(path) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [
        {
            "key_id": row["key_id"],
            "display": row["display"],
            "owner": row["owner"],
            "monthly_quota": row["monthly_quota"],
            "calls": row["calls"],
            "successful": row["successful"] or 0,
            "dangerous": row["dangerous"] or 0,
            "avg_ms": round(row["avg_ms"] or 0),
        }
        for row in rows
    ]


def prune_usage(older_than_days: int = 90, path: Path | str | None = None) -> int:
    """Delete old usage rows. Returns how many went.

    Metering data is operational, not archival. Keeping per-request
    rows forever grows without bound and widens the blast radius of a
    breach for no benefit once the month is billed.
    """
    cutoff = datetime.now(timezone.utc).timestamp() - older_than_days * 86400
    cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat(
        timespec="seconds"
    )
    with connect(path) as connection:
        cursor = connection.execute(
            "DELETE FROM usage_events WHERE created_at < ?", (cutoff_iso,)
        )
        return cursor.rowcount
