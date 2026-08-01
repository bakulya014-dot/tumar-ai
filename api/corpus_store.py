"""Opt-in storage of contributed samples, for improving detection.

Everything else in this platform is built on not keeping what people
send. This is the one path that keeps anything, so it is deliberately
narrow and every restriction is enforced in code rather than promised
in documentation.

The rules:

- **Opt-in per request.** `contribute` defaults to false. There is no
  account-level setting that quietly turns it on for traffic sent
  before anyone thought about it.
- **Redacted before storage.** Personal identifiers are stripped by
  services/redaction.py, and a sample that still looks identifying
  afterwards is dropped rather than stored. Losing a sample is cheap.
- **Consent is versioned.** Each row records the terms it was
  collected under, so a change in terms cannot retroactively cover
  what came before.
- **Withdrawal really deletes.** Not a flag, not a soft delete —
  the rows go. A promise to delete that leaves the data in place is
  not a promise.
- **Nothing is contributed anonymously.** A sample without an issued
  key has no one who could withdraw it, so it is not accepted.

What this buys is the thing a competitor cannot copy: a growing corpus
of real Kazakh and Russian fraud, which feeds the evaluation harness
and therefore every future improvement.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from api.keystore import connect
from services.redaction import contains_identifier, redact

# The terms each sample was collected under. Bump this when the terms
# change; existing rows keep the version they agreed to.
CONSENT_VERSION = "2026-08-01"

# Samples longer than this are truncated: a long paste is usually a
# thread, and the scam is at the start of it.
MAX_SAMPLE_CHARS = 2000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS contributions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id           INTEGER NOT NULL REFERENCES api_keys(id),
    created_at       TEXT    NOT NULL,
    consent_version  TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    language         TEXT    NOT NULL DEFAULT '',
    redacted_content TEXT    NOT NULL,
    verdict          TEXT    NOT NULL DEFAULT '',
    confidence       INTEGER NOT NULL DEFAULT 0,
    reviewed_label   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS contributions_by_key
    ON contributions (key_id);
"""


@dataclass(frozen=True)
class Contribution:
    """One stored sample, as it can be shown back to its contributor."""

    id: int
    created_at: str
    consent_version: str
    kind: str
    language: str
    redacted_content: str
    verdict: str
    reviewed_label: str


def _ensure(connection: sqlite3.Connection) -> None:
    connection.executescript(_SCHEMA)


def contribute(
    key_id: int | None,
    content: str,
    kind: str,
    language: str = "",
    verdict: str = "",
    confidence: int = 0,
    path: Path | str | None = None,
) -> bool:
    """Store one redacted sample. Returns whether it was kept.

    False is a normal outcome, not an error: a sample is refused when
    it cannot be attributed to a key that could later withdraw it, or
    when redaction could not make it safe to keep.
    """
    if key_id is None:
        # Nobody could withdraw this later, so we will not hold it.
        return False

    cleaned = redact(content.strip())[:MAX_SAMPLE_CHARS]
    if not cleaned:
        return False
    if contains_identifier(cleaned):
        # Redaction did not fully succeed. Drop it — a sample is worth
        # far less than the risk of holding someone's identifiers.
        return False

    with connect(path) as connection:
        _ensure(connection)
        connection.execute(
            "INSERT INTO contributions (key_id, created_at, consent_version, "
            "kind, language, redacted_content, verdict, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                key_id,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                CONSENT_VERSION,
                kind,
                language,
                cleaned,
                verdict,
                confidence,
            ),
        )
    return True


def for_key(key_id: int, path: Path | str | None = None) -> list[Contribution]:
    """Everything stored for one contributor, so they can see it.

    Transparency is part of the bargain: a customer who contributed
    should be able to read back exactly what we hold, in the form we
    hold it, rather than take our word for the redaction.
    """
    with connect(path) as connection:
        _ensure(connection)
        rows = connection.execute(
            "SELECT * FROM contributions WHERE key_id = ? ORDER BY id DESC",
            (key_id,),
        ).fetchall()
    return [
        Contribution(
            id=row["id"],
            created_at=row["created_at"],
            consent_version=row["consent_version"],
            kind=row["kind"],
            language=row["language"],
            redacted_content=row["redacted_content"],
            verdict=row["verdict"],
            reviewed_label=row["reviewed_label"],
        )
        for row in rows
    ]


def withdraw(key_id: int, path: Path | str | None = None) -> int:
    """Delete every sample contributed by this key. Returns the count.

    A real delete. Anything already exported into the labelled corpus
    has left this table, which is stated plainly in the API docs — a
    withdrawal cannot reach into a file someone has already reviewed,
    and pretending otherwise would be the dishonest part.
    """
    with connect(path) as connection:
        _ensure(connection)
        cursor = connection.execute(
            "DELETE FROM contributions WHERE key_id = ?", (key_id,)
        )
        return cursor.rowcount


def stats(path: Path | str | None = None) -> dict:
    """How much has been contributed, and how much is still unlabelled."""
    with connect(path) as connection:
        _ensure(connection)
        row = connection.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN reviewed_label = '' THEN 1 ELSE 0 END) AS unlabelled, "
            "COUNT(DISTINCT key_id) AS contributors "
            "FROM contributions"
        ).fetchone()
        by_language = connection.execute(
            "SELECT language, COUNT(*) AS n FROM contributions "
            "GROUP BY language ORDER BY n DESC"
        ).fetchall()
    return {
        "total": row["total"] or 0,
        "unlabelled": row["unlabelled"] or 0,
        "contributors": row["contributors"] or 0,
        "by_language": {item["language"] or "unknown": item["n"] for item in by_language},
    }


def export(
    limit: int = 0, unlabelled_only: bool = False, path: Path | str | None = None
) -> list[dict]:
    """Contributions in the shape the evaluation corpus expects.

    This is where the loop closes: production traffic becomes labelled
    cases, labelled cases become measurement, measurement drives the
    next improvement. The rows come out unlabelled — a human still has
    to decide whether each one is a scam, because a corpus labelled by
    the system it measures would only confirm what the system already
    believes.
    """
    query = "SELECT * FROM contributions"
    if unlabelled_only:
        query += " WHERE reviewed_label = ''"
    query += " ORDER BY id"
    if limit:
        query += f" LIMIT {int(limit)}"

    with connect(path) as connection:
        _ensure(connection)
        rows = connection.execute(query).fetchall()

    return [
        {
            "id": f"contrib-{row['id']}",
            "language": row["language"] or "en",
            "label": row["reviewed_label"] or "UNLABELLED",
            "text": row["redacted_content"],
            "tags": ["contributed", row["kind"]],
            "engine_verdict": row["verdict"],
        }
        for row in rows
    ]


def set_label(
    contribution_id: int, label: str, path: Path | str | None = None
) -> bool:
    """Record a human's judgement of one sample."""
    if label not in ("scam", "legitimate", ""):
        raise ValueError("a label must be 'scam', 'legitimate', or empty")
    with connect(path) as connection:
        _ensure(connection)
        cursor = connection.execute(
            "UPDATE contributions SET reviewed_label = ? WHERE id = ?",
            (label, contribution_id),
        )
        return cursor.rowcount > 0
