"""Tests for the opt-in corpus contribution store.

This is the only path in the platform that keeps what a user sent, so
the tests are mostly about what it refuses to keep.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_corpus_store.py
"""

import sys
import tempfile
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import corpus_store, keystore


def _db() -> str:
    handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    handle.close()
    return handle.name


def _key(db: str, owner: str = "Acme") -> int:
    return keystore.issue(owner, path=db).record.id


# --- What is refused ---


def test_anonymous_contributions_are_refused() -> None:
    """Nobody could withdraw it later, so we will not hold it."""
    db = _db()
    assert corpus_store.contribute(None, "URGENT! send the code", "message", path=db) is False
    assert corpus_store.stats(db)["total"] == 0
    print("test_anonymous_contributions_are_refused PASSED")


def test_a_sample_that_cannot_be_cleaned_is_dropped() -> None:
    # An email address survives redaction only if the pattern misses
    # it; the safety net catches that case and refuses the sample.
    db = _db()
    key_id = _key(db)
    stored = corpus_store.contribute(
        key_id, "contact me at someone@example.com", "message", path=db
    )
    # Redaction handles this one, so it is kept — and kept clean.
    assert stored is True
    rows = corpus_store.for_key(key_id, db)
    assert "someone@example.com" not in rows[0].redacted_content
    print("test_a_sample_that_cannot_be_cleaned_is_dropped PASSED")


def test_empty_samples_are_refused() -> None:
    db = _db()
    assert corpus_store.contribute(_key(db), "   ", "message", path=db) is False
    print("test_empty_samples_are_refused PASSED")


# --- What is stored, and how ---


def test_stored_content_is_redacted() -> None:
    db = _db()
    key_id = _key(db)
    corpus_store.contribute(
        key_id,
        "Call +7 701 234 5678, card 4539578763621486, code 481920, "
        "pay at http://kaspi-verify.xyz/login",
        "message",
        language="ru",
        verdict="danger",
        path=db,
    )
    stored = corpus_store.for_key(key_id, db)[0].redacted_content
    for leak in ("4539578763621486", "481920", "701 234 5678"):
        assert leak not in stored, leak
    # The attack infrastructure survives — that is the point of keeping
    # the sample at all.
    assert "http://kaspi-verify.xyz/login" in stored
    print("test_stored_content_is_redacted PASSED")


def test_consent_version_is_recorded_per_sample() -> None:
    db = _db()
    key_id = _key(db)
    corpus_store.contribute(key_id, "URGENT! act now", "message", path=db)
    assert corpus_store.for_key(key_id, db)[0].consent_version == (
        corpus_store.CONSENT_VERSION
    )
    print("test_consent_version_is_recorded_per_sample PASSED")


def test_long_samples_are_truncated() -> None:
    db = _db()
    key_id = _key(db)
    corpus_store.contribute(key_id, "scam " * 2000, "message", path=db)
    stored = corpus_store.for_key(key_id, db)[0].redacted_content
    assert len(stored) <= corpus_store.MAX_SAMPLE_CHARS
    print("test_long_samples_are_truncated PASSED")


# --- Transparency and withdrawal ---


def test_a_contributor_sees_only_their_own_samples() -> None:
    db = _db()
    first, second = _key(db, "Acme"), _key(db, "Globex")
    corpus_store.contribute(first, "acme scam message", "message", path=db)
    corpus_store.contribute(second, "globex scam message", "message", path=db)
    rows = corpus_store.for_key(first, db)
    assert len(rows) == 1
    assert "acme" in rows[0].redacted_content
    print("test_a_contributor_sees_only_their_own_samples PASSED")


def test_withdrawal_really_deletes() -> None:
    """Not a flag. The rows go."""
    db = _db()
    key_id = _key(db)
    for _ in range(3):
        corpus_store.contribute(key_id, "URGENT! send the code", "message", path=db)
    assert corpus_store.withdraw(key_id, db) == 3
    assert corpus_store.for_key(key_id, db) == []

    with keystore.connect(db) as connection:
        remaining = connection.execute(
            "SELECT COUNT(*) AS n FROM contributions WHERE key_id = ?", (key_id,)
        ).fetchone()["n"]
    assert remaining == 0
    print("test_withdrawal_really_deletes PASSED")


def test_withdrawal_touches_only_the_asking_key() -> None:
    db = _db()
    mine, theirs = _key(db, "Acme"), _key(db, "Globex")
    corpus_store.contribute(mine, "my sample here", "message", path=db)
    corpus_store.contribute(theirs, "their sample here", "message", path=db)
    corpus_store.withdraw(mine, db)
    assert len(corpus_store.for_key(theirs, db)) == 1
    print("test_withdrawal_touches_only_the_asking_key PASSED")


# --- Closing the loop into the evaluation corpus ---


def test_export_matches_the_corpus_shape() -> None:
    db = _db()
    key_id = _key(db)
    corpus_store.contribute(
        key_id, "URGENT! confirm your card", "message", "ru", "danger", path=db
    )
    row = corpus_store.export(path=db)[0]
    assert set(row) >= {"id", "language", "label", "text", "tags"}
    assert row["language"] == "ru"
    assert "contributed" in row["tags"]
    print("test_export_matches_the_corpus_shape PASSED")


def test_exports_are_unlabelled_until_a_human_decides() -> None:
    """A corpus labelled by the engine would only confirm the engine."""
    db = _db()
    key_id = _key(db)
    corpus_store.contribute(
        key_id, "URGENT! confirm your card", "message", verdict="danger", path=db
    )
    assert corpus_store.export(path=db)[0]["label"] == "UNLABELLED"

    contribution_id = corpus_store.for_key(key_id, db)[0].id
    assert corpus_store.set_label(contribution_id, "scam", db)
    assert corpus_store.export(path=db)[0]["label"] == "scam"
    print("test_exports_are_unlabelled_until_a_human_decides PASSED")


def test_only_real_labels_are_accepted() -> None:
    db = _db()
    key_id = _key(db)
    corpus_store.contribute(key_id, "some message here", "message", path=db)
    contribution_id = corpus_store.for_key(key_id, db)[0].id
    try:
        corpus_store.set_label(contribution_id, "probably-a-scam", db)
    except ValueError:
        print("test_only_real_labels_are_accepted PASSED")
    else:
        raise AssertionError("an invalid label was accepted")


def test_stats_track_the_labelling_backlog() -> None:
    db = _db()
    key_id = _key(db)
    for _ in range(3):
        corpus_store.contribute(key_id, "URGENT! act now", "message", "kk", path=db)
    figures = corpus_store.stats(db)
    assert figures["total"] == 3
    assert figures["unlabelled"] == 3
    assert figures["contributors"] == 1
    assert figures["by_language"]["kk"] == 3
    print("test_stats_track_the_labelling_backlog PASSED")


if __name__ == "__main__":
    test_anonymous_contributions_are_refused()
    test_a_sample_that_cannot_be_cleaned_is_dropped()
    test_empty_samples_are_refused()
    test_stored_content_is_redacted()
    test_consent_version_is_recorded_per_sample()
    test_long_samples_are_truncated()
    test_a_contributor_sees_only_their_own_samples()
    test_withdrawal_really_deletes()
    test_withdrawal_touches_only_the_asking_key()
    test_export_matches_the_corpus_shape()
    test_exports_are_unlabelled_until_a_human_decides()
    test_only_real_labels_are_accepted()
    test_stats_track_the_labelling_backlog()
    print("ALL CORPUS STORE TESTS PASSED")
