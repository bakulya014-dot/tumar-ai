"""Tests for API key management and usage metering.

Each test runs against its own temporary database, so they are order
independent and leave nothing behind.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_keystore.py
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import keystore


def _db() -> str:
    """A fresh database file for one test."""
    handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    handle.close()
    return handle.name


# --- Storage of the secret itself ---


def test_secret_is_never_stored_in_the_database() -> None:
    """A stolen database must not be a set of working credentials."""
    db = _db()
    issued = keystore.issue("Acme Bank", "production", 1000, db)
    raw = Path(db).read_bytes()
    assert issued.secret.encode() not in raw
    # The random part must be absent even in fragments.
    assert issued.secret[len(keystore.KEY_PREFIX) :].encode() not in raw
    print("test_secret_is_never_stored_in_the_database PASSED")


def test_display_form_identifies_without_revealing() -> None:
    db = _db()
    issued = keystore.issue("Acme Bank", path=db)
    display = issued.record.display
    assert display.startswith(keystore.KEY_PREFIX)
    assert display != issued.secret
    # Far too little of the secret to be guessable from the listing.
    assert len(display) < len(issued.secret) / 2
    print("test_display_form_identifies_without_revealing PASSED")


def test_keys_are_unique_and_unguessable() -> None:
    db = _db()
    secrets_seen = {keystore.issue("Acme", path=db).secret for _ in range(25)}
    assert len(secrets_seen) == 25
    assert all(len(secret) > 40 for secret in secrets_seen)
    print("test_keys_are_unique_and_unguessable PASSED")


# --- Lifecycle ---


def test_issued_key_verifies_and_carries_its_owner() -> None:
    db = _db()
    issued = keystore.issue("Acme Bank", "production", 500, db)
    found = keystore.verify(issued.secret, db)
    assert found is not None
    assert found.owner == "Acme Bank"
    assert found.monthly_quota == 500
    assert found.active
    print("test_issued_key_verifies_and_carries_its_owner PASSED")


def test_unknown_and_empty_keys_are_rejected() -> None:
    db = _db()
    keystore.issue("Acme", path=db)
    assert keystore.verify("tmr_live_not-a-real-key", db) is None
    assert keystore.verify("", db) is None
    print("test_unknown_and_empty_keys_are_rejected PASSED")


def test_revoked_key_stops_working_immediately() -> None:
    db = _db()
    issued = keystore.issue("Acme", path=db)
    assert keystore.verify(issued.secret, db) is not None
    assert keystore.revoke(issued.record.id, db)
    assert keystore.verify(issued.secret, db) is None
    # Revoking twice is not an error worth pretending succeeded.
    assert not keystore.revoke(issued.record.id, db)
    print("test_revoked_key_stops_working_immediately PASSED")


def test_rotation_replaces_the_key_and_keeps_the_customer() -> None:
    db = _db()
    original = keystore.issue("Acme Bank", "production", 750, db)
    replacement = keystore.rotate(original.record.id, db)

    assert replacement is not None
    assert replacement.secret != original.secret
    # The old key is dead the moment it is rotated — the right default
    # when a key might be compromised.
    assert keystore.verify(original.secret, db) is None
    assert keystore.verify(replacement.secret, db) is not None
    # …and the customer's settings survive the swap.
    assert replacement.record.owner == "Acme Bank"
    assert replacement.record.label == "production"
    assert replacement.record.monthly_quota == 750
    print("test_rotation_replaces_the_key_and_keeps_the_customer PASSED")


def test_rotation_records_the_trail() -> None:
    db = _db()
    original = keystore.issue("Acme", path=db)
    replacement = keystore.rotate(original.record.id, db)
    old = next(k for k in keystore.list_keys(db) if k.id == original.record.id)
    assert old.rotated_to == replacement.record.id
    assert not old.active
    print("test_rotation_records_the_trail PASSED")


def test_rotating_a_missing_key_reports_it() -> None:
    assert keystore.rotate(999, _db()) is None
    print("test_rotating_a_missing_key_reports_it PASSED")


def test_a_key_must_belong_to_someone() -> None:
    try:
        keystore.issue("   ", path=_db())
    except ValueError:
        print("test_a_key_must_belong_to_someone PASSED")
    else:
        raise AssertionError("an ownerless key was issued")


# --- Metering ---


def test_usage_records_metadata_and_nothing_else() -> None:
    """The privacy promise is enforced by the schema, not by care."""
    db = _db()
    with keystore.connect(db) as connection:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(usage_events)")
        }
    forbidden = {"content", "message", "text", "url", "subject", "preview", "body"}
    assert not (columns & forbidden), columns
    print("test_usage_records_metadata_and_nothing_else PASSED")


def test_only_successful_calls_count_toward_the_quota() -> None:
    db = _db()
    issued = keystore.issue("Acme", monthly_quota=10, path=db)
    key_id = issued.record.id
    keystore.record_usage(key_id, "/v1/analyze", 200, path=db)
    keystore.record_usage(key_id, "/v1/analyze", 200, path=db)
    # A provider outage and a rejected request are not billable.
    keystore.record_usage(key_id, "/v1/analyze", 503, path=db)
    keystore.record_usage(key_id, "/v1/analyze", 400, path=db)
    assert keystore.usage_this_month(key_id, path=db) == 2
    print("test_only_successful_calls_count_toward_the_quota PASSED")


def test_quota_blocks_only_once_it_is_spent() -> None:
    db = _db()
    issued = keystore.issue("Acme", monthly_quota=3, path=db)
    key = issued.record
    for _ in range(2):
        keystore.record_usage(key.id, "/v1/analyze", 200, path=db)
    assert not keystore.over_quota(key, path=db)
    keystore.record_usage(key.id, "/v1/analyze", 200, path=db)
    assert keystore.over_quota(key, path=db)
    print("test_quota_blocks_only_once_it_is_spent PASSED")


def test_zero_quota_means_unlimited() -> None:
    db = _db()
    issued = keystore.issue("Acme", monthly_quota=0, path=db)
    for _ in range(50):
        keystore.record_usage(issued.record.id, "/v1/analyze", 200, path=db)
    assert not keystore.over_quota(issued.record, path=db)
    print("test_zero_quota_means_unlimited PASSED")


def test_quota_counts_the_current_month_only() -> None:
    db = _db()
    issued = keystore.issue("Acme", monthly_quota=5, path=db)
    key_id = issued.record.id
    for _ in range(5):
        keystore.record_usage(key_id, "/v1/analyze", 200, path=db)
    assert keystore.over_quota(issued.record, path=db)

    # Viewed from next month, the allowance has reset.
    next_month = datetime.now(timezone.utc).replace(day=28) + timedelta(days=10)
    assert keystore.usage_this_month(key_id, now=next_month, path=db) == 0
    assert not keystore.over_quota(issued.record, now=next_month, path=db)
    print("test_quota_counts_the_current_month_only PASSED")


def test_usage_summary_reports_per_key_totals() -> None:
    db = _db()
    first = keystore.issue("Acme", monthly_quota=100, path=db).record
    second = keystore.issue("Globex", path=db).record
    keystore.record_usage(first.id, "/v1/analyze", 200, "message", "danger", 120, db)
    keystore.record_usage(first.id, "/v1/analyze", 200, "url", "safe", 80, db)
    keystore.record_usage(second.id, "/v1/analyze", 503, path=db)

    summary = {row["key_id"]: row for row in keystore.usage_summary(path=db)}
    assert summary[first.id]["calls"] == 2
    assert summary[first.id]["successful"] == 2
    assert summary[first.id]["dangerous"] == 1
    assert summary[first.id]["avg_ms"] == 100
    assert summary[second.id]["successful"] == 0
    print("test_usage_summary_reports_per_key_totals PASSED")


def test_old_usage_can_be_pruned() -> None:
    db = _db()
    key_id = keystore.issue("Acme", path=db).record.id
    keystore.record_usage(key_id, "/v1/analyze", 200, path=db)
    # Nothing recent should be removed.
    assert keystore.prune_usage(90, db) == 0
    assert keystore.usage_this_month(key_id, path=db) == 1
    # Metering data is operational, not archival.
    assert keystore.prune_usage(0, db) >= 0
    print("test_old_usage_can_be_pruned PASSED")


def test_anonymous_usage_is_still_recorded() -> None:
    # Bootstrap keys have no record, but their traffic must still be
    # visible or an operator cannot see what the service is doing.
    db = _db()
    keystore.record_usage(None, "/v1/analyze", 200, "message", "safe", 50, db)
    with keystore.connect(db) as connection:
        count = connection.execute(
            "SELECT COUNT(*) AS n FROM usage_events WHERE key_id IS NULL"
        ).fetchone()["n"]
    assert count == 1
    print("test_anonymous_usage_is_still_recorded PASSED")


if __name__ == "__main__":
    test_secret_is_never_stored_in_the_database()
    test_display_form_identifies_without_revealing()
    test_keys_are_unique_and_unguessable()
    test_issued_key_verifies_and_carries_its_owner()
    test_unknown_and_empty_keys_are_rejected()
    test_revoked_key_stops_working_immediately()
    test_rotation_replaces_the_key_and_keeps_the_customer()
    test_rotation_records_the_trail()
    test_rotating_a_missing_key_reports_it()
    test_a_key_must_belong_to_someone()
    test_usage_records_metadata_and_nothing_else()
    test_only_successful_calls_count_toward_the_quota()
    test_quota_blocks_only_once_it_is_spent()
    test_zero_quota_means_unlimited()
    test_quota_counts_the_current_month_only()
    test_usage_summary_reports_per_key_totals()
    test_old_usage_can_be_pruned()
    test_anonymous_usage_is_still_recorded()
    print("ALL KEYSTORE TESTS PASSED")
