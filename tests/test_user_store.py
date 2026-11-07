"""Offline tests for user_store.py (Google sign-up registry) and the
landing-page translations.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_user_store.py
"""

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import user_store


def _tmp_db() -> Path:
    return Path(tempfile.mkdtemp()) / "users.db"


def test_first_sign_in_registers_then_returning_user_is_counted() -> None:
    db = _tmp_db()
    assert user_store.record_sign_in("A@Example.com", "Aru", path=db) is True
    assert user_store.record_sign_in("a@example.com", "Aru B", path=db) is False
    assert user_store.user_count(path=db) == 1
    with sqlite3.connect(db) as conn:
        name, sign_ins = conn.execute(
            "SELECT name, sign_ins FROM users WHERE email = 'a@example.com'"
        ).fetchone()
    assert name == "Aru B" and sign_ins == 2
    print("test_first_sign_in_registers_then_returning_user_is_counted PASSED")


def test_registry_stores_no_secrets() -> None:
    db = _tmp_db()
    user_store.record_sign_in("b@example.com", "Bek", path=db)
    with sqlite3.connect(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    assert cols == {"email", "name", "provider", "language", "first_seen", "last_seen", "sign_ins"}
    print("test_registry_stores_no_secrets PASSED")


def test_empty_email_is_rejected() -> None:
    try:
        user_store.record_sign_in("  ", path=_tmp_db())
    except ValueError:
        pass
    else:
        raise AssertionError("empty email did not raise")
    print("test_empty_email_is_rejected PASSED")


def test_landing_strings_exist_in_every_language() -> None:
    files = {lang: json.loads((ROOT / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))
             for lang in ("en", "ru", "kk")}
    for section in ("landing", "account"):
        expected = set(files["en"][section])
        for lang, data in files.items():
            missing = expected - set(data.get(section, {}))
            assert not missing, f"{lang}.{section} missing {sorted(missing)}"
    print("test_landing_strings_exist_in_every_language PASSED")


if __name__ == "__main__":
    test_first_sign_in_registers_then_returning_user_is_counted()
    test_registry_stores_no_secrets()
    test_empty_email_is_rejected()
    test_landing_strings_exist_in_every_language()
    print("ALL USER STORE TESTS PASSED")
