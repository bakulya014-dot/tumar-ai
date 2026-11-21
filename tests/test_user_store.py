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


def test_delete_user_erases_the_row() -> None:
    db = _tmp_db()
    user_store.record_sign_in("aru@example.com", "Aru", path=db)
    user_store.record_sign_in("other@example.com", "Other", path=db)
    assert user_store.delete_user("ARU@example.com ", path=db) is True
    assert user_store.delete_user("aru@example.com", path=db) is False  # already gone
    assert user_store.delete_user("", path=db) is False
    with sqlite3.connect(db) as conn:
        emails = [row[0] for row in conn.execute("SELECT email FROM users")]
    assert emails == ["other@example.com"], emails  # nobody else touched
    print("test_delete_user_erases_the_row PASSED")


def test_delete_my_data_clears_session_and_signs_out() -> None:
    from unittest.mock import patch

    import auth

    state = {"language": "kk", "trust_history": [1, 2], "tumar_user_recorded": True}
    deleted, signed_out = [], []
    with patch.object(auth.st, "session_state", state),             patch.object(auth, "user_display", return_value=("Aru", "aru@example.com")),             patch.object(auth.user_store, "delete_user", side_effect=lambda e: deleted.append(e) or True),             patch.object(auth, "sign_out", side_effect=lambda: signed_out.append(True)):
        auth.delete_my_data()
    assert deleted == ["aru@example.com"]
    assert state == {"language": "kk"}, state  # history gone, language kept
    assert signed_out == [True]
    print("test_delete_my_data_clears_session_and_signs_out PASSED")


if __name__ == "__main__":
    test_first_sign_in_registers_then_returning_user_is_counted()
    test_registry_stores_no_secrets()
    test_empty_email_is_rejected()
    test_delete_user_erases_the_row()
    test_delete_my_data_clears_session_and_signs_out()
    test_landing_strings_exist_in_every_language()
    print("ALL USER STORE TESTS PASSED")
