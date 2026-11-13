"""Which Google sign-in layouts of [auth] secrets switch sign-in on.

Only placeholder values: nothing here is a real credential.

    venv\\Scripts\\python.exe tests\\test_auth_config.py
"""

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import auth  # noqa: E402

CLIENT = {
    "client_id": "placeholder.apps.googleusercontent.com",
    "client_secret": "placeholder",
    "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
}
BASE = {"redirect_uri": "https://example.test/oauth2callback", "cookie_secret": "placeholder"}


def test_nested_google_section() -> None:
    assert auth.login_provider({**BASE, "google": dict(CLIENT)}) == "google"
    print("test_nested_google_section PASSED")


def test_flat_auth_section() -> None:
    # The layout that kept the production banner on: keys straight under [auth].
    assert auth.login_provider({**BASE, **CLIENT}) == ""
    print("test_flat_auth_section PASSED")


def test_nested_wins_when_both_are_present() -> None:
    assert auth.login_provider({**BASE, **CLIENT, "google": dict(CLIENT)}) == "google"
    print("test_nested_wins_when_both_are_present PASSED")


def test_incomplete_secrets_keep_sign_in_off() -> None:
    cases = [
        {},
        {**CLIENT},  # no cookie secret or redirect URI
        {"cookie_secret": "x", **CLIENT},  # no redirect URI
        {"redirect_uri": "x", **CLIENT},  # no cookie secret
        {**BASE},  # no client at all
        {**BASE, "client_id": "x"},  # flat, missing secret and metadata URL
        {**BASE, "google": {"client_id": "x"}},  # nested, incomplete
        {**BASE, "google": "not-a-section"},
        {**BASE, "client_id": "", "client_secret": "x", "server_metadata_url": "x"},  # empty value
    ]
    for case in cases:
        assert auth.login_provider(case) is None, case
    print("test_incomplete_secrets_keep_sign_in_off PASSED")


def test_sign_in_calls_the_matching_login() -> None:
    calls = []
    with patch.object(auth.st, "login", side_effect=lambda *a: calls.append(a)), \
            patch.object(auth.st, "session_state", {}):
        with patch.object(auth, "_auth_secrets", return_value={**BASE, "google": dict(CLIENT)}):
            auth.sign_in()
        with patch.object(auth, "_auth_secrets", return_value={**BASE, **CLIENT}):
            auth.sign_in()
        with patch.object(auth, "_auth_secrets", return_value={}):
            auth.sign_in()
            assert auth.st.session_state.get("tumar_auth_missing") is True
    assert calls == [("google",), ()], calls
    print("test_sign_in_calls_the_matching_login PASSED")


if __name__ == "__main__":
    test_nested_google_section()
    test_flat_auth_section()
    test_nested_wins_when_both_are_present()
    test_incomplete_secrets_keep_sign_in_off()
    test_sign_in_calls_the_matching_login()
    print("All auth config tests passed.")
