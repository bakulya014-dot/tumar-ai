"""Sign-in state for the Streamlit app.

Google sign-in uses Streamlit's built-in OIDC support (st.login /
st.user / st.logout), configured in .streamlit/secrets.toml under
[auth] — see .streamlit/secrets.toml.example. The Google client keys may
sit in an [auth.google] section or directly under [auth]. Visitors who would rather
not create an account can continue as a guest, so every tool stays
available to everyone.
"""

from __future__ import annotations

from collections.abc import Mapping

import streamlit as st

import user_store
from i18n import current_language

PROVIDER = "google"
_GUEST_KEY = "tumar_guest"
_RECORDED_KEY = "tumar_user_recorded"
_CLIENT_KEYS = ("client_id", "client_secret", "server_metadata_url")


def login_provider(auth: Mapping) -> str | None:
    """Which st.login() provider the [auth] secrets configure, if any.

    Two layouts are accepted, because both are valid for Streamlit and
    both get pasted into hosting dashboards:

        [auth]                          [auth]
        redirect_uri  = "..."           redirect_uri  = "..."
        cookie_secret = "..."           cookie_secret = "..."
        [auth.google]                   client_id = "..."
        client_id = "..."               client_secret = "..."
        ...                             server_metadata_url = "..."

    Returns "google" for the named section (st.login("google")), "" for
    the flat layout (Streamlit's default provider: st.login()), or None
    when sign-in cannot work (no cookie secret, no redirect URI, or a
    client key missing).
    """
    if not auth or not auth.get("cookie_secret") or not auth.get("redirect_uri"):
        return None
    google = auth.get(PROVIDER)
    if isinstance(google, Mapping) and all(google.get(k) for k in _CLIENT_KEYS):
        return PROVIDER
    if all(auth.get(k) for k in _CLIENT_KEYS):
        return ""
    return None


def _auth_secrets() -> Mapping:
    try:
        return st.secrets.get("auth", {})
    except FileNotFoundError:  # no secrets file at all on this host
        return {}


def google_configured() -> bool:
    """True when the [auth] secrets configure Google sign-in (either layout)."""
    return login_provider(_auth_secrets()) is not None


def is_signed_in() -> bool:
    try:
        return bool(st.user.is_logged_in)
    except Exception:  # auth not configured on this host
        return False


def is_guest() -> bool:
    return bool(st.session_state.get(_GUEST_KEY))


def has_access() -> bool:
    """May this visitor use the tools (signed in, or chose guest mode)?"""
    return is_signed_in() or is_guest()


def sign_in() -> None:
    """Button callback: start the Google flow (or explain why it can't)."""
    provider = login_provider(_auth_secrets())
    if provider == PROVIDER:
        st.login(PROVIDER)
    elif provider == "":
        st.login()  # flat [auth] layout: Streamlit's default provider
    else:
        st.session_state["tumar_auth_missing"] = True


def continue_as_guest() -> None:
    st.session_state[_GUEST_KEY] = True


def sign_out() -> None:
    st.session_state.pop(_GUEST_KEY, None)
    st.session_state.pop(_RECORDED_KEY, None)
    if is_signed_in():
        st.logout()


def user_display() -> tuple[str, str]:
    """(name, email) of the signed-in person, or ("", "")."""
    if not is_signed_in():
        return "", ""
    return str(st.user.get("name") or ""), str(st.user.get("email") or "")


def record_registration() -> bool | None:
    """Store the signed-in user once per session.

    Returns True for a brand-new registration, False for a returning
    user, None when nothing was recorded (not signed in, or already done
    this session).
    """
    if not is_signed_in() or st.session_state.get(_RECORDED_KEY):
        return None
    name, email = user_display()
    if not email:
        return None
    st.session_state[_RECORDED_KEY] = True
    try:
        return user_store.record_sign_in(
            email, name, PROVIDER, current_language()
        )
    except Exception:
        # A registry hiccup must never lock someone out of the app.
        return None
