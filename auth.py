"""Sign-in state for the Streamlit app.

Google sign-in uses Streamlit's built-in OIDC support (st.login /
st.user / st.logout), configured in .streamlit/secrets.toml under
[auth] — see .streamlit/secrets.toml.example. Visitors who would rather
not create an account can continue as a guest, so every tool stays
available to everyone.
"""

from __future__ import annotations

import streamlit as st

import user_store
from i18n import current_language

PROVIDER = "google"
_GUEST_KEY = "tumar_guest"
_RECORDED_KEY = "tumar_user_recorded"


def google_configured() -> bool:
    """True when secrets.toml carries an [auth.google] section."""
    try:
        auth = st.secrets.get("auth", {})
    except FileNotFoundError:
        return False
    return bool(auth.get("cookie_secret")) and "google" in auth


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
    if google_configured():
        st.login(PROVIDER)
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
