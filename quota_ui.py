"""The web app's side of the daily quota (services/quota.py).

Signed-in users are counted by their Google account. Guests are counted
by IP address when Streamlit can see it, otherwise per browser session.
A per-session count can be reset by reloading the page; the IP count
cannot, which is why the IP is preferred.
"""

import uuid

import streamlit as st

import auth
from i18n import t
from services.quota import default_quota


def _guest_identity() -> str:
    try:
        ip = st.context.ip_address
    except Exception:
        ip = None
    if ip:
        return f"ip:{ip}"
    if "tumar_session_id" not in st.session_state:
        st.session_state["tumar_session_id"] = uuid.uuid4().hex
    return f"session:{st.session_state['tumar_session_id']}"


def allow_check(kind: str) -> bool:
    """Count one check of `kind`; show why and return False when over quota."""
    _name, email = auth.user_display()
    if email:
        identity, tier = f"user:{email}", "user"
    else:
        identity, tier = _guest_identity(), "guest"
    decision = default_quota().consume(identity, tier, kind)
    if decision.allowed:
        return True
    st.warning(t(f"quota.exceeded_{tier}", limit=decision.limit))
    return False
