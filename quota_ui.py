"""The web app's side of the daily quota (services/quota.py).

Signed-in users are counted by their Google account.

Guests are counted per browser session by default, and every guest
check also draws from one shared daily pool (TUMAR_DAILY_LIMIT_GUEST_POOL)
that caps the total cost of anonymous use. Why not by IP: Streamlit
reports the network peer it sees, and behind a hosting proxy (Streamlit
Cloud, Render…) that is usually the proxy, so every guest would share a
single 20-check allowance. A session count can be reset by opening a new
session; the shared pool is what bounds that.

Set TUMAR_GUEST_QUOTA_KEY=ip on a host that passes real visitor
addresses through to the app; anything else means per session.
"""

import os
import uuid

import streamlit as st

import auth
from i18n import t
from services.quota import default_quota


def _guest_identity() -> str:
    if os.environ.get("TUMAR_GUEST_QUOTA_KEY", "").strip().lower() == "ip":
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
    quota = default_quota()
    _name, email = auth.user_display()
    if email:
        decision = quota.consume(f"user:{email}", "user", kind)
        if not decision.allowed:
            st.warning(t("quota.exceeded_user", limit=decision.limit))
        return decision.allowed

    decision = quota.consume(_guest_identity(), "guest", kind)
    if not decision.allowed:
        st.warning(t("quota.exceeded_guest", limit=decision.limit))
        return False
    pool = quota.consume("all-guests", "guest_pool", kind)
    if not pool.allowed:
        st.warning(t("quota.exceeded_pool"))
        return False
    return True


def refund(kind: str) -> None:
    """Return one check counted by allow_check() that cost nothing —
    the provider failed, so the user got an offline result or an error.
    Guests get both their own count and the shared pool back."""
    quota = default_quota()
    _name, email = auth.user_display()
    if email:
        quota.refund(f"user:{email}", "user", kind)
        return
    quota.refund(_guest_identity(), "guest", kind)
    quota.refund("all-guests", "guest_pool", kind)


def settle(kind: str, report=None, failed: bool = False) -> None:
    """Refund the check when it did not reach the paid service:
    a ServiceError (failed=True) or a rules-only offline report."""
    offline = report is not None and report.analysis_metadata.get("mode") == "offline"
    if failed or offline:
        refund(kind)
