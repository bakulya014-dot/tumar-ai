"""The "help improve detection" box shown under a report (UI layer).

Asking an ordinary person to donate a message they just had checked is
a bigger ask than asking a company to, and it deserves a better
consent flow than a checkbox. Three things make this one honest:

**It appears after the result, never before.** Nobody is asked to
agree to anything in order to get their answer. The check happens
first, unconditionally; the invitation comes afterwards.

**It shows exactly what would be stored.** Not a description of
redaction — the redacted text itself, before the user decides.
Describing it asks for trust; showing it asks for nothing, because the
reader can check it themselves.

**It is honest about withdrawal.** Contributions can be removed while
the session lasts. Afterwards they cannot, because nothing links them
to the person who sent them, and that is stated plainly rather than
buried. Keeping an identifier forever so that deletion stays possible
would be the more invasive choice; this one is explained, not hidden.

Only messages and links are ever offered. An email address is the
subject of its own check, not research material, and a password is
never stored under any circumstance.
"""

import secrets

import streamlit as st

import components
from api import corpus_store
from i18n import current_language, t
from services.trust_report import TrustReport

# Kinds worth contributing. Anything not listed here is never offered.
CONTRIBUTABLE = frozenset({"message", "url"})

_SESSION_KEY = "contribution_session_id"


def _session_id() -> str:
    """A random id for this browser session, tied to no identity.

    It exists so a person can take back what they contributed while
    they are still here. It is not stored with anything that could
    identify them, and it disappears when the session does.
    """
    if _SESSION_KEY not in st.session_state:
        st.session_state[_SESSION_KEY] = secrets.token_urlsafe(16)
    return st.session_state[_SESSION_KEY]


def contribution_box(content: str, report: TrustReport) -> None:
    """Offer to contribute one analyzed sample, with full disclosure."""
    kind = _kind_for(report)
    if kind not in CONTRIBUTABLE or not content.strip():
        return

    session_id = _session_id()
    already = corpus_store.for_session(session_id)
    mine = [item for item in already if item.redacted_content == corpus_store.preview(content)]

    with st.expander(t("contribute.title"), expanded=False):
        if mine:
            _render_thanks(session_id)
            return

        st.caption(t("contribute.why"))

        redacted = corpus_store.preview(content)
        st.markdown(f"**{t('contribute.preview_title')}**")
        st.code(redacted, language=None)
        st.caption(t("contribute.preview_note"))
        st.caption(t("contribute.withdraw_note"))

        if st.button(t("contribute.button"), key=f"contribute_{report.report_id}"):
            stored = corpus_store.contribute(
                key_id=None,
                content=content,
                kind=kind,
                language=current_language(),
                verdict=report.verdict,
                confidence=report.confidence,
                session_id=session_id,
            )
            if stored:
                st.success(t("contribute.stored"))
                st.rerun()
            else:
                # Refused because redaction could not make it safe.
                # Say so; a silent failure would be worse than a no.
                components.error_view(t("contribute.refused"))


def _render_thanks(session_id: str) -> None:
    """Shown once this sample has been contributed."""
    st.success(t("contribute.already"))
    st.caption(t("contribute.withdraw_note"))
    if st.button(t("contribute.withdraw_button"), key=f"withdraw_{session_id}"):
        removed = corpus_store.withdraw_session(session_id)
        st.info(t("contribute.withdrawn", count=removed))
        st.rerun()


def _kind_for(report: TrustReport) -> str:
    """Map a report's subject type onto an analyzer kind."""
    return {"message": "message", "url": "url"}.get(report.subject_type, "")
