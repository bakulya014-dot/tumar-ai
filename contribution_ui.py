"""The "help improve detection" box shown under a report (UI layer).

Asking an ordinary person to donate a message they just had checked is
a bigger ask than asking a company to, and it deserves a better
consent flow than a checkbox. Four things make this one honest:

**It appears after the result, never before.** Nobody is asked to
agree to anything in order to get their answer. The check happens
first, unconditionally; the invitation comes afterwards.

**It shows exactly what would be stored.** Not a description of
redaction — the redacted text itself, before the user decides.
Describing it asks for trust; showing it asks for nothing, because the
reader can check it themselves. That same redacted string is what
leaves this process, so the preview cannot be a polite fiction.

**It is honest about withdrawal.** Contributions can be removed while
the session lasts. Afterwards they cannot, because nothing links them
to the person who sent them, and that is stated plainly rather than
buried. Keeping an identifier forever so that deletion stays possible
would be the more invasive choice; this one is explained, not hidden.

**It does not appear at all unless the samples will survive.** The app
can run on a host that discards its filesystem on restart. Collecting
consented data into storage that will vanish is worse than not
collecting it, so storage has to be declared durable — either a
Tumar.AI API to send to, or an operator asserting the disk persists.
Neither configured means no invitation, rather than a promise we
cannot keep.

Only messages and links are ever offered. An email address is the
subject of its own check, not research material, and a password is
never stored under any circumstance.
"""

import os
import secrets

import streamlit as st

import components
from api import corpus_store
from i18n import current_language, t
from services.corpus_client import RemoteCorpus
from services.trust_report import TrustReport

# Kinds worth contributing. Anything not listed here is never offered.
CONTRIBUTABLE = frozenset({"message", "url"})

_SESSION_KEY = "contribution_session_id"


def _setting(name: str) -> str:
    """Read config from Streamlit secrets, falling back to the environment."""
    try:
        value = st.secrets.get(name, "")
    except (FileNotFoundError, KeyError):
        value = ""
    return str(value or os.environ.get(name, ""))


def _remote() -> RemoteCorpus:
    """The API that owns the database, if one is configured."""
    return RemoteCorpus(
        base_url=_setting("TUMAR_API_URL"), api_key=_setting("TUMAR_APP_API_KEY")
    )


def _local_storage_is_durable() -> bool:
    """Whether the operator has vouched for this host's filesystem.

    There is no reliable way to ask a container whether its disk
    survives a restart, so this is an assertion rather than a
    detection: someone who knows the deployment sets it. Defaulting to
    "no" means the failure mode is a missing invitation, not silently
    discarded consent.
    """
    return _setting("TUMAR_DURABLE_STORAGE").strip().lower() in ("1", "true", "yes")


def storage_available() -> bool:
    """Whether contributed samples would actually survive."""
    return _remote().configured or _local_storage_is_durable()


def _session_id() -> str:
    """A random id for this browser session, tied to no identity.

    It exists so a person can take back what they contributed while
    they are still here. It is not stored with anything that could
    identify them, and it disappears when the session does.
    """
    if _SESSION_KEY not in st.session_state:
        st.session_state[_SESSION_KEY] = secrets.token_urlsafe(16)
    return st.session_state[_SESSION_KEY]


def _contributed_ids() -> set[str]:
    """Report ids contributed in this session.

    Tracked in session state rather than by asking storage, because
    the remote backend deliberately offers no read-back of one
    session's samples — a lookup endpoint would be a way to enumerate
    other people's contributions.
    """
    return st.session_state.setdefault("contributed_reports", set())


def contribution_box(content: str, report: TrustReport) -> None:
    """Offer to contribute one analyzed sample, with full disclosure."""
    kind = _kind_for(report)
    if kind not in CONTRIBUTABLE or not content.strip():
        return
    if not storage_available():
        # Nowhere durable to put it, so do not ask.
        return

    with st.expander(t("contribute.title"), expanded=False, icon=components.icon("contribute")):
        if report.report_id in _contributed_ids():
            _render_thanks()
            return

        st.caption(t("contribute.why"))

        # What is shown here is exactly what is sent and stored.
        redacted = corpus_store.preview(content)
        st.markdown(f"**{t('contribute.preview_title')}**")
        st.code(redacted, language=None)
        st.caption(t("contribute.preview_note"))
        st.caption(t("contribute.withdraw_note"))

        if st.button(
            t("contribute.button"),
            key=f"contribute_{report.report_id}",
            icon=components.icon("contribute"),
        ):
            if _store(redacted, kind, report):
                _contributed_ids().add(report.report_id)
                st.success(t("contribute.stored"), icon=components.icon("done"))
                st.rerun()
            else:
                # Refused, or our own service was unreachable. Say so;
                # a silent failure would be worse than a no.
                components.error_view(t("contribute.refused"))


def _store(redacted: str, kind: str, report: TrustReport) -> bool:
    """Persist one sample wherever this deployment keeps them."""
    remote = _remote()
    if remote.configured:
        return remote.submit(
            content=redacted,
            kind=kind,
            language=current_language(),
            verdict=report.verdict,
            confidence=report.confidence,
            session_id=_session_id(),
        )
    return corpus_store.contribute(
        key_id=None,
        content=redacted,
        kind=kind,
        language=current_language(),
        verdict=report.verdict,
        confidence=report.confidence,
        session_id=_session_id(),
    )


def _render_thanks() -> None:
    """Shown once this sample has been contributed."""
    st.success(t("contribute.already"), icon=components.icon("done"))
    st.caption(t("contribute.withdraw_note"))
    if st.button(
        t("contribute.withdraw_button"),
        key="withdraw_contributions",
        icon=components.icon("delete"),
    ):
        removed = _withdraw()
        _contributed_ids().clear()
        st.info(t("contribute.withdrawn", count=removed))
        st.rerun()


def _withdraw() -> int:
    """Delete everything this session contributed."""
    session_id = _session_id()
    remote = _remote()
    if remote.configured:
        return remote.withdraw(session_id)
    return corpus_store.withdraw_session(session_id)


def _kind_for(report: TrustReport) -> str:
    """Map a report's subject type onto an analyzer kind."""
    return {"message": "message", "url": "url"}.get(report.subject_type, "")
