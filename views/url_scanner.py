"""URL Scanner page — paste a link, get a trust verdict before clicking.

UI only: collect input, call the scanner service, remember the result,
and render it through the shared report view. All analysis logic lives
in services/url_scanner.py.
"""

import streamlit as st

import components
import quota_ui
import report_store
from components import page_header
from contribution_ui import contribution_box
from i18n import current_language, t
from report_view import render_trust_report
from services.common import ServiceError
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject

MAX_URL_LENGTH = 500
SOURCE = "url_scanner"


def _fill_example() -> None:
    """Button callback: put a sample phishing-style URL into the box."""
    st.session_state["url_input"] = t("url.example_url")


page_header(t("url.title"), t("url.subtitle"), "url")

api_key = components.get_gemini_api_key()
if not api_key:
    # No key: checks still run, as clearly labelled rules-only reports.
    st.info(t("scam.not_configured"), icon=components.icon("info"))

url = st.text_input(
    t("url.input_label"),
    key="url_input",
    max_chars=MAX_URL_LENGTH,
    placeholder=t("url.input_placeholder"),
    help=t("url.input_help"),
)

check_col, example_col = st.columns([3, 1])
check_clicked = check_col.button(
    t("url.check_button"), type="primary", use_container_width=True,
    icon=components.icon("url"),
)
example_col.button(
    t("url.example_button"), on_click=_fill_example, use_container_width=True,
    icon=components.icon("example"),
)

if check_clicked:
    cleaned = url.strip()
    if not cleaned:
        st.warning(t("url.empty_warning"))
    elif not quota_ui.allow_check("url"):
        pass
    else:
        with st.spinner(t("url.spinner")):
            try:
                # Shared Trust Engine, with the labelled rules-only
                # fallback when the AI provider fails.
                report = TrustEngine().analyze(
                    TrustSubject(content=cleaned, declared_kind="url", language=current_language()),
                    AnalysisContext(api_key=api_key, offline_fallback=True, channel="web"),
                )
            except ServiceError as error:
                quota_ui.settle("url", failed=True)
                components.error_view(t(f'errors.{error.code}'))
            else:
                quota_ui.settle("url", report)
                report_store.remember(st.session_state, report)

# Rendered from the store so the verdict survives later re-runs.
remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    render_trust_report(remembered)
    st.caption(components.labeled("info", t("url.address_only_note")))
    contribution_box(url, remembered)
else:
    components.empty_state("url", t("url.empty_title"), t("url.empty_text"))
