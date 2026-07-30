"""URL Scanner page — paste a link, get a trust verdict before clicking.

UI only: collect input, call the scanner service, remember the result,
and render it through the shared report view. All analysis logic lives
in services/url_scanner.py.
"""

import streamlit as st

import components
import report_store
from components import page_header
from i18n import current_language, t
from report_view import render_trust_report
from services.url_scanner import UrlScanError, scan_url

MAX_URL_LENGTH = 500
SOURCE = "url_scanner"


def _fill_example() -> None:
    """Button callback: put a sample phishing-style URL into the box."""
    st.session_state["url_input"] = t("url.example_url")


page_header(t("url.title"), t("url.subtitle"))

api_key = components.get_gemini_api_key()
if not api_key:
    components.error_view(t("scam.not_configured"))
    st.stop()

url = st.text_input(
    t("url.input_label"),
    key="url_input",
    max_chars=MAX_URL_LENGTH,
    placeholder=t("url.input_placeholder"),
    help=t("url.input_help"),
)

check_col, example_col = st.columns([3, 1])
check_clicked = check_col.button(
    t("url.check_button"), type="primary", use_container_width=True
)
example_col.button(
    t("url.example_button"), on_click=_fill_example, use_container_width=True
)

if check_clicked:
    cleaned = url.strip()
    if not cleaned:
        st.warning(t("url.empty_warning"))
    else:
        with st.spinner(t("url.spinner")):
            try:
                report = scan_url(
                    cleaned, api_key=api_key, language=current_language()
                )
            except UrlScanError as error:
                components.error_view(f"😕 {t(f'errors.{error.code}')}")
            else:
                report_store.remember(st.session_state, report)

# Rendered from the store so the verdict survives later re-runs.
remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    render_trust_report(remembered)
    st.caption(t("url.address_only_note"))
else:
    components.empty_state("🔗", t("url.empty_title"), t("url.empty_text"))
