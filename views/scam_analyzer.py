"""Scam Analyzer page — paste a message, get a trust report.

UI only: collect input, call the analysis service, remember the result,
and render it through the shared report view. The deterministic scanner
lives in services/heuristics.py and the AI logic in
services/scam_analysis.py.
"""

import streamlit as st

import components
import report_store
from components import page_header
from contribution_ui import contribution_box
from report_view import render_trust_report
from services.scam_analysis import ScamAnalysisError, analyze_message
from services.trust_report import TrustReport, from_scam_report
from i18n import t

MAX_MESSAGE_LENGTH = 5000
SOURCE = "scam_analyzer"


def _fill_example() -> None:
    """Button callback: put a sample scam message into the input box."""
    st.session_state["scam_message"] = t("scam.example_message")


def _render(report: TrustReport) -> None:
    """Shared report layout, plus this module's own safety warning."""
    render_trust_report(report)
    # One-time codes are the single most damaging thing a victim can
    # hand over, so this module escalates it above the evidence list —
    # but only when the message asks for one, not when it delivers one.
    if any(item.code == "otp_disclosure" for item in report.evidence):
        st.warning(t("scam.otp_warning"))


page_header(t("scam.title"), t("scam.subtitle"), "scam")

api_key = components.get_gemini_api_key()
if not api_key:
    components.error_view(t("scam.not_configured"))
    st.stop()

message = st.text_area(
    t("scam.input_label"),
    key="scam_message",
    height=180,
    max_chars=MAX_MESSAGE_LENGTH,
    placeholder=t("scam.input_placeholder"),
    help=t("scam.input_help"),
)

analyze_col, example_col = st.columns([3, 1])
analyze_clicked = analyze_col.button(
    t("scam.analyze_button"), type="primary", use_container_width=True,
    icon=components.icon("scam"),
)
example_col.button(
    t("scam.example_button"), on_click=_fill_example, use_container_width=True,
    icon=components.icon("example"),
)

if analyze_clicked:
    cleaned = message.strip()
    if not cleaned:
        st.warning(t("scam.empty_warning"))
    else:
        with st.spinner(t("scam.spinner")):
            try:
                result = analyze_message(cleaned, api_key=api_key)
            except ScamAnalysisError as error:
                components.error_view(t(f'errors.{error.code}'))
            else:
                report_store.remember(
                    st.session_state, from_scam_report(result, cleaned)
                )

# Rendered from the store, not from the click: a result must survive
# every later re-run (language switch, typing, any other widget).
remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    _render(remembered)
    contribution_box(message, remembered)
else:
    components.empty_state(
        "scam", t("scam.empty_title"), t("scam.empty_text")
    )
