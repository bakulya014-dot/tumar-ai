"""URL Scanner page — paste a link, get a trust verdict before clicking.

UI only: it collects input, calls the URL scanner service, and renders
the returned TrustReport with the Aura design system. All analysis
logic lives in services/url_scanner.py.
"""

import streamlit as st

import components
from components import page_header
from i18n import current_language, t
from services.trust_report import TrustReport
from services.url_scanner import UrlScanError, scan_url

MAX_URL_LENGTH = 500


def _fill_example() -> None:
    """Button callback: put a sample phishing-style URL into the box."""
    st.session_state["url_input"] = t("url.example_url")


def _render_report(report: TrustReport) -> None:
    """Show the TrustReport: verdict, scores, evidence, and advice."""
    components.verdict_card(
        components.TRUST_CSS_VARIANTS[report.verdict],
        t(f"trust.verdict.{report.verdict}"),
        report.trust_score,
        t("trust.score_label"),
    )
    components.meter(
        t("trust.confidence"),
        report.confidence,
        "brand",
        t("scam.metric_confidence_help"),
    )
    st.caption(t("url.address_only_note"))

    ai_flags = [item.detail for item in report.evidence if item.kind == "ai"]
    if ai_flags:
        st.subheader(t("url.red_flags_title"))
        components.chip_row(ai_flags, "danger")

    st.subheader(t("url.explanation_title"))
    st.write(report.explanation)

    st.subheader(t("url.actions_title"))
    for number, action in enumerate(report.recommended_actions, start=1):
        st.markdown(f"{number}. {action}")

    with st.expander(t("url.breakdown_title"), expanded=True):
        heuristic_codes = [
            item.code for item in report.evidence if item.kind == "heuristic"
        ]
        if heuristic_codes:
            reasons = "; ".join(
                t(f"scam.url_reason.{code}") for code in heuristic_codes
            )
            components.threat_card(report.subject_preview, reasons)
        else:
            st.caption(t("url.no_signals"))


page_header(t("url.title"), t("url.subtitle"))

api_key = components.get_gemini_api_key()
if not api_key:
    st.error(t("scam.not_configured"))
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
                st.error(f"😕 {t(f'errors.{error.code}')}")
            else:
                _render_report(report)
