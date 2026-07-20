"""Scam Analyzer page — paste a message, get a two-layer risk report.

UI only: it collects input, calls the analysis service, and renders
the validated report with the Aura design system. The deterministic
scanner lives in services/heuristics.py and the AI logic in
services/scam_analysis.py.
"""

import streamlit as st

import components
from components import page_header
from i18n import t
from services.scam_analysis import ScamAnalysisError, ScamReport, analyze_message

MAX_MESSAGE_LENGTH = 5000


def _get_api_key() -> str:
    """Read the Gemini API key from Streamlit's secrets storage."""
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
    except FileNotFoundError:
        # No secrets file at all — treat it the same as a missing key.
        return ""


def _fill_example() -> None:
    """Button callback: put a sample scam message into the input box."""
    st.session_state["scam_message"] = t("scam.example_message")


def _meter_variant(value: int) -> str:
    """Color a 0–100 meter like a verdict: green, amber, red."""
    if value >= 66:
        return "danger"
    if value >= 26:
        return "warn"
    return "ok"


def _render_report(report: ScamReport) -> None:
    """Show the two-layer analysis: AI verdict + deterministic findings."""
    ai = report.ai
    heuristics = report.heuristics

    components.verdict_card(
        ai.verdict,
        t(f"scam.verdict.{ai.verdict.lower()}"),
        ai.risk_score,
        t("scam.metric_risk"),
    )

    confidence_col, urgency_col = st.columns(2)
    with confidence_col:
        components.meter(
            t("scam.metric_confidence"),
            ai.confidence,
            "brand",
            t("scam.metric_confidence_help"),
        )
    with urgency_col:
        components.meter(
            t("scam.metric_urgency"),
            heuristics.urgency_score,
            _meter_variant(heuristics.urgency_score),
            t("scam.metric_urgency_help"),
        )

    if ai.red_flags:
        st.subheader(t("scam.red_flags_title"))
        components.chip_row(ai.red_flags, "danger")

    st.subheader(t("scam.explanation_title"))
    st.write(ai.explanation)

    st.subheader(t("scam.actions_title"))
    for number, action in enumerate(ai.recommended_actions, start=1):
        st.markdown(f"{number}. {action}")

    with st.expander(t("scam.breakdown_title"), expanded=True):
        components.meter(
            t("scam.credential_risk_label"),
            ai.credential_theft_risk,
            _meter_variant(ai.credential_theft_risk),
        )
        components.meter(
            t("scam.financial_risk_label"),
            ai.financial_scam_risk,
            _meter_variant(ai.financial_scam_risk),
        )

        otp = heuristics.otp_requested
        components.kv_chip(
            t("scam.otp_label"),
            t("scam.yes") if otp else t("scam.no"),
            "danger" if otp else "ok",
        )
        if otp:
            st.warning(t("scam.otp_warning"))

        if heuristics.suspicious_urls:
            st.markdown(f"**{t('scam.urls_title')}**")
            for finding in heuristics.suspicious_urls:
                reasons = "; ".join(
                    t(f"scam.url_reason.{code}") for code in finding.reasons
                )
                components.threat_card(finding.url, reasons)

        signal_groups = (
            ("scam.signal_urgency", heuristics.urgency_matches),
            ("scam.signal_credential", heuristics.credential_indicators),
            ("scam.signal_financial", heuristics.financial_indicators),
            ("scam.signal_manipulation", heuristics.manipulation_indicators),
        )
        detected = [(key, matches) for key, matches in signal_groups if matches]
        if detected:
            st.markdown(f"**{t('scam.signals_title')}**")
            for label_key, matches in detected:
                st.caption(t(label_key))
                components.chip_row(matches, "warn")
        elif not heuristics.suspicious_urls and not otp:
            st.caption(t("scam.no_signals"))


page_header(t("scam.title"), t("scam.subtitle"))

api_key = _get_api_key()
if not api_key:
    st.error(t("scam.not_configured"))
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
    t("scam.analyze_button"), type="primary", use_container_width=True
)
example_col.button(
    t("scam.example_button"), on_click=_fill_example, use_container_width=True
)

if analyze_clicked:
    cleaned = message.strip()
    if not cleaned:
        st.warning(t("scam.empty_warning"))
    else:
        with st.spinner(t("scam.spinner")):
            try:
                report = analyze_message(cleaned, api_key=api_key)
            except ScamAnalysisError as error:
                st.error(f"😕 {t(f'errors.{error.code}')}")
            else:
                _render_report(report)
