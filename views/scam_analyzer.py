"""Scam Analyzer page — paste a message, get an AI risk verdict.

This file is UI only: it collects input, calls the analysis service,
and renders the validated result. All AI logic lives in
services/scam_analysis.py.
"""

import streamlit as st

from components import page_header
from services.scam_analysis import ScamAnalysis, ScamAnalysisError, analyze_message

MAX_MESSAGE_LENGTH = 5000

EXAMPLE_MESSAGE = (
    "URGENT! Your bank card has been temporarily blocked due to suspicious "
    "activity. To restore access immediately, verify your identity here: "
    "http://secure-bank-verify-kz.com/unlock and enter the SMS code we just "
    "sent you. If you do not act within 30 minutes, your funds will be frozen."
)


def _get_api_key() -> str:
    """Read the Gemini API key from Streamlit's secrets storage."""
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
    except FileNotFoundError:
        # No secrets file at all — treat it the same as a missing key.
        return ""


def _fill_example() -> None:
    """Button callback: put a sample scam message into the input box."""
    st.session_state["scam_message"] = EXAMPLE_MESSAGE


def _render_result(analysis: ScamAnalysis) -> None:
    """Show a validated analysis in a clear, color-coded layout."""
    verdict_styles = {
        "Safe": ("✅", st.success),
        "Suspicious": ("⚠️", st.warning),
        "Dangerous": ("🚨", st.error),
    }
    icon, banner = verdict_styles[analysis.verdict]
    banner(f"{icon} **Verdict: {analysis.verdict}** · Risk score: {analysis.risk_score}/100")
    st.progress(analysis.risk_score / 100, text="Risk level")

    if analysis.red_flags:
        st.subheader("🚩 Red flags detected")
        for flag in analysis.red_flags:
            st.markdown(f"- {flag}")

    st.subheader("💬 What is going on?")
    st.write(analysis.explanation)

    st.subheader("✅ What you should do")
    for number, action in enumerate(analysis.recommended_actions, start=1):
        st.markdown(f"{number}. {action}")


page_header(
    "🔍 Scam Analyzer",
    "Paste a suspicious message — email, SMS, or chat — and let AI judge it.",
)

api_key = _get_api_key()
if not api_key:
    st.error(
        "⚙️ The AI engine is not configured on this installation. "
        "Add your Gemini API key to `.streamlit/secrets.toml` and restart the app."
    )
    st.stop()

message = st.text_area(
    "Suspicious message",
    key="scam_message",
    height=180,
    max_chars=MAX_MESSAGE_LENGTH,
    placeholder="Paste the full text of the suspicious message here…",
)

analyze_col, example_col = st.columns([3, 1])
analyze_clicked = analyze_col.button(
    "🔍 Analyze message", type="primary", use_container_width=True
)
example_col.button(
    "✨ Try an example", on_click=_fill_example, use_container_width=True
)

if analyze_clicked:
    cleaned = message.strip()
    if not cleaned:
        st.warning("The message box is empty — paste a message first.")
    else:
        with st.spinner("Tumar.AI is analyzing the message…"):
            try:
                result = analyze_message(cleaned, api_key=api_key)
            except ScamAnalysisError as error:
                st.error(f"😕 {error}")
            else:
                _render_result(result)
