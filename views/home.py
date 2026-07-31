"""Home — the platform dashboard.

Answers, in this order: what should I do first (Quick Check), what has
happened so far (session figures and recent activity), what else can I
do (the module grid), and how does any of this work (the closing
explainer). The "what is Tumar.AI" story stays short here; the full
version lives on the About page.

Quick Check is the Trust Engine's first consumer: the user pastes
anything and the engine detects what it is and routes it. The
specialized pages remain for the detail-rich version of each module.
"""

import streamlit as st

import components
import report_store
from components import feature_card, render_hero, section_header
from i18n import current_language, t
from report_view import render_trust_report
from services.common import ServiceError
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject

MAX_QUICK_LENGTH = 5000

# How many recent rows the dashboard shows before it stops being a
# summary and starts being a list.
RECENT_LIMIT = 5

# TrustReport.source -> the page with the full version of that check.
_TOOL_PAGES = {
    "breach_checker": "views/breach_checker.py",
    "url_scanner": "views/url_scanner.py",
    "scam_analyzer": "views/scam_analyzer.py",
}

api_key = components.get_gemini_api_key()

render_hero("Tumar.AI", t("home.subtitle"))
st.write(t("home.intro"))

# --- Primary action: one paste box for anything ---

section_header(t("home.quick_title"), t("home.quick_intro"))

quick_input = st.text_area(
    t("home.quick_input_label"),
    key="quick_input",
    height=90,
    max_chars=MAX_QUICK_LENGTH,
    placeholder=t("home.quick_input_placeholder"),
    help=t("home.quick_input_help"),
)

if st.button(t("home.quick_button"), type="primary", use_container_width=True):
    cleaned = quick_input.strip()
    if not cleaned:
        st.warning(t("home.quick_empty"))
    else:
        engine = TrustEngine()
        subject = TrustSubject(content=cleaned, language=current_language())
        analyzer = engine.detect(subject)
        if analyzer:
            st.caption(
                t("home.quick_detected", kind=t(f"trust.kind.{analyzer.kind}"))
            )
        with st.spinner(t("home.quick_spinner")):
            try:
                report = engine.analyze(
                    subject, AnalysisContext(api_key=api_key)
                )
            except ServiceError as error:
                components.error_view(f"😕 {t(f'errors.{error.code}')}")
            else:
                report_store.remember(st.session_state, report)

# Rendered from the store so the verdict survives later re-runs.
latest = report_store.latest(st.session_state)
if latest:
    render_trust_report(latest)
    page = _TOOL_PAGES.get(latest.source)
    if page:
        st.page_link(page, label=t("home.quick_full_tool"), icon="➡️")

# --- This session so far ---

past = report_store.history(st.session_state)
if past:
    summary = report_store.summarize(past)
    section_header(t("home.stats_title"), t("home.stats_scope"))
    checks_col, threats_col, trust_col = st.columns(3)
    with checks_col:
        components.stat(str(summary.checks), t("home.stat_checks"))
    with threats_col:
        components.stat(
            str(summary.threats),
            t("home.stat_threats"),
            "danger" if summary.threats else "brand",
        )
    with trust_col:
        components.stat(f"{summary.average_trust}", t("home.stat_avg_trust"))

    section_header(t("home.recent_title"))
    for report in past[:RECENT_LIMIT]:
        components.recent_row(
            t(f"trust.verdict.{report.verdict}"),
            components.TRUST_CHIP_VARIANTS[report.verdict],
            report.subject_preview,
            t(f"trust.kind.{report.subject_type}"),
            report.created_at.strftime("%H:%M"),
        )
    # Users of a privacy-first product should be able to act on that
    # promise, not just read it.
    if st.button(t("home.recent_clear")):
        report_store.clear(st.session_state)
        st.rerun()
else:
    section_header(t("home.recent_title"))
    components.empty_state(
        "🕒", t("home.recent_empty_title"), t("home.recent_empty_text")
    )

# --- Everything the platform can check ---

section_header(t("home.tools_title"))

tools_left, tools_right = st.columns(2)
with tools_left:
    feature_card(
        "🔍",
        t("home.scam_card_title"),
        t("home.scam_card_text"),
        "views/scam_analyzer.py",
        t("home.scam_card_link"),
    )
    feature_card(
        "📧",
        t("home.breach_card_title"),
        t("home.breach_card_text"),
        "views/breach_checker.py",
        t("home.breach_card_link"),
    )
with tools_right:
    feature_card(
        "🔗",
        t("home.url_card_title"),
        t("home.url_card_text"),
        "views/url_scanner.py",
        t("home.url_card_link"),
    )
    feature_card(
        "🔑",
        t("home.password_card_title"),
        t("home.password_card_text"),
        "views/password_checker.py",
        t("home.password_card_link"),
        badge=t("home.planned_badge"),
    )

# --- Platform status: only what we actually know ---

section_header(t("home.status_title"))
status_left, status_right = st.columns(2)
with status_left:
    components.status_badge(
        t("home.status_ai_ok") if api_key else t("home.status_ai_missing"),
        "ok" if api_key else "warn",
    )
    st.caption(t("home.status_ai_label"))
with status_right:
    components.status_badge(t("home.status_privacy_value"), "ok")
    st.caption(t("home.status_privacy_label"))

# --- How it works, for first-time visitors ---

section_header(t("home.how_title"))

step1, step2, step3 = st.columns(3)
with step1, st.container(border=True, key="tstep_1"):
    st.markdown(t("home.how_step1"))
with step2, st.container(border=True, key="tstep_2"):
    st.markdown(t("home.how_step2"))
with step3, st.container(border=True, key="tstep_3"):
    st.markdown(t("home.how_step3"))

st.caption(t("home.trust_line"))
