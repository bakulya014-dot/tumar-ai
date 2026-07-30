"""Home page — what Tumar.AI is, the Quick Check, and where to start.

The Quick Check is the Trust Engine's first consumer: the user pastes
anything (message, link, or email address) and the engine detects what
it is and routes it to the right analyzer. The specialized pages
remain for the full, detail-rich experience of each module.
"""

import streamlit as st

import components
from components import feature_card, render_hero
from i18n import current_language, t
from services.common import ServiceError
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject
from services.trust_report import TrustReport

MAX_QUICK_LENGTH = 5000

# Analyzer kind -> the page with the full version of that check.
_TOOL_PAGES = {
    "email": "views/breach_checker.py",
    "url": "views/url_scanner.py",
    "message": "views/scam_analyzer.py",
}


def _render_quick_report(report: TrustReport, kind: str) -> None:
    """Compact TrustReport rendering: verdict, story, next steps."""
    components.verdict_card(
        components.TRUST_CSS_VARIANTS[report.verdict],
        t(f"trust.verdict.{report.verdict}"),
        report.trust_score,
        t("trust.score_label"),
    )
    # AI modules fill free text; deterministic modules fill full
    # dotted i18n keys — either way one line renders it.
    st.write(report.explanation or t(report.explanation_key))

    actions = report.recommended_actions or [
        t(key) for key in report.recommended_action_keys
    ]
    for number, action in enumerate(actions, start=1):
        st.markdown(f"{number}. {action}")

    page = _TOOL_PAGES.get(kind)
    if page:
        st.page_link(page, label=t("home.quick_full_tool"), icon="➡️")


render_hero("Tumar.AI", t("home.subtitle"))

st.write(t("home.intro"))

st.subheader(t("home.quick_title"))
st.caption(t("home.quick_intro"))

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
            st.markdown(
                t("home.quick_detected", kind=t(f"trust.kind.{analyzer.kind}"))
            )
        with st.spinner(t("home.quick_spinner")):
            try:
                report = engine.analyze(
                    subject,
                    AnalysisContext(api_key=components.get_gemini_api_key()),
                )
            except ServiceError as error:
                st.error(f"😕 {t(f'errors.{error.code}')}")
            else:
                _render_quick_report(report, analyzer.kind if analyzer else "")

st.subheader(t("home.tools_title"))

feature_card(
    "🔍",
    t("home.scam_card_title"),
    t("home.scam_card_text"),
    "views/scam_analyzer.py",
    t("home.scam_card_link"),
)
feature_card(
    "🔗",
    t("home.url_card_title"),
    t("home.url_card_text"),
    "views/url_scanner.py",
    t("home.url_card_link"),
)
feature_card(
    "📧",
    t("home.breach_card_title"),
    t("home.breach_card_text"),
    "views/breach_checker.py",
    t("home.breach_card_link"),
)
feature_card(
    "🔑",
    t("home.password_card_title"),
    t("home.password_card_text"),
    "views/password_checker.py",
    t("home.password_card_link"),
)

st.subheader(t("home.how_title"))

step1, step2, step3 = st.columns(3)
with step1, st.container(border=True, key="tstep_1"):
    st.markdown(t("home.how_step1"))
with step2, st.container(border=True, key="tstep_2"):
    st.markdown(t("home.how_step2"))
with step3, st.container(border=True, key="tstep_3"):
    st.markdown(t("home.how_step3"))
