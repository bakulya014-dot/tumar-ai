"""AI Security Check page — is this text trying to manipulate an AI?

UI only: collect the text and its context, call the Trust Engine with
declared_kind="ai_content", remember the result, and render it through
the shared report view. Detection lives in services/ai_security/.
"""

import streamlit as st

import components
import quota_ui
import report_store
from components import page_header
from i18n import current_language, t
from report_view import render_trust_report
from services.ai_security import CONTEXTS
from services.common import ServiceError
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject

MAX_CONTENT_LENGTH = 8000  # below the engine's 10,000-character backstop
MAX_TASK_LENGTH = 300
SOURCE = "ai_security"
KIND = "ai_content"

# Example button -> (context, text key, task key)
_EXAMPLES = {
    "ticket": ("document", "ais.example.ticket", ""),
    "supplier": ("document", "ais.example.supplier", ""),
    "tool": ("tool", "ais.example.tool", "ais.example.tool_task"),
}


def _fill(example: str) -> None:
    context, text_key, task_key = _EXAMPLES[example]
    st.session_state["ais_context"] = context
    st.session_state["ais_text"] = t(text_key)
    st.session_state["ais_task"] = t(task_key) if task_key else ""


page_header(t("ais.title"), t("ais.subtitle"), "smart_toy")

api_key = components.get_gemini_api_key()
if not api_key:
    st.info(t("ais.not_configured"), icon=components.icon("info"))

context = st.selectbox(
    t("ais.context_label"),
    CONTEXTS,
    key="ais_context",
    format_func=lambda c: t(f"ais.context.{c}"),
    help=t("ais.context_help"),
)
text = st.text_area(
    t("ais.input_label"),
    key="ais_text",
    height=200,
    max_chars=MAX_CONTENT_LENGTH,
    placeholder=t("ais.input_placeholder"),
    help=t("ais.input_help"),
)
task = ""
if context == "tool":
    task = st.text_input(
        t("ais.task_label"),
        key="ais_task",
        max_chars=MAX_TASK_LENGTH,
        placeholder=t("ais.task_placeholder"),
        help=t("ais.task_help"),
    )
st.caption(t("ais.static_note"))

analyze_clicked = st.button(
    t("ais.analyze_button"), type="primary", use_container_width=True, icon=components.icon("smart_toy"),
)
st.caption(t("ais.examples_label"))
for column, example in zip(st.columns(3), _EXAMPLES):
    column.button(
        t(f"ais.example_button.{example}"), on_click=_fill, args=(example,),
        use_container_width=True, icon=components.icon("example"),
    )

if analyze_clicked:
    cleaned = text.strip()
    if not cleaned:
        st.warning(t("ais.empty_warning"))
    elif not quota_ui.allow_check(KIND):
        pass
    else:
        with st.spinner(t("ais.spinner")):
            try:
                report = TrustEngine().analyze(
                    TrustSubject(
                        content=cleaned,
                        declared_kind=KIND,
                        language=current_language(),
                        hints={"context": context, "task": task.strip()},
                    ),
                    AnalysisContext(api_key=api_key, offline_fallback=True, channel="web"),
                )
            except ServiceError as error:
                quota_ui.settle(KIND, failed=True)
                components.error_view(t(f"errors.{error.code}"))
            else:
                quota_ui.settle(KIND, report)
                report_store.remember(st.session_state, report)

remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    render_trust_report(remembered)
else:
    components.empty_state("smart_toy", t("ais.empty_title"), t("ais.empty_text"))
