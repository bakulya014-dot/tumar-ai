"""Email Breach Checker page — has this email appeared in known leaks?

UI only: collect the email, call the breach service, remember the
result, and render it through the shared report view. All lookup logic
lives in services/breach_checker.py.

This page renders the same Trust Report as every other module: before,
it spoke its own visual language (colored banners, no trust score), so
the same email produced a different-looking answer here than through
the home page's Quick Check. In a product about trust, one input must
always produce one answer.
"""

import streamlit as st

import components
import report_store
from components import page_header
from i18n import t
from report_view import render_trust_report
from services.breach_checker import BreachCheckError, check_email, is_valid_email
from services.trust_report import from_breach_result

SOURCE = "breach_checker"

page_header(t("breach.title"), t("breach.subtitle"), "breach")

st.caption(components.labeled("privacy", t("breach.privacy_note")))

email = st.text_input(
    t("breach.input_label"),
    key="breach_email",
    placeholder=t("breach.input_placeholder"),
    max_chars=254,
    help=t("breach.input_help"),
)
check_clicked = st.button(
    t("breach.check_button"), type="primary", use_container_width=True,
    icon=components.icon("search"),
)

if check_clicked:
    cleaned = email.strip()
    if not cleaned:
        st.warning(t("breach.empty_warning"))
    elif not is_valid_email(cleaned.lower()):
        st.warning(t("breach.invalid_warning"))
    else:
        with st.spinner(t("breach.spinner")):
            try:
                result = check_email(cleaned)
            except BreachCheckError as error:
                components.error_view(t(f'errors.{error.code}'))
            else:
                report_store.remember(
                    st.session_state, from_breach_result(result)
                )

# Rendered from the store so the result survives later re-runs.
remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    st.caption(t("breach.checked_label", email=remembered.subject_preview))
    render_trust_report(remembered)
else:
    components.empty_state(
        "breach", t("breach.empty_title"), t("breach.empty_text")
    )
