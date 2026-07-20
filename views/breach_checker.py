"""Email Breach Checker page — has this email appeared in known leaks?

UI only: collect the email, call the breach service, render the
result with the Aura design system. All lookup logic lives in
services/breach_checker.py.
"""

import streamlit as st

import components
from components import page_header
from i18n import t
from services.breach_checker import (
    BreachCheckError,
    EmailBreachResult,
    check_email,
    is_valid_email,
)


def _render_result(result: EmailBreachResult) -> None:
    """Show the lookup outcome in plain language."""
    if not result.breached:
        st.success(t("breach.safe_banner", email=result.email))
        st.caption(t("breach.safe_caption"))
        st.subheader(t("breach.safe_tips_title"))
    else:
        banner = st.error if result.risk_level == "high" else st.warning
        banner(
            t(
                "breach.breached_banner",
                email=result.email,
                count=result.breach_count,
            )
        )

        st.subheader(t("breach.breaches_title"))
        if result.breach_count <= 8:
            components.chip_row(result.breaches, "danger")
        else:
            components.chip_row(result.breaches[:6], "danger")
            with st.expander(t("breach.expander_label", count=result.breach_count)):
                st.write(", ".join(result.breaches))

        st.subheader(t("breach.meaning_title"))
        st.write(t("breach.meaning_text"))

        st.subheader(t("breach.actions_title"))

    for number, key in enumerate(result.recommendations, start=1):
        st.markdown(f"{number}. {t(f'breach.{key}')}")


page_header(t("breach.title"), t("breach.subtitle"))

st.caption(t("breach.privacy_note"))

email = st.text_input(
    t("breach.input_label"),
    placeholder=t("breach.input_placeholder"),
    max_chars=254,
    help=t("breach.input_help"),
)
check_clicked = st.button(
    t("breach.check_button"), type="primary", use_container_width=True
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
                st.error(f"😕 {t(f'errors.{error.code}')}")
            else:
                _render_result(result)
