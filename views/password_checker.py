"""Password Health page — has this password already leaked?

UI only: collect the password, call the check service, remember the
report, and render it through the shared report view. The k-anonymity
lookup and the strength assessment live in services/password_check.py.

The input has no `key=`: Streamlit mirrors keyed widget values into
session state, and this is the one input in the product whose value
should not sit there any longer than the run that uses it.
"""

import streamlit as st

import components
import report_store
from components import page_header
from i18n import t
from report_view import render_trust_report
from services.password_check import PasswordCheckError, check_password

MAX_PASSWORD_LENGTH = 128
SOURCE = "password_checker"

page_header(t("password.title"), t("password.subtitle"), "password")

st.info(t("password.privacy"), icon=components.icon("privacy"))

password = st.text_input(
    t("password.input_label"),
    type="password",
    max_chars=MAX_PASSWORD_LENGTH,
    placeholder=t("password.input_placeholder"),
    help=t("password.input_help"),
)

check_clicked = st.button(
    t("password.check_button"), type="primary", use_container_width=True,
    icon=components.icon("key"),
)

if check_clicked:
    if not password:
        st.warning(t("password.empty_warning"))
    else:
        with st.spinner(t("password.spinner")):
            try:
                report = check_password(password)
            except PasswordCheckError as error:
                components.error_view(t(f'errors.{error.code}'))
            else:
                # Only the report is remembered. It contains a fixed
                # row of dots, never the password or its length.
                report_store.remember(st.session_state, report)

remembered = report_store.latest(st.session_state, SOURCE)
if remembered:
    render_trust_report(remembered)
    st.caption(components.labeled("info", t("password.method_note")))
else:
    components.empty_state(
        "password", t("password.empty_title"), t("password.empty_text")
    )
