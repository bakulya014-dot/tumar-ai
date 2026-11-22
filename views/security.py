"""Security & privacy — what Tumar.AI actually does with your data, in plain words.

Every statement here is backed by code and tests (see the PR that added
this page); nothing is aspirational. When a safeguard changes, this
page changes with it.
"""

import streamlit as st

import components
from i18n import t

SECTIONS = (
    ("data", "privacy", ("message", "link", "image", "email", "password", "account")),
    ("ai", "science", ("does", "never", "floor", "text")),
    ("safeguards", "shield", ("limits", "errors", "secrets", "switches", "logs")),
    ("limits", "info", ("no_guarantee", "demo_map", "session", "third_parties")),
)

components.page_header(t("security.title"), t("security.subtitle"), "lock")

for section, icon_name, items in SECTIONS:
    components.section_header(t(f"security.{section}.title"), icon_name=icon_name)
    for item in items:
        st.markdown(f"- {t(f'security.{section}.{item}')}")

st.caption(t("security.footer"))
