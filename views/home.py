"""Home page — what Tumar.AI is and where to start."""

import streamlit as st

from components import feature_card, render_hero
from i18n import t

render_hero("Tumar.AI", t("home.subtitle"))

st.write(t("home.intro"))

st.subheader(t("home.tools_title"))

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
