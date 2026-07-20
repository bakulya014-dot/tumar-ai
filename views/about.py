"""About page — mission, name story, and product principles."""

import streamlit as st

from components import page_header
from i18n import t

page_header(t("about.title"), t("about.subtitle"))

st.write(t("about.intro"))

st.subheader(t("about.why_tumar_title"))
st.write(t("about.why_tumar_text"))

st.subheader(t("about.matters_title"))
st.write(t("about.matters_text"))

st.subheader(t("about.stack_title"))
st.markdown(t("about.stack_table"))

st.subheader(t("about.principles_title"))
st.markdown(t("about.principles_text"))
