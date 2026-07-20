"""Password Health page — has this password already leaked?

The password check is under development; until it ships, this page
previews what the finished feature will deliver.
"""

import streamlit as st

from components import coming_soon, page_header
from i18n import t

page_header(t("password.title"), t("password.subtitle"))

st.write(f"**{t('password.what_title')}**")
st.markdown(t("password.bullets"))

st.write(t("password.privacy"))

coming_soon(t("password.feature_name"))
