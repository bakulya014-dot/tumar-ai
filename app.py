"""Tumar.AI — AI-powered cybersecurity assistant.

Entry point for the Streamlit app: sets global page settings,
builds the sidebar navigation, and runs the selected page.

Run with:
    streamlit run app.py
"""

from pathlib import Path

import streamlit as st

# Folder that contains this file — lets us load assets reliably
# no matter which folder the app was started from.
APP_DIR = Path(__file__).parent

# Global settings, applied once and shared by every page.
st.set_page_config(
    page_title="Tumar.AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# Logo shown at the top of the sidebar on every page.
st.logo(str(APP_DIR / "assets" / "logo.svg"), size="large")

# Each st.Page links one file in views/ to one entry in the sidebar menu.
pages = [
    st.Page("views/home.py", title="Home", icon="🏠", default=True),
    st.Page("views/scam_analyzer.py", title="Scam Analyzer", icon="🔍"),
    st.Page("views/breach_checker.py", title="Email Breach Checker", icon="📧"),
    st.Page("views/password_checker.py", title="Password Health", icon="🔑"),
    st.Page("views/about.py", title="About", icon="ℹ️"),
]

selected_page = st.navigation(pages)

# Extra sidebar content, shown below the navigation menu.
with st.sidebar:
    st.divider()
    st.caption("🛡️ Tumar.AI — your digital amulet against online scams.")
    st.caption("v0.1.0 · Early preview")

selected_page.run()
