"""Tumar.AI — AI-powered cybersecurity assistant.

Entry point for the Streamlit app: sets global page settings, loads
the Aura design system, builds the sidebar navigation and language
selector, and runs the selected page.

Run with:
    streamlit run app.py
"""

from pathlib import Path

import streamlit as st

from components import load_styles
from i18n import LANGUAGES, t

# Folder that contains this file — lets us load assets reliably
# no matter which folder the app was started from.
APP_DIR = Path(__file__).parent

# Global settings, applied once and shared by every page.
st.set_page_config(
    page_title="Tumar.AI",
    page_icon="🛡️",
    # Wide, so the dashboard can lay out real columns. styles.css caps
    # the container at a readable width and caps prose lines, so wide
    # buys dashboard room without producing 130-character text lines.
    layout="wide",
    initial_sidebar_state="expanded",
)

# Aura design system: stylesheet + ambient aurora background.
load_styles()

# Logo shown at the top of the sidebar on every page.
st.logo(str(APP_DIR / "assets" / "logo.svg"), size="large")

# Deep links like ?lang=ru open the app in that language. The user's
# own selector choice (stored in session state) always wins afterward.
requested_language = st.query_params.get("lang")
if requested_language in LANGUAGES and "language" not in st.session_state:
    st.session_state["language"] = requested_language

# Each st.Page links one file in views/ to one entry in the sidebar
# menu. Titles go through t() so the menu follows the chosen language.
#
# Pages are grouped into sections rather than listed flat: the roadmap
# adds many more modules, and a flat list stops being scannable at
# around eight entries. New modules join an existing section — or add
# one — without the menu needing a redesign.
pages = {
    t("nav.section_overview"): [
        st.Page("views/home.py", title=t("nav.home"), icon="🏠", default=True),
    ],
    t("nav.section_analyze"): [
        st.Page("views/scam_analyzer.py", title=t("nav.scam"), icon="🔍"),
        st.Page("views/url_scanner.py", title=t("nav.url"), icon="🔗"),
        st.Page("views/image_scanner.py", title=t("nav.image"), icon="🖼️"),
    ],
    t("nav.section_monitor"): [
        st.Page("views/breach_checker.py", title=t("nav.breach"), icon="📧"),
        st.Page("views/password_checker.py", title=t("nav.password"), icon="🔑"),
    ],
    t("nav.section_platform"): [
        st.Page("views/about.py", title=t("nav.about"), icon="ℹ️"),
    ],
}

selected_page = st.navigation(pages)

# Language selector + footer, shown below the navigation menu.
with st.sidebar:
    st.divider()
    st.selectbox(
        t("app.language_label"),
        options=list(LANGUAGES),
        format_func=LANGUAGES.get,
        key="language",
    )
    st.caption(t("app.tagline"))
    st.caption(t("app.version_caption"))

selected_page.run()
