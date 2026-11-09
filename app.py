"""Tumar.AI — AI-powered cybersecurity assistant.

Entry point for the Streamlit app: sets global page settings, loads
the Aura design system, builds the sidebar navigation and language
selector, and runs the selected page.

Run with:
    streamlit run app.py
"""

import os
from pathlib import Path

import streamlit as st

import auth
from components import load_styles
from i18n import LANGUAGES, t

# Provider keys are read from the environment, so that services stay
# free of any secret-storage details and work identically under the
# API, the CLI and the test suite. Streamlit keeps its secrets
# elsewhere, so bridge them across once at startup.
#
# Only names are listed here — never a value, and nothing is logged.
# Existing environment variables win, so a deployment can override the
# secrets file without editing it.
_PROVIDER_SECRETS = (
    "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "DEEPSEEK_MODEL",
    "DEEPSEEK_VISION",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "TUMAR_TEXT_PROVIDER",
    "TUMAR_VISION_PROVIDER",
)

for _name in _PROVIDER_SECRETS:
    if os.environ.get(_name):
        continue
    try:
        _value = st.secrets.get(_name, "")
    except FileNotFoundError:  # no secrets file on this installation
        break
    if _value:
        os.environ[_name] = str(_value)

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

# Deep links like ?lang=ru open the app in that language. The user's
# own selector choice (stored in session state) always wins afterward.
requested_language = st.query_params.get("lang")
if requested_language in LANGUAGES and "language" not in st.session_state:
    st.session_state["language"] = requested_language

# The landing page and the sidebar each draw a language selector bound
# to the same "language" key. They are different widgets, so when the
# landing selector disappears Streamlit would delete its value and the
# sidebar would fall back to English. Re-assigning the value at the top
# of every run detaches it from any one widget, so a language chosen on
# the landing page survives sign-in or guest entry.
if "language" in st.session_state:
    st.session_state["language"] = st.session_state["language"]

# Each st.Page links one file in views/ to one entry in the sidebar
# menu. Titles go through t() so the menu follows the chosen language.
#
# Pages are grouped into sections rather than listed flat: the roadmap
# adds many more modules, and a flat list stops being scannable at
# around eight entries. New modules join an existing section — or add
# one — without the menu needing a redesign.
#
# Visitors who have neither signed in with Google nor chosen guest mode
# see only the public landing page — no sidebar, no tools yet.
if not auth.has_access():
    st.navigation(
        [st.Page("views/landing.py", title="Tumar.AI", icon="🛡️", default=True)],
        position="hidden",
    ).run()
    st.stop()

# Logo shown at the top of the sidebar on every app page (the landing
# page draws its own).
st.logo(str(APP_DIR / "assets" / "logo.svg"), size="large")

# First run after Google sign-in: register (or refresh) the user and
# greet them once.
_new_user = auth.record_registration()
if _new_user is not None:
    _first_name = (auth.user_display()[0] or "").split(" ")[0] or "👋"
    st.toast(
        t("account.welcome_new" if _new_user else "account.welcome_back", name=_first_name),
        icon="🛡️",
    )

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
        st.Page(
            "views/launch_film.py",
            title="Launch Film",
            icon="🎬",
            url_path="launch-film",
        ),
        st.Page("views/about.py", title=t("nav.about"), icon="ℹ️"),
    ],
}

selected_page = st.navigation(pages)

# Language selector + footer, shown below the navigation menu.
with st.sidebar:
    st.divider()
    _name, _email = auth.user_display()
    if _email:
        st.caption(t("account.signed_in_as", name=_name or _email))
        st.caption(_email)
    else:
        st.caption(t("account.guest"))
        st.button(
            t("account.create_account"),
            on_click=auth.sign_in,
            use_container_width=True,
            type="primary",
        )
        if st.session_state.pop("tumar_auth_missing", False):
            st.warning(t("landing.auth_missing"))
    st.button(t("account.sign_out"), on_click=auth.sign_out, use_container_width=True)
    st.selectbox(
        t("app.language_label"),
        options=list(LANGUAGES),
        format_func=LANGUAGES.get,
        key="language",
    )
    st.caption(t("app.tagline"))
    st.caption(t("app.version_caption"))

selected_page.run()
