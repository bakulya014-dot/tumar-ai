"""Launch Film — public presentation assets for Tumar.AI.

The page deliberately serves the film inside the product so a single QR code
can take judges, users, and partners from a physical pitch into a live product
experience. Videos are static assets; no user data is collected to play them.
"""

from pathlib import Path

import streamlit as st

from components import icon, page_header
from i18n import t


APP_DIR = Path(__file__).resolve().parent.parent
FILM = APP_DIR / "assets" / "tumar-launch-film.mp4"
ANIMATION = APP_DIR / "assets" / "tumar-launch-animation.mp4"


page_header(t("film.title"), t("film.subtitle"), "film")

st.caption(t("film.caption"))

if FILM.exists():
    st.subheader(t("film.film_heading"))
    st.video(str(FILM), format="video/mp4")

if ANIMATION.exists():
    st.subheader(t("film.animation_heading"))
    st.video(str(ANIMATION), format="video/mp4")

if not FILM.exists() and not ANIMATION.exists():
    st.info(t("film.pending"))

st.page_link("views/home.py", label=t("film.try_link"), icon=icon("brand"))
