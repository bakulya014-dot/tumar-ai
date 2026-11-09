"""Launch Film — public presentation assets for Tumar.AI.

The page deliberately serves the film inside the product so a single QR code
can take judges, users, and partners from a physical pitch into a live product
experience. Videos are static assets; no user data is collected to play them.
"""

from pathlib import Path

import streamlit as st

from components import page_header


APP_DIR = Path(__file__).resolve().parent.parent
FILM = APP_DIR / "assets" / "tumar-launch-film.mp4"
ANIMATION = APP_DIR / "assets" / "tumar-launch-animation.mp4"


page_header(
    "🎬 Tumar.AI Launch Film",
    "See the product story, then try the live cybersecurity assistant.",
)

st.caption("No account required. These videos are presentation assets only.")

if FILM.exists():
    st.subheader("Launch film")
    st.video(str(FILM), format="video/mp4")

if ANIMATION.exists():
    st.subheader("Product animation")
    st.video(str(ANIMATION), format="video/mp4")

if not FILM.exists() and not ANIMATION.exists():
    st.info("The launch videos are being prepared. Please check back soon.")

st.page_link("views/home.py", label="Try Tumar.AI", icon="🛡️")
