"""Home page — what Tumar.AI is and where to start."""

import streamlit as st

from components import feature_card, page_header

page_header(
    "🛡️ Tumar.AI",
    "Your digital tumar — a personal AI amulet against online scams.",
)

st.write(
    "Online scams get smarter every year — fake bank messages, phishing "
    "links, leaked passwords. **Tumar.AI** checks the danger for you and "
    "explains it in plain language. No security degree required."
)

st.subheader("What can I do here?")

feature_card(
    "🔍",
    "Scam Analyzer",
    "Paste a suspicious message and AI will rate how dangerous it is, "
    "spot the manipulation tricks, and tell you exactly what to do.",
    "views/scam_analyzer.py",
    "Analyze a message",
)
feature_card(
    "📧",
    "Email Breach Checker",
    "Find out whether your email address appears in known data breaches — "
    "and what to do if it does.",
    "views/breach_checker.py",
    "Check my email",
)
feature_card(
    "🔑",
    "Password Health",
    "Check whether a password has already leaked to the internet — without "
    "your password ever leaving your device unprotected.",
    "views/password_checker.py",
    "Test a password",
)

st.subheader("How it works")

step1, step2, step3 = st.columns(3)
step1.markdown("**1. Pick a tool**  \nChoose a check in the sidebar.")
step2.markdown("**2. Paste your data**  \nA message, an email, or a password.")
step3.markdown("**3. Get plain advice**  \nA clear verdict and simple next steps.")
