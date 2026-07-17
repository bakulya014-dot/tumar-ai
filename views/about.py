"""About page — mission, name story, and product principles."""

import streamlit as st

from components import page_header

page_header(
    "ℹ️ About Tumar.AI",
    "Your personal AI companion for a safer digital life.",
)

st.write(
    "**Tumar.AI** exists for one reason: everyday people — not just security "
    "experts — deserve real protection from online scams. We turn "
    "professional security checks into simple tools anyone can use."
)

st.subheader('Why "Tumar"?')
st.write(
    "A **tumar (тұмар)** is a traditional Kazakh amulet, worn to protect its "
    "owner from harm. Tumar.AI is exactly that — a digital amulet that "
    "protects ordinary people from the dangers of the online world."
)

st.subheader("Why it matters")
st.write(
    "Most scam victims are ordinary users, not companies. The tools that "
    "could protect them exist, but they are scattered, technical, and full "
    "of jargon. Tumar.AI puts the essential checks in one friendly place "
    "and explains every result in plain language."
)

st.subheader("Under the hood")
st.markdown(
    """
| Layer | Technology |
| --- | --- |
| Language | Python |
| UI framework | Streamlit |
| AI engine | Google Gemini |
"""
)

st.subheader("Our principles")
st.markdown(
    """
- **Privacy by design** — Tumar.AI does not store anything you type: no database, no logs.
- **Your password stays yours** — it is never sent anywhere in full (see the Password Health page).
- **Honesty** — Tumar.AI is a decision aid, not a guarantee. When in doubt, contact
  your bank or service provider directly through official channels.
"""
)
