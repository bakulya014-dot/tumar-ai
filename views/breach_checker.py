"""Email Breach Checker page — has this email appeared in known leaks?

The breach-lookup service is under development; until it ships, this
page previews what the finished feature will deliver.
"""

import streamlit as st

from components import coming_soon, page_header

page_header(
    "📧 Email Breach Checker",
    "Check whether your email address appears in known public data breaches.",
)

st.write("**What you will get:**")
st.markdown(
    """
- Whether your email was found in any known breach
- Which services leaked it, and when
- What the risks are — and what you should do next
"""
)

coming_soon("The breach lookup service")
