"""Password Health page — has this password already leaked?

The password check is under development; until it ships, this page
previews what the finished feature will deliver.
"""

import streamlit as st

from components import coming_soon, page_header

page_header(
    "🔑 Password Health",
    "Check whether a password appears in public breach databases.",
)

st.write("**What you will get:**")
st.markdown(
    """
- Whether the password has appeared in known data leaks
- How many times it has been seen by attackers
- Simple advice on choosing a stronger password
"""
)

st.write(
    "🔒 **Privacy first:** your password is never sent anywhere in full. "
    "We use a technique that shares only a tiny anonymous fingerprint of it "
    "— the full details will be explained right here when the feature ships."
)

coming_soon("The password health check")
