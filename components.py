"""Reusable UI building blocks shared by every page.

Keeping these in one place means a design change here updates
the whole app — no copy-pasted layout code on individual pages.
"""

import streamlit as st


def page_header(title: str, subtitle: str) -> None:
    """Render a consistent title and subtitle at the top of a page."""
    st.title(title)
    st.caption(subtitle)
    st.divider()


def feature_card(
    icon: str,
    title: str,
    description: str,
    page_path: str,
    link_label: str,
) -> None:
    """Render one bordered feature card with a link to its page."""
    with st.container(border=True):
        st.subheader(f"{icon} {title}")
        st.write(description)
        st.page_link(page_path, label=link_label, icon="➡️")


def coming_soon(feature_name: str) -> None:
    """Friendly placeholder for features that are not released yet."""
    st.info(f"🚧 **{feature_name}** is under active development — coming soon.")
