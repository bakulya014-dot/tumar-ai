"""The personal safety checklist, shared by Settings & Safety and My Safety Center.

Five habits that stop most of the scams Tumar sees. Ticks are kept for
this browser session only, in the same store My Safety Center already
uses for its ticks, so both pages show the same state and "Clear current
session data" removes them together.
"""

import streamlit as st

from i18n import t

HABITS = ("two_factor", "no_codes", "verify_payments", "check_links", "updates")
TICKS = "_res_ticks"  # shared with views/safety_center.py


def ticks() -> dict[str, bool]:
    return st.session_state.setdefault(TICKS, {})


def done_count() -> int:
    store = ticks()
    return sum(bool(store.get(f"habit_{habit}")) for habit in HABITS)


def render() -> None:
    """Five checkboxes, each with a one-line reason, and progress."""
    store = ticks()
    for habit in HABITS:
        name = f"habit_{habit}"
        widget = f"_w_{name}"

        def remember(name: str = name, widget: str = widget) -> None:
            store[name] = bool(st.session_state[widget])

        st.checkbox(
            t(f"checklist.{habit}"), value=store.get(name, False), key=widget,
            on_change=remember, help=t(f"checklist.{habit}_why"),
        )
    st.caption(t("checklist.progress", done=done_count(), total=len(HABITS)))
