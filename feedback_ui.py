"""Feedback under a result: helpful? actually a scam? a missed scam?

Kept in this browser session only (st.session_state["_feedback"], keyed
by report id). Nothing is sent anywhere and no message content is
collected: the answers are a few words about the result, not the text
that was checked. "Clear current session data" in Settings & Safety
removes them. Durable feedback would need storage, retention rules and
consent wording that the free deployment does not have; until then the
box says plainly that answers stay in this session.
"""

from __future__ import annotations

import streamlit as st

from i18n import t
from services.trust_report import TrustReport

STORE = "_feedback"
HELPFUL = ("yes", "no")
WAS_SCAM = ("yes", "no", "unsure")


def store() -> dict[str, dict[str, str]]:
    return st.session_state.setdefault(STORE, {})


def answers(report: TrustReport) -> dict[str, str]:
    return store().get(report.report_id, {})


def _choice(question: str, options: tuple[str, ...], report: TrustReport) -> None:
    saved = answers(report).get(question)
    widget = f"_w_fb_{question}_{report.report_id}"

    def remember() -> None:
        value = st.session_state.get(widget)
        entry = store().setdefault(report.report_id, {})
        if value:
            entry[question] = value
        else:
            entry.pop(question, None)

    st.segmented_control(
        t(f"feedback.{question}"), options, default=saved, key=widget, on_change=remember,
        format_func=lambda option: t(f"feedback.option.{option}"),
    )


def render(report: TrustReport) -> None:
    """The feedback box, after the result and never before it."""
    with st.container(border=True):
        _choice("helpful", HELPFUL, report)
        _choice("was_scam", WAS_SCAM, report)
        entry = answers(report)
        # A missed scam is a result that did not say "danger" for something that was one.
        if report.verdict != "danger":
            if entry.get("missed") == "yes":
                st.success(t("feedback.missed_thanks"))
            elif st.button(t("feedback.missed_button"), key=f"_w_fb_missed_{report.report_id}"):
                store().setdefault(report.report_id, {})["missed"] = "yes"
                st.success(t("feedback.missed_thanks"))
        if entry.get("helpful") or entry.get("was_scam"):
            st.caption(t("feedback.thanks"))
        st.caption(t("feedback.privacy"))
