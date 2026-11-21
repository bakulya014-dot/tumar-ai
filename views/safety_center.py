"""My Safety Center — one place that turns this session's checks into next steps.

Signed-in users see it in the menu. Everything comes from the session's
check history (report_store), which lives only in this browser session:
Tumar.AI writes no check history to disk, and the page says so.
"""

import streamlit as st

import components
import report_store
from i18n import t
from services import safety_center

TOOL_PAGES = (
    ("views/scam_analyzer.py", "nav.scam", "scam"),
    ("views/url_scanner.py", "nav.url", "url"),
    ("views/image_scanner.py", "nav.image", "image"),
    ("views/breach_checker.py", "nav.breach", "breach"),
)
STATUS_VARIANTS = {"calm": "ok", "watch": "warn", "act": "danger"}
RECENT_LIMIT = 8

components.page_header(t("center.title"), t("center.subtitle"), "shield_person")
st.caption(t("center.scope"))

reports = report_store.history(st.session_state)
snap = safety_center.snapshot(reports)

if snap.status == "empty":
    components.empty_state("shield_person", t("center.empty_title"), t("center.empty_text"))
    cols = st.columns(len(TOOL_PAGES))
    for col, (page, label, icon_name) in zip(cols, TOOL_PAGES):
        with col:
            st.page_link(page, label=t(label), icon=components.icon(icon_name))
    st.stop()

# --- Snapshot ---
components.section_header(t("center.snapshot_title"), icon_name="stats")
components.status_badge(t(f"center.status_{snap.status}"), STATUS_VARIANTS[snap.status])
score_col, checks_col, danger_col = st.columns(3)
with score_col:
    components.stat(
        str(snap.safety_score),
        t("center.score_label"),
        components.metric_variant(snap.safety_score, higher_is_worse=False),
    )
with checks_col:
    components.stat(str(snap.checks), t("center.checks_label"))
with danger_col:
    components.stat(str(snap.dangerous), t("center.dangerous_label"), "danger" if snap.dangerous else "brand")
st.caption(t("center.score_explain"))

# --- Do this now ---
components.section_header(t("center.actions_title"), icon_name="actions")
for number, action in enumerate(safety_center.top_actions(reports, t), start=1):
    st.markdown(f"**{number}.** {action}")

# --- Dangerous findings ---
danger = safety_center.dangerous_findings(reports)
components.section_header(t("center.danger_title"), icon_name="warning")
if danger:
    for report in danger[:RECENT_LIMIT]:
        components.recent_row(
            t("trust.verdict.danger"),
            "danger",
            report.subject_preview,
            t(f"trust.kind.{report.subject_type}"),
            report.created_at.strftime("%H:%M"),
        )
else:
    st.caption(t("center.danger_none"))

# --- Progress this session ---
if len(snap.trend) >= 2:
    components.section_header(t("center.trend_title"), t("center.trend_caption"), icon_name="breakdown")
    st.line_chart({t("center.score_label"): snap.trend}, height=180)

# --- Recent checks ---
components.section_header(t("center.recent_title"), icon_name="history")
for report in reports[:RECENT_LIMIT]:
    components.recent_row(
        t(f"trust.verdict.{report.verdict}"),
        components.TRUST_CHIP_VARIANTS[report.verdict],
        report.subject_preview,
        t(f"trust.kind.{report.subject_type}"),
        report.created_at.strftime("%H:%M"),
    )
if st.button(t("home.recent_clear"), icon=components.icon("delete")):
    report_store.clear(st.session_state)
    st.rerun()
