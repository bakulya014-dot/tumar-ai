"""Kazakhstan Threat Map — prototype on simulated data, labelled as such.

Shows how scam categories could be tracked across regions once
anonymised aggregate counts exist. Today every figure is simulated
(services/threat_map_demo.py), and the page says so before anything
else. The visitor's own last check is matched to a category locally;
nothing is sent or stored.
"""

import streamlit as st

import components
import report_store
from i18n import t
from services import threat_map_demo as demo

components.page_header(t("map.title"), t("map.subtitle"), "map")
st.warning(t("map.demo_notice"), icon=components.icon("info"))

# --- Your last check, as part of the wider picture ---
history = report_store.history(st.session_state)
latest_category = next((c for c in (demo.categorize(r) for r in history) if c), None)
if latest_category:
    st.info(
        t("map.your_check", category=t(f"map.cat.{latest_category}")),
        icon=components.icon("my_location"),
    )
else:
    st.caption(t("map.no_check"))

# --- National picture ---
components.section_header(t("map.national_title"), t("map.week_caption"), icon_name="stats")
national = demo.national_counts()
st.bar_chart(
    {t("map.reports_label"): {t(f"map.cat.{c}"): national[c] for c in demo.CATEGORIES}},
    horizontal=True,
    height=260,
    color="#8855FF",
)

# --- By region ---
components.section_header(t("map.region_title"), t("map.week_caption"), icon_name="map")
regions = demo.region_counts()
rows = [
    {t("map.region_label"): t(f"map.region.{r}"), **{t(f"map.cat.{c}"): regions[r][c] for c in demo.CATEGORIES}}
    for r in demo.REGIONS
]
st.dataframe(rows, hide_index=True, width="stretch")

st.caption(t("map.method_note"))
