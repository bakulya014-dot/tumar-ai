"""Kazakhstan Threat Map — official internet-fraud statistics.

Shows published figures (services/threat_map_data.py): how many cases are
registered, which schemes they follow, and where. Every figure names its
period and source, listed at the bottom. The visitor's own last check is
matched to one of the official schemes locally; nothing is sent or stored,
and no check is ever added to the figures.
"""

import altair as alt
import streamlit as st

import components
import report_store
from i18n import t
from services import threat_map_data as data


def _n(value: int) -> str:
    """12 345 — a thin-space thousands separator reads the same in every language."""
    return f"{value:,}".replace(",", " ")


def _bars(values: dict[str, int], value_label: str, color: str) -> None:
    """Horizontal bars, largest first, with full-length labels and the value at the end."""
    rows = [{"label": k, "value": v} for k, v in values.items()]
    base = alt.Chart(alt.Data(values=rows)).encode(
        y=alt.Y("label:N", sort="-x", title=None, axis=alt.Axis(labelLimit=320, labelFontSize=13)),
        x=alt.X("value:Q", title=value_label),
    )
    bars = base.mark_bar(color=color, cornerRadiusEnd=4)
    text = base.mark_text(align="left", dx=6, fontSize=13, color="#A8B0C2").encode(text=alt.Text("value:Q", format=","))
    st.altair_chart(
        (bars + text).properties(height=44 * len(rows) + 30),
        width="stretch",
    )


components.page_header(t("map.title"), t("map.subtitle"), "map")
st.info(t("map.official_notice", date=data.AS_OF), icon=components.icon("info"))

# --- Your last check, matched to an official scheme ---
history = report_store.history(st.session_state)
latest_category = next((c for c in (data.categorize(r) for r in history) if c), None)
if latest_category:
    st.info(
        t("map.your_check", category=t(f"map.cat.{latest_category}")),
        icon=components.icon("my_location"),
    )
else:
    st.caption(t("map.no_check"))

# --- Headline numbers ---
components.section_header(t("map.key_title"), icon_name="stats")
tiles = (
    (_n(data.YEAR_2025_TOTAL), t("map.stat_2025", share=data.YEAR_2025_SHARE_PCT), "danger"),
    (_n(data.NATIONAL_TOTAL), t("map.stat_2026", change=data.NATIONAL_CHANGE_PCT), "brand"),
    (f"{data.SHARE_OF_ALL_CRIME_PCT}%", t("map.stat_share"), "danger"),
    (f"{data.CALLS_BLOCKED_2026 // 1_000_000}M", t("map.stat_calls"), "brand"),
)
for row in (tiles[:2], tiles[2:]):
    for col, (value, label, variant) in zip(st.columns(2), row):
        with col:
            components.stat(value, label, variant, stacked=True)
st.caption(t(
    "map.growth_note",
    y2018=_n(data.YEAR_2018_TOTAL), y2025=_n(data.YEAR_2025_TOTAL),
    times=data.YEAR_2025_TOTAL // data.YEAR_2018_TOTAL,
    fraud_share=f"{data.SHARE_OF_ALL_FRAUD_PCT:g}",
    nine=_n(data.NINE_MONTHS_2026_TOTAL), nine_change=data.NINE_MONTHS_CHANGE_PCT,
    sites=_n(data.SITES_BLOCKED_2026), phishing=_n(data.PHISHING_SITES_BLOCKED_2026),
))

# --- National picture, by scheme ---
components.section_header(t("map.national_title"), t("map.scheme_caption"), icon_name="stats")
national = data.national_counts()
_bars({t(f"map.cat.{c}"): national[c] for c in data.CATEGORIES}, t("map.reports_label"), "#8855FF")

# --- By region ---
components.section_header(
    t("map.region_title"), t("map.region_caption", share=data.TOP5_SHARE_PCT), icon_name="map",
)
counted = [r for r in data.REGIONS if r.cases is not None]
_bars({t(f"map.region.{r.key}"): r.cases for r in counted}, t("map.region_cases_label"), "#E5484D")
not_published = t("map.not_published")
rows = [
    {
        t("map.region_label"): t(f"map.region.{r.key}"),
        t("map.region_cases_label"): _n(r.cases) if r.cases is not None else not_published,
        t("map.region_share_label"): f"{r.crime_share:g}%" if r.crime_share is not None else not_published,
    }
    for r in data.REGIONS
]
st.dataframe(rows, hide_index=True, width="stretch")

# --- Anti-fraud Centre ---
components.section_header(
    t("map.antifraud_title"),
    t("map.antifraud_caption", incidents=_n(data.ANTIFRAUD_INCIDENTS),
      loans=_n(data.FRAUD_LOANS_2025), loans_bn=data.FRAUD_LOANS_2025_BN_TENGE),
    icon_name="shield",
)
_bars({t(f"map.af.{k}"): v for k, v in data.ANTIFRAUD_SCHEMES}, t("map.antifraud_share_label"), "#2E90FA")

# --- Sources ---
with st.expander(t("map.sources_title"), icon=components.icon("link")):
    st.markdown("\n".join(
        f"- [{title}]({url}) — {publisher}, {date}" for title, publisher, date, url in data.SOURCES.values()
    ))
st.caption(t("map.method_note"))
