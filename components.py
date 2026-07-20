"""Reusable UI building blocks shared by every page.

Two kinds of helpers live here:

- Streamlit wrappers (page_header, feature_card, coming_soon).
- "Aura" design-system components (hero, gauge, meters, chips,
  threat cards) that render custom HTML.

Every dynamic value injected into HTML is escaped with html.escape()
— a security product must never ship an XSS hole in its own UI.
"""

import html
from pathlib import Path

import streamlit as st

from i18n import t

_APP_DIR = Path(__file__).parent

# 2π × r(54) — kept in sync with the gauge SVG radius below.
_GAUGE_CIRCUMFERENCE = 339.3


@st.cache_data(show_spinner=False)
def _styles() -> str:
    """Read the stylesheet once per server process."""
    return (_APP_DIR / "assets" / "styles.css").read_text(encoding="utf-8")


def load_styles() -> None:
    """Inject the Aura stylesheet and the ambient aurora background."""
    st.markdown(f"<style>{_styles()}</style>", unsafe_allow_html=True)
    st.markdown(
        '<div class="t-aurora" aria-hidden="true">'
        "<span></span><span></span><span></span></div>",
        unsafe_allow_html=True,
    )


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
    """Render one glass feature card with a link to its page.

    The container key becomes a stable `st-key-tcard_*` CSS class
    that assets/styles.css targets for the glass + hover styling.
    """
    slug = page_path.rsplit("/", 1)[-1].removesuffix(".py")
    with st.container(border=True, key=f"tcard_{slug}"):
        st.subheader(f"{icon} {title}")
        st.write(description)
        st.page_link(page_path, label=link_label, icon="➡️")


def coming_soon(feature_name: str) -> None:
    """Friendly placeholder for features that are not released yet."""
    st.info(t("common.coming_soon", feature=feature_name))


def render_hero(title: str, subtitle: str) -> None:
    """Home hero: the pulsing tumar amulet and a gradient headline."""
    st.markdown(
        f"""
<div class="t-hero">
  <div class="t-amulet" role="img" aria-label="{html.escape(title)}">
    <span class="t-aura"></span><span class="t-aura a2"></span><span class="t-aura a3"></span>
    <svg class="t-amulet-svg" viewBox="0 0 96 96" aria-hidden="true">
      <defs>
        <linearGradient id="t-amulet-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#F5C97B"/>
          <stop offset="1" stop-color="#22D3EE"/>
        </linearGradient>
      </defs>
      <path d="M48 8 L86 74 A6 6 0 0 1 81 83 H15 A6 6 0 0 1 10 74 Z"
            fill="rgba(34,211,238,0.06)" stroke="url(#t-amulet-grad)"
            stroke-width="2.5" stroke-linejoin="round"/>
      <path d="M34 54 l10 10 l19 -23" fill="none" stroke="#7DE9FF"
            stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  </div>
  <h1 class="t-hero-title">{html.escape(title)}</h1>
  <p class="t-hero-sub">{html.escape(subtitle)}</p>
</div>
""",
        unsafe_allow_html=True,
    )


def verdict_card(
    verdict: str, verdict_label: str, score: int, score_label: str
) -> None:
    """Big verdict summary: animated risk gauge + colored verdict chip.

    `verdict` is schema-enforced upstream (Safe/Suspicious/Dangerous),
    so it is safe to use as a CSS class suffix.
    """
    variant = verdict.lower()
    chip = {"safe": "ok", "suspicious": "warn", "dangerous": "danger"}[variant]
    offset = _GAUGE_CIRCUMFERENCE * (1 - score / 100)
    st.markdown(
        f"""
<div class="t-verdict t-verdict--{variant}">
  <div class="t-gauge t-gauge--{variant}" role="img"
       aria-label="{html.escape(score_label)}: {score}/100">
    <svg width="128" height="128" viewBox="0 0 128 128">
      <circle class="t-gauge-track" cx="64" cy="64" r="54" fill="none" stroke-width="10"/>
      <circle class="t-gauge-fill" cx="64" cy="64" r="54" fill="none" stroke-width="10"
              stroke-dasharray="{_GAUGE_CIRCUMFERENCE:.1f}"
              stroke-dashoffset="{offset:.1f}"/>
    </svg>
    <div class="t-gauge-value">{score}</div>
  </div>
  <div class="t-verdict-info">
    <span class="t-chip t-chip--{chip}">{html.escape(verdict_label)}</span>
    <span class="t-verdict-score">{html.escape(score_label)}: {score}/100</span>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def meter(label: str, value: int, variant: str = "brand", tooltip: str = "") -> None:
    """Animated horizontal meter (0–100) with an uppercase micro-label."""
    title_attr = f' title="{html.escape(tooltip)}"' if tooltip else ""
    st.markdown(
        f"""
<div class="t-meter t-meter--{variant}"{title_attr}>
  <div class="t-meter-head"><span>{html.escape(label)}</span><b>{value}/100</b></div>
  <div class="t-meter-track"><span class="t-meter-fill" style="width:{value}%"></span></div>
</div>
""",
        unsafe_allow_html=True,
    )


def chip_row(labels: list[str], variant: str = "neutral") -> None:
    """A wrapping row of pill chips."""
    suffix = "" if variant == "neutral" else f" t-chip--{variant}"
    chips = "".join(
        f'<span class="t-chip{suffix}">{html.escape(label)}</span>'
        for label in labels
    )
    st.markdown(f'<div class="t-chips">{chips}</div>', unsafe_allow_html=True)


def kv_chip(label: str, value: str, variant: str) -> None:
    """One 'label → value chip' row, e.g. OTP requested → Yes."""
    st.markdown(
        f'<div class="t-kv"><span class="t-kv-label">{html.escape(label)}</span>'
        f'<span class="t-chip t-chip--{variant}">{html.escape(value)}</span></div>',
        unsafe_allow_html=True,
    )


def threat_card(url: str, reasons: str) -> None:
    """One suspicious URL with plain-language reasons underneath."""
    st.markdown(
        f'<div class="t-threat"><div class="t-threat-url">{html.escape(url)}</div>'
        f'<div class="t-threat-why">{html.escape(reasons)}</div></div>',
        unsafe_allow_html=True,
    )
