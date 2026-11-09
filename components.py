"""Reusable UI building blocks shared by every page.

Two kinds of helpers live here:

- Streamlit wrappers (page_header, feature_card, section_header).
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

# Platform verdict code -> CSS variant of the Aura components (the
# stylesheet predates the TrustReport schema, so its class names still
# follow the scam analyzer's wording).
TRUST_CSS_VARIANTS = {"safe": "safe", "caution": "suspicious", "danger": "dangerous"}

# Platform verdict code -> chip variant, for compact verdict pills.
TRUST_CHIP_VARIANTS = {"safe": "ok", "caution": "warn", "danger": "danger"}

# One icon language for the whole product: Google's Material Symbols
# (Rounded), the vector set Streamlit itself ships. Emoji render
# differently on every OS and read as playful; a single outlined set
# reads as one designed system. Pages name icons by meaning ("scam",
# "history"); this table is the only place that knows the glyph.
ICONS = {
    "brand": "shield",
    "home": "space_dashboard",
    "scam": "manage_search",
    "url": "link",
    "image": "image_search",
    "breach": "alternate_email",
    "password": "password",
    "film": "movie",
    "about": "info",
    "quick": "bolt",
    "stats": "monitoring",
    "history": "history",
    "delete": "delete",
    "status": "monitor_heart",
    "explain": "forum",
    "flags": "flag",
    "actions": "task_alt",
    "breakdown": "analytics",
    "signals": "science",
    "evidence": "fact_check",
    "privacy": "lock",
    "contribute": "volunteer_activism",
    "done": "check_circle",
    "language": "translate",
    "next": "arrow_forward",
    "error": "error",
    "warning": "warning",
    "key": "key",
    "info": "info",
    "example": "auto_awesome",
    "search": "search",
    "settings": "settings",
    "tips": "tips_and_updates",
}


def icon(name: str) -> str:
    """Streamlit's Markdown shortcode for a named icon (labels, titles, icon=)."""
    return f":material/{ICONS.get(name, name)}:"


def icon_html(name: str, extra_class: str = "") -> str:
    """The same icon as an HTML span, for the custom HTML components."""
    glyph = html.escape(ICONS.get(name, name))
    cls = f"t-ms {extra_class}".strip()
    return f'<span class="{cls}" aria-hidden="true">{glyph}</span>'


def labeled(name: str, text: str) -> str:
    """`text` with its icon in front, for Markdown-rendered labels."""
    return f"{icon(name)} {text}"


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


def get_gemini_api_key() -> str:
    """Read the Gemini API key from Streamlit's secrets storage.

    Shared by every AI-powered page so secret handling lives in one
    place; services never read secrets themselves — the key is always
    passed in by the UI layer.
    """
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
    except FileNotFoundError:
        # No secrets file at all — treat it the same as a missing key.
        return ""


def page_header(title: str, subtitle: str, icon_name: str = "brand") -> None:
    """A consistent page header: icon tile, title and subtitle.

    The tile carries the page's icon in the brand cyan, with a slow
    sheen sweep (styles.css .t-page-icon) as its micro-animation.
    """
    st.markdown(
        f'<div class="t-page-head">'
        f'<div class="t-page-icon">{icon_html(icon_name)}</div>'
        f'<div class="t-page-text"><h1>{html.escape(title)}</h1>'
        f"<p>{html.escape(subtitle)}</p></div></div>",
        unsafe_allow_html=True,
    )
    st.divider()


def feature_card(
    icon_name: str,
    title: str,
    description: str,
    page_path: str,
    link_label: str,
    badge: str = "",
) -> None:
    """Render one glass feature card with a link to its page.

    The container key becomes a stable `st-key-tcard_*` CSS class
    that assets/styles.css targets for the glass + hover styling.

    `badge` marks a module that is not finished yet. A card that looks
    identical to a working one, but leads to a placeholder, is a small
    broken promise — so unbuilt modules say so on the card itself.
    """
    slug = page_path.rsplit("/", 1)[-1].removesuffix(".py")
    with st.container(border=True, key=f"tcard_{slug}"):
        st.markdown(
            f'<div class="t-card-head"><span class="t-card-icon">{icon_html(icon_name)}</span>'
            f"<h3>{html.escape(title)}</h3></div>",
            unsafe_allow_html=True,
        )
        if badge:
            status_badge(badge, "gold")
        st.write(description)
        st.page_link(page_path, label=link_label, icon=icon("next"))


def recent_row(
    verdict_label: str,
    variant: str,
    preview: str,
    kind_label: str,
    time_label: str,
) -> None:
    """One line of recent activity: verdict, what was checked, when.

    `preview` is already masked and truncated by the TrustReport
    schema, so this row can never widen what the report exposed.
    """
    st.markdown(
        f'<div class="t-recent"><span class="t-chip t-chip--{variant}">'
        f"{html.escape(verdict_label)}</span>"
        f'<span class="t-recent-main">{html.escape(preview)}</span>'
        f'<span class="t-recent-kind">{html.escape(kind_label)}</span>'
        f'<span class="t-recent-time">{html.escape(time_label)}</span></div>',
        unsafe_allow_html=True,
    )


def section_header(title: str, caption: str = "", icon_name: str = "") -> None:
    """One consistent section heading across every page."""
    st.subheader(labeled(icon_name, title) if icon_name else title)
    if caption:
        st.caption(caption)


def status_badge(label: str, variant: str = "neutral") -> None:
    """A single status pill — platform status, module state, verdicts."""
    suffix = "" if variant == "neutral" else f" t-chip--{variant}"
    st.markdown(
        f'<div class="t-chips"><span class="t-chip{suffix}">'
        f"{html.escape(label)}</span></div>",
        unsafe_allow_html=True,
    )


def stat(value: str, label: str, variant: str = "brand") -> None:
    """A dashboard stat tile (styles.css .t-stat)."""
    modifier = "" if variant == "brand" else f" t-stat--{variant}"
    st.markdown(
        f'<div class="t-stat{modifier}"><span class="t-stat-value">'
        f'{html.escape(value)}</span><span class="t-stat-label">'
        f"{html.escape(label)}</span></div>",
        unsafe_allow_html=True,
    )


def empty_state(icon_name: str, title: str, text: str) -> None:
    """Shown where content will appear once the user acts.

    An empty area leaves users wondering whether something is broken;
    a named empty state tells them what will show up and why. The
    illustration is a small "standing watch" radar: concentric rings,
    a slow sweep, and the module's icon at the centre.
    """
    st.markdown(
        f'<div class="t-empty"><div class="t-radar" aria-hidden="true">'
        f'<span class="t-radar-ring"></span><span class="t-radar-ring r2"></span>'
        f'<span class="t-radar-sweep"></span>{icon_html(icon_name, "t-radar-icon")}</div>'
        f'<div class="t-empty-title">{html.escape(title)}</div>'
        f'<div class="t-empty-text">{html.escape(text)}</div></div>',
        unsafe_allow_html=True,
    )


def error_view(message: str, hint: str = "") -> None:
    """The one way this product reports a failure."""
    st.error(message, icon=icon("error"))
    if hint:
        st.caption(hint)


def metric_variant(value: int, higher_is_worse: bool = True) -> str:
    """Map a 0–100 value to a meter color, respecting its semantics."""
    level = value if higher_is_worse else 100 - value
    if level >= 66:
        return "danger"
    if level >= 26:
        return "warn"
    return "ok"


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
      <path class="t-amulet-check" d="M34 54 l10 10 l19 -23" fill="none" stroke="#7DE9FF"
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


def threat_card(url: str, reasons: str) -> None:
    """One suspicious URL with plain-language reasons underneath."""
    st.markdown(
        f'<div class="t-threat"><div class="t-threat-url">{html.escape(url)}</div>'
        f'<div class="t-threat-why">{html.escape(reasons)}</div></div>',
        unsafe_allow_html=True,
    )
