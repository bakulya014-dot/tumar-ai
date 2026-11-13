"""Landing — the public front door shown before sign-in.

Tells a first-time visitor who Tumar.AI is for, why it beats the usual
guesswork, and how it works, then offers two ways in: register with
Google, or try the tools as a guest. Every string goes through t(), and
every value placed in HTML is escaped. No emoji or pictograms are drawn
here: markers are plain CSS shapes, so the page reads the same on every
platform.
"""

import html
import unicodedata
from pathlib import Path

import streamlit as st

import auth
import branding
from i18n import LANGUAGES, t

_ASSETS = Path(__file__).resolve().parent.parent / "assets"

_AUDIENCES = ("parents", "students", "seniors", "business", "freelancers", "shoppers")
_MARQUEE = (
    "parents", "students", "seniors", "business", "freelancers",
    "shoppers", "teachers", "creators", "remote",
)
_OLD_TOOLS = ("search", "virustotal", "hibp", "family_chat", "notebook", "ignore")
_OLD_PAINS = ("lost_money", "hijacked", "leaked")
_FEATURES = ("threat", "kanon", "xon", "bot")
_TUMAR_WINS = ("verdict", "plain", "private")
_STEPS = ("paste", "check", "act")
_PRIVACY = ("redact", "never_sold", "k_anon")
# The five tools, in the brand poster's order, with their Material icon.
_TOOLS = (
    ("scam", "psychology"), ("url", "link"), ("image", "image_search"),
    ("breach", "mail"), ("trust", "verified_user"),
)
_STRIP = (("ai", "memory"), ("rules", "policy"), ("lang", "translate"), ("api", "api"))


def _plain(text: str) -> str:
    """Drop pictographs (emoji, variation selectors) and surrounding space."""
    kept = (
        ch for ch in text
        if unicodedata.category(ch) != "So" and not 0xFE00 <= ord(ch) <= 0xFE0F
    )
    return "".join(kept).strip()


def e(key: str, **kw: object) -> str:
    """Translate, strip pictographs, and HTML-escape."""
    return html.escape(_plain(t(key, **kw)))


def _html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def _cta_row(suffix: str) -> None:
    """The two ways in. Real Streamlit buttons, since st.login needs one."""
    _, left, right, _ = st.columns([1, 1.25, 1.25, 1])
    with left:
        st.button(
            t("landing.cta_google"),
            key=f"cta_google_{suffix}",
            on_click=auth.sign_in,
            use_container_width=True,
        )
    with right:
        st.button(
            t("landing.cta_guest"),
            key=f"cta_guest_{suffix}",
            on_click=auth.continue_as_guest,
            use_container_width=True,
        )


_html(f"<style>{(_ASSETS / 'landing.css').read_text(encoding='utf-8')}</style>")

# ---------- Top bar: logo · language · sign in ----------
logo, lang, signin = st.columns([3, 1.1, 0.9], vertical_alignment="center")
with logo:
    _html(f'<div class="l-brand">{branding.inline_logo_html("lbar")}</div>')
with lang:
    st.selectbox(
        t("app.language_label"),
        options=list(LANGUAGES),
        format_func=LANGUAGES.get,
        key="language",
        label_visibility="collapsed",
    )
with signin:
    st.button(
        t("landing.sign_in"), key="top_signin",
        on_click=auth.sign_in, use_container_width=True,
    )

if st.session_state.pop("tumar_auth_missing", False):
    st.warning(t("landing.auth_missing"))

# ---------- Hero ----------
rotator = "".join(
    f"<span>{e('landing.for_' + a)}</span>" for a in _AUDIENCES + _AUDIENCES[:1]
)
_html(f"""
<section class="l-hero">
  <div class="l-grid" aria-hidden="true"></div>
  <div class="l-pill"><i aria-hidden="true"></i>
    <div class="l-rotator" aria-label="{e('landing.for_' + _AUDIENCES[0])}"><div>{rotator}</div></div>
  </div>
  <h1 class="l-title">
    <span>{e('landing.h1_a')}</span>
    <span>{e('landing.h1_b')}</span>
    <span class="l-accent">{e('landing.h1_c')}</span>
  </h1>
  <p class="l-amulet">{e('landing.amulet_a')}<br><span>{e('landing.amulet_b')}</span></p>
  <p class="l-sub">{e('landing.sub')}</p>
</section>
""")
_cta_row("hero")
_html(f'<p class="l-fine">{e("landing.fine_print")}</p>')

# ---------- Audience marquee ----------
items = "".join(f"<span>{e('landing.aud_' + a)}</span>" for a in _MARQUEE)
_html(f"""
<section class="l-band">
  <p class="l-eyebrow">{e('landing.marquee_title')}</p>
  <div class="l-marquee"><div>{items}{items}</div></div>
</section>
""")

# ---------- The five tools (numbered, as on the brand poster) ----------
tools = "".join(
    f'<div class="l-tool" role="listitem"><div class="l-tool-icon"><span translate="no" aria-hidden="true">{glyph}</span></div>'
    f"<div><p class='l-tool-title'><em>0{i}</em><span>{e('landing.tool_' + k + '_t')}</span></p>"
    f"<p class='l-tool-desc'>{e('landing.tool_' + k + '_d')}</p></div></div>"
    for i, (k, glyph) in enumerate(_TOOLS, start=1)
)
strip = "".join(
    f'<div role="listitem"><span class="t-ms" translate="no" aria-hidden="true">{glyph}</span>{e("landing.strip_" + k)}</div>'
    for k, glyph in _STRIP
)
_html(f"""
<section class="l-section">
  <p class="l-eyebrow">{e('landing.tools_eyebrow')}</p>
  <h2 class="l-h2">{e('landing.tools_title')}</h2>
  <div class="l-tools" role="list">{tools}</div>
  <div class="l-strip" role="list">{strip}</div>
</section>
""")

# ---------- The old way vs the Tumar.AI way ----------
old_tools = "".join(f"<span>{e('landing.old_' + k)}</span>" for k in _OLD_TOOLS)
pains = "".join(f"<span>{e('landing.pain_' + k)}</span>" for k in _OLD_PAINS)
features = "".join(
    f"<li><em>0{i}</em><div><b>{e('landing.feat_' + k + '_t')}</b>"
    f"<span>{e('landing.feat_' + k + '_d')}</span></div></li>"
    for i, k in enumerate(_FEATURES, start=1)
)
wins = "".join(f"<span>{e('landing.win_' + k)}</span>" for k in _TUMAR_WINS)
_html(f"""
<section class="l-section">
  <p class="l-eyebrow">{e('landing.compare_eyebrow')}</p>
  <h2 class="l-h2">{e('landing.compare_a')}<br><span class="l-accent">{e('landing.compare_b')}</span></h2>
  <div class="l-compare">
    <div class="l-card l-old">
      <p class="l-card-tag">{e('landing.old_tag')}</p>
      <p class="l-card-lead">{e('landing.old_lead')}</p>
      <div class="l-scatter">{old_tools}</div>
      <div class="l-pains">{pains}</div>
    </div>
    <div class="l-card l-new">
      <p class="l-card-tag">{e('landing.new_tag')}</p>
      <p class="l-card-lead">{e('landing.new_lead')}</p>
      <ol class="l-stack">{features}</ol>
      <div class="l-wins">{wins}</div>
    </div>
  </div>
</section>
""")

# ---------- How it works ----------
steps = "".join(
    f"<div class='l-step'><em>0{i}</em><h3>{e('landing.step_' + k + '_t')}</h3>"
    f"<p>{e('landing.step_' + k + '_d')}</p></div>"
    for i, k in enumerate(_STEPS, start=1)
)
_html(f"""
<section class="l-section">
  <p class="l-eyebrow">{e('landing.how_eyebrow')}</p>
  <h2 class="l-h2">{e('landing.how_title')}</h2>
  <div class="l-steps">{steps}</div>
</section>
""")

# ---------- Privacy ----------
privacy = "".join(
    f"<li><b>{e('landing.priv_' + k + '_t')}</b><span>{e('landing.priv_' + k + '_d')}</span></li>"
    for k in _PRIVACY
)
_html(f"""
<section class="l-section">
  <p class="l-eyebrow">{e('landing.priv_eyebrow')}</p>
  <h2 class="l-h2">{e('landing.priv_title')}</h2>
  <ul class="l-privacy">{privacy}</ul>
</section>
""")

# ---------- Closing call to action ----------
_html(f"""
<section class="l-final">
  <div class="l-grid" aria-hidden="true"></div>
  <h2 class="l-h2">{e('landing.final_title')}</h2>
  <p class="l-sub">{e('landing.final_sub')}</p>
</section>
""")
_cta_row("final")
_html(f"""
<div class="l-horizon" aria-hidden="true">
  <svg viewBox="0 0 1200 80" preserveAspectRatio="none">
    <path d="M0 64 L120 40 L210 56 L330 20 L450 50 L560 32 L640 46 L760 10 L880 48
             L990 30 L1090 50 L1200 34" fill="none" vector-effect="non-scaling-stroke"/>
  </svg>
</div>
<footer class="l-footer">
  <span>© 2026 Tumar.AI</span><span>{e('app.tagline')}</span>
</footer>
""")
