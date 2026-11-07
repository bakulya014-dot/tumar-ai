"""Landing — the public front door shown before sign-in.

Tells a first-time visitor who Tumar.AI is for, why it beats the usual
guesswork, and how it works, then offers two ways in: register with
Google, or try the tools as a guest. Every string goes through t(), and
every value placed in HTML is escaped.
"""

import html
from pathlib import Path

import streamlit as st

import auth
from i18n import LANGUAGES, t

_ASSETS = Path(__file__).resolve().parent.parent / "assets"

_AUDIENCES = ("parents", "students", "seniors", "business", "freelancers", "shoppers")
_MARQUEE = (
    "parents", "students", "seniors", "business", "freelancers",
    "shoppers", "teachers", "creators", "remote",
)
_OLD_TOOLS = ("search", "virustotal", "hibp", "family_chat", "notebook", "ignore")
_OLD_PAINS = ("lost_money", "hijacked", "leaked")
_MODULES = (
    ("🔍", "scam"), ("🔗", "url"), ("🖼️", "image"),
    ("📧", "breach"), ("🔑", "password"), ("🤖", "bot"),
)
_TUMAR_WINS = ("verdict", "plain", "private")
_STEPS = ("paste", "check", "act")
_PRIVACY = ("redact", "never_sold", "k_anon")


def e(key: str, **kw: object) -> str:
    """Translate and HTML-escape."""
    return html.escape(t(key, **kw))


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
    _html(
        '<div class="l-brand"><svg viewBox="0 0 48 48" aria-hidden="true">'
        '<defs><linearGradient id="l-g" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#F5C97B"/><stop offset="1" stop-color="#22D3EE"/>'
        "</linearGradient></defs>"
        '<path d="M24 6 L42 38 A3 3 0 0 1 39.4 42.5 H8.6 A3 3 0 0 1 6 38 Z" '
        'fill="rgba(34,211,238,0.08)" stroke="url(#l-g)" stroke-width="2.5" '
        'stroke-linejoin="round"/><path d="M17 27 l5.5 5.5 l10.5 -13" fill="none" '
        'stroke="#7DE9FF" stroke-width="3" stroke-linecap="round" '
        'stroke-linejoin="round"/></svg><span>Tumar.AI</span></div>'
    )
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
stars = "".join(f'<i style="--x:{(i * 37) % 100}%;--y:{(i * 53) % 90}%;--d:{i % 7}s"></i>' for i in range(28))
_html(f"""
<section class="l-hero">
  <div class="l-stars" aria-hidden="true">{stars}</div>
  <div class="l-rotator" aria-label="{e('landing.for_' + _AUDIENCES[0])}"><div>{rotator}</div></div>
  <h1 class="l-title">
    <span>{e('landing.h1_a')}</span>
    <span>{e('landing.h1_b')}</span>
    <span class="l-accent">{e('landing.h1_c')}</span>
  </h1>
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

# ---------- Old way vs the Tumar way ----------
old_chips = "".join(f"<span>{e('landing.old_' + k)}</span>" for k in _OLD_TOOLS)
pains = "".join(f"<span class='l-pain'>{e('landing.pain_' + k)}</span>" for k in _OLD_PAINS)
tiles = "".join(
    f"<div class='l-tile'><b>{icon}</b><span>{e('landing.mod_' + k)}</span></div>"
    for icon, k in _MODULES
)
wins = "".join(f"<span class='l-win'>✓ {e('landing.win_' + k)}</span>" for k in _TUMAR_WINS)
_html(f"""
<section class="l-section">
  <p class="l-eyebrow">{e('landing.compare_eyebrow')}</p>
  <h2 class="l-h2">{e('landing.compare_a')}<br><span class="l-accent">{e('landing.compare_b')}</span></h2>
  <div class="l-compare">
    <div class="l-card l-old">
      <p class="l-card-tag">{e('landing.old_tag')}</p>
      <p class="l-card-lead">{e('landing.old_lead')}</p>
      <div class="l-chips l-scatter">{old_chips}</div>
      <div class="l-chips">{pains}</div>
    </div>
    <div class="l-card l-new">
      <p class="l-card-tag">{e('landing.new_tag')}</p>
      <p class="l-card-lead">{e('landing.new_lead')}</p>
      <div class="l-tiles">{tiles}</div>
      <div class="l-chips">{wins}</div>
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

# ---------- Closing call to action over the night steppe ----------
_html(f"""
<section class="l-final">
  <div class="l-stars" aria-hidden="true">{stars}</div>
  <h2 class="l-h2">{e('landing.final_title')}</h2>
  <p class="l-sub">{e('landing.final_sub')}</p>
</section>
""")
_cta_row("final")
_html(f"""
<div class="l-steppe" aria-hidden="true">
  <svg viewBox="0 0 1200 140" preserveAspectRatio="none">
    <path d="M0 140 L0 92 L120 60 L210 84 L330 34 L450 78 L560 52 L640 70 L760 22 L880 72
             L990 46 L1090 74 L1200 50 L1200 140 Z" fill="#0A1224"/>
    <path d="M0 140 L0 112 L180 96 L360 112 L540 98 L720 114 L900 100 L1080 112 L1200 104
             L1200 140 Z" fill="#070D1A"/>
  </svg>
</div>
<footer class="l-footer">
  <span>© 2026 Tumar.AI</span><span>{e('app.tagline')}</span>
</footer>
""")
