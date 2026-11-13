"""Tumar.AI brand mark and wordmark, drawn from shapes (no fonts).

One source of truth for the logo. The symbol is the tumar amulet: a
faceted triangle, electric blue to violet, with a check at its centre.
The wordmark is TUMAR.AI in a blocky pixel style, TUMAR in light ink and
.AI in violet, after the brand poster.

Everything is drawn from polygons and rectangles, so the files render
identically in an <img>, in st.logo, in a browser tab and in print,
with no web font to load. `python scripts/build_brand_assets.py`
writes the files in assets/brand/ from this module; a test checks they
are up to date.
"""

from __future__ import annotations

ELECTRIC = "#00B8FF"
BLUE = "#397BFF"
PURPLE = "#8855FF"
LILAC = "#A78BFA"
INK_DARK_BG = "#F8FAFC"  # wordmark ink on dark backgrounds
INK_LIGHT_BG = "#0B1020"  # wordmark ink on light backgrounds
AI_ON_LIGHT = "#6D3FE6"  # .AI on light backgrounds (contrast)

# --- the symbol (64 x 64) -------------------------------------------------

_OUTER = "M29.4 8.6Q32 4 34.6 8.6L58 50.4Q60.6 55 55.4 55H8.6Q3.4 55 6 50.4Z"
_TOP, _RIGHT, _LEFT = (32, 4), (60.6, 55), (3.4, 55)
_IN_TOP, _IN_RIGHT, _IN_LEFT = (32, 20), (46.5, 46), (17.5, 46)
_CHECK = "M25 37.5L30 42.2L38.6 31.6"


def _pts(*points: tuple[float, float]) -> str:
    return " ".join(f"{x:g},{y:g}" for x, y in points)


def symbol_markup(uid: str = "tm") -> str:
    """The amulet symbol as SVG elements in a 64x64 box (no <svg> wrapper).

    `uid` keeps gradient ids unique when several marks share one page.
    """
    return (
        f'<defs>'
        f'<linearGradient id="{uid}-l" x1="0" y1="0" x2="0.4" y2="1">'
        f'<stop offset="0" stop-color="{ELECTRIC}"/><stop offset="1" stop-color="{BLUE}"/></linearGradient>'
        f'<linearGradient id="{uid}-r" x1="1" y1="0" x2="0.6" y2="1">'
        f'<stop offset="0" stop-color="{LILAC}"/><stop offset="1" stop-color="{PURPLE}"/></linearGradient>'
        f'<linearGradient id="{uid}-b" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0" stop-color="{BLUE}"/><stop offset="1" stop-color="{PURPLE}"/></linearGradient>'
        f'<clipPath id="{uid}-c"><path d="{_OUTER}"/></clipPath>'
        f'</defs>'
        f'<g clip-path="url(#{uid}-c)">'
        # three facets between the outer and inner triangle
        f'<polygon points="{_pts(_TOP, _IN_TOP, _IN_LEFT, _LEFT)}" fill="url(#{uid}-l)"/>'
        f'<polygon points="{_pts(_TOP, _RIGHT, _IN_RIGHT, _IN_TOP)}" fill="url(#{uid}-r)"/>'
        f'<polygon points="{_pts(_LEFT, _IN_LEFT, _IN_RIGHT, _RIGHT)}" fill="url(#{uid}-b)"/>'
        f'</g>'
        # the inner chamber and its rim
        f'<polygon points="{_pts(_IN_TOP, _IN_RIGHT, _IN_LEFT)}" fill="#0D1220" '
        f'stroke="#C7D7FF" stroke-opacity="0.55" stroke-width="1" stroke-linejoin="round"/>'
        f'<path class="t-amulet-check" d="{_CHECK}" fill="none" stroke="{INK_DARK_BG}" stroke-width="3.4" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
    )


def symbol_svg(size: int = 64, uid: str = "tm") -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 64 64" role="img" aria-label="Tumar.AI">{symbol_markup(uid)}</svg>'
    )


# --- the wordmark (pixel letters on a 7-unit grid) -------------------------

# Each glyph: (width in units, [(x, y, w, h), ...]).
_GLYPHS: dict[str, tuple[int, list[tuple[int, int, int, int]]]] = {
    "T": (5, [(0, 0, 5, 1), (2, 1, 1, 6)]),
    "U": (5, [(0, 0, 1, 6), (4, 0, 1, 6), (1, 6, 3, 1)]),
    "M": (5, [(0, 0, 1, 7), (4, 0, 1, 7), (1, 1, 1, 1), (3, 1, 1, 1), (2, 2, 1, 2)]),
    "A": (5, [(0, 1, 1, 6), (4, 1, 1, 6), (1, 0, 3, 1), (1, 4, 3, 1)]),
    "R": (5, [(0, 0, 1, 7), (1, 0, 3, 1), (4, 1, 1, 2), (1, 3, 3, 1), (3, 4, 1, 1), (4, 5, 1, 2)]),
    ".": (1, [(0, 6, 1, 1)]),
    "I": (3, [(0, 0, 3, 1), (1, 1, 1, 5), (0, 6, 3, 1)]),
}
_GAP = 1


def _word_width(text: str) -> int:
    return sum(_GLYPHS[c][0] for c in text) + _GAP * (len(text) - 1)


WORDMARK_UNITS = _word_width("TUMAR.AI")  # 41


def wordmark_markup(unit: float, x0: float, y0: float, ink: str, accent: str) -> str:
    """TUMAR in `ink`, .AI in `accent`, top-left at (x0, y0), 7 units tall."""
    parts: list[str] = []
    x = 0
    for index, char in enumerate("TUMAR.AI"):
        width, rects = _GLYPHS[char]
        color = ink if index < 5 else accent
        for rx, ry, rw, rh in rects:
            parts.append(
                f'<rect x="{x0 + (x + rx) * unit:g}" y="{y0 + ry * unit:g}" '
                f'width="{rw * unit:g}" height="{rh * unit:g}" fill="{color}"/>'
            )
        x += width + _GAP
    return "".join(parts)


def logo_svg(variant: str = "dark", uid: str = "tm") -> str:
    """Horizontal logo: symbol + TUMAR.AI. variant 'dark' or 'light' background."""
    ink, accent = (INK_DARK_BG, PURPLE) if variant == "dark" else (INK_LIGHT_BG, AI_ON_LIGHT)
    unit = 4.0
    height = 48
    word_x = 58
    word_y = (height - 7 * unit) / 2
    width = word_x + WORDMARK_UNITS * unit + 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:g}" height="{height}" '
        f'viewBox="0 0 {width:g} {height}" role="img" aria-label="Tumar.AI">'
        f'<g transform="translate(0 0) scale(0.75)">{symbol_markup(uid)}</g>'
        f'{wordmark_markup(unit, word_x, word_y, ink, accent)}</svg>'
    )


def inline_logo_html(uid: str = "tmi") -> str:
    """The dark-background logo for inline use in page HTML."""
    return logo_svg("dark", uid).replace("<svg ", '<svg class="t-logo" ', 1)


# --- files -------------------------------------------------------------

def brand_files() -> dict[str, str]:
    """Published filename -> SVG text."""
    return {
        "tumar-logo.svg": logo_svg("dark", "tmd"),
        "tumar-logo-light.svg": logo_svg("light", "tml"),
        "tumar-symbol.svg": symbol_svg(64, "tms"),
    }
