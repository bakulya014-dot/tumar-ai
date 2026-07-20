"""Lightweight internationalization (i18n) for the Streamlit UI.

Translations live in JSON files, one per language (en.json, ru.json,
kk.json). Keys are dotted paths like "scam.analyze_button".

Business logic never touches this module: services return short codes,
and the UI turns codes into words here. That keeps the services
reusable in a future FastAPI backend, where clients localize responses
themselves.
"""

import json
from functools import lru_cache
from pathlib import Path

import streamlit as st

_I18N_DIR = Path(__file__).resolve().parent

# Language code -> name shown in the language selector.
LANGUAGES = {"en": "English", "ru": "Русский", "kk": "Қазақша"}
DEFAULT_LANGUAGE = "en"


def _flatten(node: dict, prefix: str = "") -> dict[str, str]:
    """Turn nested JSON into {"a.b.c": "text"} pairs."""
    flat: dict[str, str] = {}
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


@lru_cache(maxsize=None)
def _load(language: str) -> dict[str, str]:
    """Read and flatten one language file (cached after first read)."""
    path = _I18N_DIR / f"{language}.json"
    with open(path, encoding="utf-8") as fh:
        return _flatten(json.load(fh))


def current_language() -> str:
    """The user's chosen language for this session."""
    try:
        return st.session_state.get("language", DEFAULT_LANGUAGE)
    except Exception:
        # Outside a Streamlit session (tests, scripts) fall back to English.
        return DEFAULT_LANGUAGE


def t(key: str, **placeholders: object) -> str:
    """Translate a dotted key into the current language.

    Missing keys fall back to English, then to the key itself so a
    translation gap never crashes the app. Placeholders are filled
    with str.format, e.g. t("breach.safe_banner", email="a@b.c").
    """
    text = _load(current_language()).get(key)
    if text is None:
        text = _load(DEFAULT_LANGUAGE).get(key, key)
    return text.format(**placeholders) if placeholders else text
