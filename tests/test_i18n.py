"""Translation-file integrity tests (no Streamlit needed).

Verifies that every language file defines exactly the same keys and
the same {placeholders} as the English reference — the classic i18n
failure is a language silently missing a string.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_i18n.py
"""

import json
import re
import sys
from pathlib import Path

I18N_DIR = Path(__file__).resolve().parent.parent / "i18n"
LANGUAGES = ("en", "ru", "kk")
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def _flatten(node: dict, prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def _load(language: str) -> dict[str, str]:
    with open(I18N_DIR / f"{language}.json", encoding="utf-8") as fh:
        return _flatten(json.load(fh))


def test_key_parity() -> None:
    reference = set(_load("en"))
    assert reference, "English file is empty?"
    for language in LANGUAGES[1:]:
        keys = set(_load(language))
        missing = reference - keys
        extra = keys - reference
        assert not missing, f"{language}.json is missing keys: {sorted(missing)}"
        assert not extra, f"{language}.json has extra keys: {sorted(extra)}"
    print(f"test_key_parity PASSED ({len(reference)} keys per language)")


def test_placeholder_parity() -> None:
    english = _load("en")
    for language in LANGUAGES[1:]:
        translated = _load(language)
        for key, text in english.items():
            expected = set(_PLACEHOLDER.findall(text))
            actual = set(_PLACEHOLDER.findall(translated[key]))
            assert expected == actual, (
                f"{language}.json key '{key}': placeholders {actual} "
                f"do not match English {expected}"
            )
    print("test_placeholder_parity PASSED")


def test_no_empty_translations() -> None:
    for language in LANGUAGES:
        for key, text in _load(language).items():
            assert isinstance(text, str) and text.strip(), (
                f"{language}.json key '{key}' is empty"
            )
    print("test_no_empty_translations PASSED")


if __name__ == "__main__":
    test_key_parity()
    test_placeholder_parity()
    test_no_empty_translations()
    print("ALL I18N TESTS PASSED")
