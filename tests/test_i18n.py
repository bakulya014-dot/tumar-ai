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


def test_every_literal_key_used_in_code_exists() -> None:
    """Catch t("some.key") calls with no matching translation.

    t() falls back to the key itself, so a typo or a forgotten string
    does not crash — it renders "home.stats_title" on screen for the
    user to see. This test is the safety net for every page, including
    ones added later. Keys built at runtime (t(f"trust.verdict.{...}"))
    are covered by tests/test_report_view.py instead.
    """
    root = Path(__file__).resolve().parent.parent
    sources = [root / "app.py", root / "components.py", root / "report_view.py"]
    sources += sorted((root / "views").glob("*.py"))

    available = set(_load("en"))
    missing: list[str] = []
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for key in re.findall(r"\bt\(\s*\"([\w.]+)\"", text):
            if key not in available:
                missing.append(f"{path.name}: {key}")
    assert not missing, f"keys used in code but not in en.json: {missing}"
    print("test_every_literal_key_used_in_code_exists PASSED")


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
    test_every_literal_key_used_in_code_exists()
    test_no_empty_translations()
    print("ALL I18N TESTS PASSED")
