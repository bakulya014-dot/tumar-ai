"""Telegram bot and Launch Film translations: complete, well-formed, wired in.

tests/test_i18n.py already checks key parity, placeholder parity and
empty strings across en/ru/kk, and the website's t("...") keys. This
suite covers what is specific to the bot:

- every key the bot builds (literally or from a known family) exists;
- Telegram HTML tags match between languages (Telegram rejects a reply
  with unbalanced tags, so a broken translation would lose the reply);
- handlers send no hard-coded user-facing text (admin-only lines aside);
- English output is unchanged from before translation;
- Russian and Kazakh outputs render, with no placeholders left over;
- inline-button callbacks answer in the presser's language.

    venv\\Scripts\\python.exe tests\\test_bot_i18n.py
"""

import ast
import asyncio
import json
import re
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from i18n import LANGUAGES, _load, translate  # noqa: E402
from telegram_bot.handlers import commands, screenshot  # noqa: E402

HANDLERS = ROOT / "telegram_bot" / "handlers"
_TAG = re.compile(r"</?(?:b|i|code|u|s|a|pre)\b[^>]*>")


def test_json_is_well_formed_without_duplicate_keys() -> None:
    def no_duplicates(pairs):
        keys = [key for key, _ in pairs]
        duplicated = [key for key, count in Counter(keys).items() if count > 1]
        assert not duplicated, f"duplicate keys: {duplicated}"
        return dict(pairs)

    for language in LANGUAGES:
        raw = (ROOT / "i18n" / f"{language}.json").read_text(encoding="utf-8")
        json.loads(raw, object_pairs_hook=no_duplicates)
    print("test_json_is_well_formed_without_duplicate_keys PASSED")


def _required_bot_keys() -> set[str]:
    """Every key the bot can look up: literal calls plus the dynamic families."""
    keys: set[str] = set()
    for path in HANDLERS.glob("*.py"):
        keys |= set(re.findall(r"translate\(\s*[\"']([\w.]+)[\"']", path.read_text(encoding="utf-8")))
    keys |= {f"bot.button.{b}" for b in ("news", "tip", "check", "scan", "audit")}
    keys |= {f"bot.help.{t}" for t in ("check", "scan", "audit")}
    keys |= {f"bot.tips.{k}.{part}" for k in commands.TIP_KEYS for part in ("title", "text")}
    keys |= {f"bot.shot.level.{level}" for level in screenshot._LEVELS}
    keys |= {
        f"bot.shot.advice.{level}.{n}"
        for level, count in screenshot._ADVICE_COUNT.items()
        for n in range(1, count + 1)
    }
    keys |= {f"bot.shot.invalid.{code}" for code in screenshot._VALIDATION_CODES}
    keys |= {f"bot.shot.ocr_{status}" for status in ("unavailable", "failed")}
    keys |= {f"image.category.{c}" for c in screenshot._CATEGORIES}
    keys |= {f"film.{k}" for k in ("title", "subtitle", "caption", "film_heading", "animation_heading", "pending", "try_link")}
    keys.add("nav.film")
    return keys


def test_every_bot_key_exists_in_all_languages() -> None:
    required = _required_bot_keys()
    assert len(required) > 80, len(required)  # the families really were collected
    for language in LANGUAGES:
        missing = sorted(required - set(_load(language)))
        assert not missing, f"{language}: missing {missing}"
    print(f"test_every_bot_key_exists_in_all_languages PASSED ({len(required)} keys)")


def test_bot_strings_are_translated_and_html_matches() -> None:
    english = {k: v for k, v in _load("en").items() if k.startswith(("bot.", "film."))}
    for language in ("ru", "kk"):
        translated = _load(language)
        for key, text in english.items():
            other = translated[key]
            assert other != text, f"{language}: '{key}' is still the English text"
            assert sorted(_TAG.findall(other)) == sorted(_TAG.findall(text)), (
                f"{language}: HTML tags differ in '{key}'"
            )
    print("test_bot_strings_are_translated_and_html_matches PASSED")


# Admin-only replies to /broadcast (one operator, not end users).
_ADMIN_ONLY = {"community.py": {"cmd_broadcast"}}


def test_handlers_send_no_hard_coded_text() -> None:
    """A literal with words, passed straight to answer()/edit_text(), is untranslated."""
    offenders: list[str] = []
    for path in sorted(HANDLERS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if func.name in _ADMIN_ONLY.get(path.name, set()):
                continue
            for call in ast.walk(func):
                if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
                    continue
                if call.func.attr not in ("answer", "edit_text", "reply", "send_message"):
                    continue
                args = list(call.args) + [kw.value for kw in call.keywords if kw.arg == "text"]
                for arg in args:
                    literal = ""
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        literal = arg.value
                    elif isinstance(arg, ast.JoinedStr):
                        literal = "".join(
                            part.value for part in arg.values
                            if isinstance(part, ast.Constant) and isinstance(part.value, str)
                        )
                    if re.search(r"[A-Za-z]{3,}", literal):
                        offenders.append(f"{path.name}:{call.lineno} {literal[:50]!r}")
    assert not offenders, f"hard-coded user-facing text: {offenders}"
    print("test_handlers_send_no_hard_coded_text PASSED")


def test_english_output_is_unchanged() -> None:
    labels = [b.text for row in commands.get_onboarding_keyboard("en").inline_keyboard for b in row]
    assert labels == ["📰 Live Threat News", "💡 OpSec Tip", "🔍 Check Account", "🌐 Scan Target", "🧠 Deep AI Audit"]
    assert translate("bot.title.audit", "en") == "TUMAR CONTEXTUAL SECURITY AUDIT"
    assert commands._perform_scan("192.168.1.1", "en") == (
        "🛡️ <b>TUMAR IP THREAT INTELLIGENCE</b>\n\n"
        "🎯 <b>Target:</b> <code>192.168.1.1</code>\n"
        "📌 <b>Classification:</b> <b>Private / Internal RFC1918 Address</b>\n"
        "✅ <b>Verdict:</b> <b>LOCAL / NON-ROUTABLE</b>\n"
        "💡 <b>Info:</b> This address is reserved for local network routing and cannot be accessed "
        "directly from the public internet."
    )
    assert screenshot._validation_message("image_too_large", "en").startswith("The image is larger than ")
    assert commands.opsec_tips("en")[0][0] == "🎓 <b>Campus Wi-Fi Defense</b>"
    print("test_english_output_is_unchanged PASSED")


def test_russian_and_kazakh_render() -> None:
    samples = {"ru": "частный", "kk": "жеке"}
    for language, word in samples.items():
        private = commands._perform_scan("10.0.0.1", language)
        assert word in private and "10.0.0.1" in private, private
        public = commands._perform_scan("8.8.8.8", language)
        assert "8.8.8.8" in public and "{" not in public and "Attackers" not in public, public
        tip_title, _advice = commands.opsec_tips(language)[0]
        assert "Campus" not in tip_title
        usage = translate("bot.shot.invalid.image_too_large", language, mb=6)
        assert "6" in usage and "{" not in usage
        keyboard = [b.text for row in commands.get_onboarding_keyboard(language).inline_keyboard for b in row]
        assert "📰 Live Threat News" not in keyboard and len(keyboard) == 5
    print("test_russian_and_kazakh_render PASSED")


def test_unknown_locale_falls_back_to_english() -> None:
    from i18n import language_from_locale

    assert language_from_locale("de-DE") == "en"
    assert language_from_locale(None) == "en"
    assert language_from_locale("kk") == "kk" and language_from_locale("ru-RU") == "ru"
    assert translate("bot.title.scan", "de") == translate("bot.title.scan", "en")
    print("test_unknown_locale_falls_back_to_english PASSED")


def test_button_help_answers_in_the_pressers_language() -> None:
    # The message under the buttons was sent by the bot, so its sender's
    # locale is the bot's. The reply must follow the user who pressed.
    sent: list[str] = []
    bot_message = SimpleNamespace(
        answer=AsyncMock(side_effect=lambda text, **_kw: sent.append(text)),
        from_user=SimpleNamespace(language_code=None, is_bot=True),
    )
    callback = SimpleNamespace(
        data="act_scan_help",
        answer=AsyncMock(),
        message=bot_message,
        from_user=SimpleNamespace(language_code="kk"),
    )
    asyncio.run(commands.handle_dashboard_actions(callback))
    assert sent == [translate("bot.help.scan", "kk")], sent
    print("test_button_help_answers_in_the_pressers_language PASSED")


def test_screenshot_reason_codes_use_website_wording() -> None:
    assert screenshot._url_reason("shortener", "ru") == translate("scam.url_reason.shortener", "ru")
    assert screenshot._url_reason("url_no_https", "kk") == translate("scam.url_reason.no_https", "kk")
    assert screenshot._url_reason("brand_new_code", "en") == "brand new code"  # unknown: readable fallback
    print("test_screenshot_reason_codes_use_website_wording PASSED")


if __name__ == "__main__":
    test_json_is_well_formed_without_duplicate_keys()
    test_every_bot_key_exists_in_all_languages()
    test_bot_strings_are_translated_and_html_matches()
    test_handlers_send_no_hard_coded_text()
    test_english_output_is_unchanged()
    test_russian_and_kazakh_render()
    test_unknown_locale_falls_back_to_english()
    test_button_help_answers_in_the_pressers_language()
    test_screenshot_reason_codes_use_website_wording()
    print("All bot translation tests passed.")
