"""Offline tests for the Tumar.AI Telegram Bot & News Pipeline modules.

Validates anti-spam middleware, news summarization/collection logic,
and command processing logic without making live external network calls.
"""

import asyncio
import html
from dataclasses import dataclass
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.news.collector import FALLBACK_ARTICLES, NewsArticle, _strip_html
from app.news.summarizer import _format_rule_based
from aiogram.types import Message
from telegram_bot.handlers.commands import (
    STUDENT_OPSEC_TIPS,
    _extract_exposed_fields,
    _perform_audit,
    _perform_scan,
    get_onboarding_keyboard,
)
from telegram_bot.middlewares.anti_spam import AntiSpamMiddleware
from i18n import translate
import os

_PROVIDER_VARS = (
    "GEMINI_API_KEY", "TUMAR_TEXT_PROVIDER", "TUMAR_VISION_PROVIDER",
    "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KIMI_API_KEY",
)


def _no_ai_provider() -> dict:
    return {name: os.environ.pop(name, None) for name in _PROVIDER_VARS}


def _restore(saved: dict) -> None:
    for name, value in saved.items():
        if value is not None:
            os.environ[name] = value


def test_anti_spam_middleware_rate_limiting() -> None:
    """Test that AntiSpamMiddleware allows normal requests and throttles rapid requests."""
    middleware = AntiSpamMiddleware(rate_limit_seconds=1.0)

    # Mock Telegram user and message
    mock_user = MagicMock()
    mock_user.id = 12345

    mock_msg = MagicMock(spec=Message)
    mock_msg.from_user = mock_user
    mock_msg.answer = AsyncMock()

    mock_handler = AsyncMock(return_value="OK")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # First call: should be permitted
        res1 = loop.run_until_complete(middleware(mock_handler, mock_msg, {}))
        assert res1 == "OK", "First request must be passed to handler"
        assert mock_handler.call_count == 1

        # Second call immediately: should be throttled
        res2 = loop.run_until_complete(middleware(mock_handler, mock_msg, {}))
        assert res2 is None, "Immediate second request must be throttled (return None)"
        assert mock_handler.call_count == 1, "Handler must not have been invoked a second time"
        assert mock_msg.answer.call_count == 1, "User should receive rate-limit alert"

        # Advance time by adjusting recorded timestamp
        middleware._user_timestamps[12345] = time.monotonic() - 1.5

        # Third call after cooldown: should succeed
        res3 = loop.run_until_complete(middleware(mock_handler, mock_msg, {}))
        assert res3 == "OK", "Request after cooldown must succeed"
        assert mock_handler.call_count == 2
    finally:
        loop.close()

    print("test_anti_spam_middleware_rate_limiting PASSED")


def test_news_collector_html_stripping() -> None:
    """Test HTML cleaning and entity decoding."""
    raw = "<p>Security <b>alert</b>: Critical &amp; urgent vulnerability!</p>"
    clean = _strip_html(raw)
    assert clean == "Security alert: Critical & urgent vulnerability!"
    assert len(FALLBACK_ARTICLES) >= 3
    print("test_news_collector_html_stripping PASSED")


def test_news_summarizer_rule_based_fallback() -> None:
    """Test deterministic rule-based digest formatting."""
    articles = [
        NewsArticle(
            title="Chromium Exploit Fixed",
            link="https://example.com/exploit",
            summary="High severity vulnerability resolved.",
            published="Today",
            source="The Hacker News",
        )
    ]
    digest = _format_rule_based(articles, limit=1)
    assert "TUMAR.AI CYBER THREAT DIGEST" in digest
    assert "Chromium Exploit Fixed" in digest
    assert "The Hacker News" in digest
    assert "https://example.com/exploit" in digest
    print("test_news_summarizer_rule_based_fallback PASSED")


def test_commands_dashboard_and_tips() -> None:
    """Test that keyboard and student OpSec tips are valid and populated."""
    kb = get_onboarding_keyboard()
    assert len(kb.inline_keyboard) >= 3
    callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row]
    assert "act_news" in callbacks
    assert "act_tip" in callbacks
    assert "act_check_help" in callbacks
    assert "act_scan_help" in callbacks
    assert "act_audit_help" in callbacks

    assert len(STUDENT_OPSEC_TIPS) >= 5
    for title, advice in STUDENT_OPSEC_TIPS:
        assert title and advice
    print("test_commands_dashboard_and_tips PASSED")


def test_scan_logic_for_ip_and_domains() -> None:
    """Test scan classification for private vs public IP and deceptive domains."""
    # Private IP
    res_private = _perform_scan("192.168.1.1")
    assert "Private / Internal RFC1918 Address" in res_private
    assert "LOCAL / NON-ROUTABLE" in res_private

    # Public IP
    res_public = _perform_scan("8.8.8.8")
    assert "Direct Public IP Host" in res_public

    # Domains go through the shared Trust Engine. With no AI key the
    # engine returns its labelled rules-only report (the same one the
    # website shows), so this exercises the offline path on purpose.
    saved = _no_ai_provider()
    try:
        res_domain = _perform_scan("kaspi-bank-login.xyz")
        res_clean = _perform_scan("https://github.com")
    finally:
        _restore(saved)
    assert translate("trust.verdict.danger", "en").upper() in res_domain
    # Offline never certifies "safe", and an ordinary site is not "dangerous".
    assert translate("trust.verdict.safe", "en").upper() not in res_clean
    assert translate("trust.verdict.danger", "en").upper() not in res_clean
    assert html.escape(translate("trust.offline.bot_note", "en")) in res_clean
    print("test_scan_logic_for_ip_and_domains PASSED")


def test_audit_heuristic_scoring() -> None:
    """Test audit evaluation for high-risk phishing vs benign messages."""
    malicious_text = (
        "URGENT: Your account is blocked. Send your password and one-time code immediately."
    )
    benign_text = "Hi team, please find the class notes attached for tomorrow's lecture."
    saved = _no_ai_provider()
    try:
        res_bad = _perform_audit(malicious_text)
        res_good = _perform_audit(benign_text)
    finally:
        _restore(saved)
    danger = translate("trust.verdict.danger", "en").upper()
    assert danger in res_bad
    assert translate("trust.score_label", "en") in res_bad
    assert danger not in res_good
    print("test_audit_heuristic_scoring PASSED")


def test_breach_analytics_field_extraction() -> None:
    """Test extraction of human readable breach fields from analytics payload."""
    sample_analytics = {
        "BreachMetrics": {
            "xposed_data": [
                {
                    "children": [
                        {
                            "children": [
                                {"name": "data_Passwords"},
                                {"name": "data_Phone numbers"},
                            ]
                        }
                    ]
                }
            ]
        }
    }
    fields = _extract_exposed_fields(sample_analytics)
    assert "Passwords" in fields
    assert "Phone numbers" in fields
    print("test_breach_analytics_field_extraction PASSED")


def main() -> None:
    test_anti_spam_middleware_rate_limiting()
    test_news_collector_html_stripping()
    test_news_summarizer_rule_based_fallback()
    test_commands_dashboard_and_tips()
    test_scan_logic_for_ip_and_domains()
    test_audit_heuristic_scoring()
    test_breach_analytics_field_extraction()
    print("All Telegram Bot & News Pipeline tests PASSED successfully!")


if __name__ == "__main__":
    main()
