"""The Telegram bot on the shared Trust Engine. Offline: no token, no network.

Covers the report formatter, the engine path and its offline fallback
for /audit, /scan and /check, the per-user daily quota, and the group
features moved from the legacy bot (registry, daily dispatch, /broadcast).

    venv\\Scripts\\python.exe tests\\test_bot_trust_engine.py
"""

import asyncio
import html
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiogram.types import Message  # noqa: E402

import services.quota as quota_module  # noqa: E402
from i18n import language_from_locale, translate  # noqa: E402
from services.common import ServiceError  # noqa: E402
from services.quota import DailyQuota  # noqa: E402
from services.trust_report import Evidence, TrustReport  # noqa: E402
from telegram_bot.handlers import commands, community  # noqa: E402
from telegram_bot.report_format import TELEGRAM_LIMIT, format_report  # noqa: E402


def _report(**overrides) -> TrustReport:
    data = dict(
        source="scam_analyzer",
        subject_type="message",
        subject_preview="Your card is blocked, send the code",
        verdict="danger",
        trust_score=8,
        confidence=91,
        evidence=[
            Evidence(kind="heuristic", code="otp", detail="send the code", weight="strong"),
            Evidence(kind="ai", code="red_flag", detail="<script>alert(1)</script>"),
        ],
        explanation="A classic one-time-code theft attempt.",
        recommended_actions=["Do not share the code."],
    )
    data.update(overrides)
    return TrustReport(**data)


class FakeEngine:
    def __init__(self, report=None, error=None):
        self.report, self.error, self.calls = report, error, []

    def analyze(self, subject, context):
        self.calls.append(subject)
        if self.error:
            raise self.error
        return self.report


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _message(user_id=7, language_code="ru", chat_type="private", text="/audit hi"):
    return Message.model_validate({
        "message_id": 1,
        "date": datetime.now(timezone.utc),
        "chat": {"id": 42, "type": chat_type},
        "from": {"id": user_id, "is_bot": False, "first_name": "T", "language_code": language_code},
        "text": text,
    })


# --- formatter --------------------------------------------------------


def test_formatter_escapes_and_localizes() -> None:
    text = format_report(_report(), "TUMAR CONTEXTUAL SECURITY AUDIT", "kk")
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert translate("trust.verdict.danger", "kk").upper() in text
    assert "8/100" in text and "91%" in text
    assert translate("trust.evidence_ai", "kk") in text  # the method is named
    print("test_formatter_escapes_and_localizes PASSED")


def test_formatter_fits_one_message() -> None:
    long = _report(explanation="x " * 5000, recommended_actions=["y " * 400] * 6,
                   evidence=[Evidence(kind="heuristic", code="urgency", detail="z " * 300)] * 30)
    text = format_report(long, "T", "en")
    assert len(text) <= TELEGRAM_LIMIT, len(text)
    print("test_formatter_fits_one_message PASSED")


def test_locale_mapping() -> None:
    assert language_from_locale("ru-RU") == "ru"
    assert language_from_locale("kk") == "kk"
    assert language_from_locale("de") == "en" and language_from_locale(None) == "en"
    print("test_locale_mapping PASSED")


# --- engine path and offline fallback ---------------------------------


def test_audit_uses_the_shared_engine() -> None:
    original = commands._ENGINE
    commands._ENGINE = FakeEngine(report=_report())
    try:
        text = commands._perform_audit("Your card is blocked, send the code", "ru")
        subject = commands._ENGINE.calls[0]
    finally:
        commands._ENGINE = original
    assert subject.declared_kind == "message" and subject.language == "ru"
    assert translate("bot.title.audit", "ru") in text  # the title follows the user's language
    assert translate("trust.verdict.danger", "ru").upper() in text
    assert "Offline check" not in text
    print("test_audit_uses_the_shared_engine PASSED")


_PROVIDER_VARS = (
    "GEMINI_API_KEY", "TUMAR_TEXT_PROVIDER", "TUMAR_VISION_PROVIDER",
    "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KIMI_API_KEY",
)


def _no_ai_provider() -> dict:
    """Remove every AI key so the real engine hits a provider failure."""
    return {name: os.environ.pop(name, None) for name in _PROVIDER_VARS}


def _restore(saved: dict) -> None:
    for name, value in saved.items():
        if value is not None:
            os.environ[name] = value


def test_audit_and_scan_fall_back_offline_and_say_so() -> None:
    # The REAL engine with no AI key: the provider fails, the engine
    # returns the shared rules-only report, and the bot labels it —
    # the same report the website shows, not a bot-only score.
    saved = _no_ai_provider()
    try:
        audit = commands._perform_audit("URGENT: send your password and one-time code now")
        scan = commands._perform_scan("kaspi-bank-login.xyz")
        calm = commands._perform_audit("Hi team, the class notes for tomorrow are attached.")
    finally:
        _restore(saved)
    note = html.escape(translate("trust.offline.bot_note", "en"))  # as sent to Telegram
    danger = translate("trust.verdict.danger", "en").upper()
    for text in (audit, scan, calm):
        assert note in text, text
    assert danger in audit and danger in scan
    # Offline never certifies "safe": no rule matched is not proof.
    assert translate("trust.verdict.safe", "en").upper() not in calm
    assert danger not in calm
    print("test_audit_and_scan_fall_back_offline_and_say_so PASSED")


def test_offline_checks_are_refunded() -> None:
    os.environ["TUMAR_DAILY_LIMIT_BOT"] = "1"
    quota_module._default = DailyQuota()
    saved = _no_ai_provider()
    try:
        msg = _message(user_id=321)
        object.__setattr__(msg, "answer", AsyncMock())
        for _ in range(3):  # limit 1, yet every offline check is given back
            assert _run(commands.quota_allows(msg, "message"))
            commands._perform_audit("send me your SMS code", "en", user_id=321)
    finally:
        _restore(saved)
        os.environ.pop("TUMAR_DAILY_LIMIT_BOT", None)
        quota_module._default = None
    print("test_offline_checks_are_refunded PASSED")


def test_scan_of_plain_text_runs_the_message_check() -> None:
    # The legacy bot advertised "/scan text"; a sentence must never be
    # judged as a URL and reported "no malicious signals".
    original = commands._ENGINE
    commands._ENGINE = FakeEngine(report=_report())
    try:
        text = commands._perform_scan("send me your SMS code", "en")
        kinds = [s.declared_kind for s in commands._ENGINE.calls]
        commands._ENGINE = FakeEngine(report=_report(subject_type="url", verdict="caution"))
        commands._perform_scan("kaspi-bank-login.xyz", "en")
        link_kinds = [s.declared_kind for s in commands._ENGINE.calls]
    finally:
        commands._ENGINE = original
    saved = _no_ai_provider()
    try:
        offline = commands._perform_scan("send me your SMS code now, your account is blocked", "en")
    finally:
        _restore(saved)
    assert kinds == ["message"] and "TUMAR CONTEXTUAL SECURITY AUDIT" in text
    assert link_kinds == ["url"]
    assert html.escape(translate("trust.offline.bot_note", "en")) in offline
    assert translate("trust.verdict.danger", "en").upper() in offline
    print("test_scan_of_plain_text_runs_the_message_check PASSED")


def test_ip_addresses_never_reach_the_engine() -> None:
    original = commands._ENGINE
    commands._ENGINE = FakeEngine(error=AssertionError("engine must not be called"))
    try:
        assert "LOCAL / NON-ROUTABLE" in commands._perform_scan("10.0.0.1")
    finally:
        commands._ENGINE = original
    print("test_ip_addresses_never_reach_the_engine PASSED")


def test_breach_check_uses_engine_for_emails() -> None:
    original, analytics = commands._ENGINE, commands._query_breach_analytics
    commands._ENGINE = FakeEngine(report=_report(source="breach_checker", subject_type="email",
                                                 subject_preview="st***@example.com", verdict="caution",
                                                 evidence=[Evidence(kind="external", code="breach", detail="ExampleLeak")]))
    commands._query_breach_analytics = lambda email: {}
    try:
        text = commands._perform_breach_check("student@example.com")
        kind = commands._ENGINE.calls[0].declared_kind
        commands._ENGINE = FakeEngine(error=ServiceError("unavailable"))
        failed = commands._perform_breach_check("student@example.com")
    finally:
        commands._ENGINE, commands._query_breach_analytics = original, analytics
    assert kind == "email" and "ExampleLeak" in text and "student@example.com" not in text
    assert "Lookup Notice" in failed
    print("test_breach_check_uses_engine_for_emails PASSED")


# --- quota --------------------------------------------------------------


def test_bot_quota_blocks_and_explains_in_users_language() -> None:
    os.environ["TUMAR_DAILY_LIMIT_BOT"] = "2"
    quota_module._default = DailyQuota()
    try:
        msg = _message(user_id=99, language_code="ru")
        answer = AsyncMock()
        object.__setattr__(msg, "answer", answer)
        results = [_run(commands.quota_allows(msg, "message")) for _ in range(3)]
        assert results == [True, True, False], results
        sent = answer.await_args.args[0]
        assert translate("quota.exceeded_bot", "ru", limit=2) in sent
        assert _run(commands.quota_allows(_message(user_id=100), "message"))  # another user
    finally:
        os.environ.pop("TUMAR_DAILY_LIMIT_BOT", None)
        quota_module._default = None
    print("test_bot_quota_blocks_and_explains_in_users_language PASSED")


# --- groups and broadcasts (moved from bot.py) --------------------------


def test_registry_and_daily_dispatch() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        reg = community.TargetRegistry(Path(tmp) / "b.db")
        reg.add(-1, "Group A", "group")
        reg.add(-2, "Group B", "supergroup")
        reg.add(-2, "Group B renamed", "supergroup")
        reg.remove(-1)
        assert reg.get_all() == {-2}
        reg.conn.close()

    bot = MagicMock()
    bot.send_message = AsyncMock(side_effect=[Exception("blocked"), None])
    sent = _run(community.send_daily_broadcast(bot, targets={-5, -6}))
    assert sent == 1 and bot.send_message.await_count == 2
    assert translate("bot.daily.header", "en") in bot.send_message.await_args.kwargs["text"]
    assert _run(community.send_daily_broadcast(MagicMock(), targets=set())) == 0
    print("test_registry_and_daily_dispatch PASSED")


def test_broadcast_is_admin_only() -> None:
    os.environ["TELEGRAM_ADMIN_ID"] = "555"
    try:
        msg = _message(user_id=7, text="/broadcast hello")
        answer = AsyncMock()
        object.__setattr__(msg, "answer", answer)
        _run(community.cmd_broadcast(msg, MagicMock()))
        assert "Admin access only" in answer.await_args.args[0]
    finally:
        os.environ.pop("TELEGRAM_ADMIN_ID", None)
    print("test_broadcast_is_admin_only PASSED")


if __name__ == "__main__":
    test_formatter_escapes_and_localizes()
    test_formatter_fits_one_message()
    test_locale_mapping()
    test_audit_uses_the_shared_engine()
    test_audit_and_scan_fall_back_offline_and_say_so()
    test_offline_checks_are_refunded()
    test_scan_of_plain_text_runs_the_message_check()
    test_ip_addresses_never_reach_the_engine()
    test_breach_check_uses_engine_for_emails()
    test_bot_quota_blocks_and_explains_in_users_language()
    test_registry_and_daily_dispatch()
    test_broadcast_is_admin_only()
    print("All bot Trust Engine tests passed.")
