"""The rules-only fallback (services/offline_report.py) and its engine switch.

Offline, no API key: the provider failure is real (missing key), so this
exercises exactly what users see when Gemini is unreachable.

    venv\\Scripts\\python.exe tests\\test_offline_report.py
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.common import ServiceError  # noqa: E402
from services.offline_report import (  # noqa: E402
    OFFLINE_CAP,
    PROVIDER_FAILURES,
    is_provider_failure,
    offline_message_report,
    offline_url_report,
)
from services.quota import DailyQuota  # noqa: E402
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject  # noqa: E402

_PROVIDER_VARS = (
    "GEMINI_API_KEY", "TUMAR_TEXT_PROVIDER", "TUMAR_VISION_PROVIDER",
    "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KIMI_API_KEY",
)


def _no_ai():
    return {name: os.environ.pop(name, None) for name in _PROVIDER_VARS}


def _restore(saved):
    for name, value in saved.items():
        if value is not None:
            os.environ[name] = value


def _analyze(content: str, kind: str, fallback: bool):
    return TrustEngine().analyze(
        TrustSubject(content=content, declared_kind=kind),
        AnalysisContext(offline_fallback=fallback),
    )


def test_engine_falls_back_only_when_asked() -> None:
    saved = _no_ai()
    try:
        try:
            _analyze("Your card is blocked, send me the SMS code", "message", fallback=False)
            raise AssertionError("without the flag the provider error must surface (API contract)")
        except ServiceError as exc:
            assert is_provider_failure(exc.code), exc.code
        report = _analyze("Your card is blocked, send me the SMS code", "message", fallback=True)
        assert report.analysis_metadata["mode"] == "offline"
        assert report.analysis_metadata["offline_reason"] in PROVIDER_FAILURES
        assert AnalysisContext().offline_fallback is False
    finally:
        _restore(saved)
    print("test_engine_falls_back_only_when_asked PASSED")


def test_input_errors_are_never_hidden_by_the_fallback() -> None:
    saved = _no_ai()
    try:
        _analyze("definitely not a link", "url", fallback=True)
        raise AssertionError("an invalid URL must still be reported as an error")
    except ServiceError as exc:
        assert exc.code == "invalid_url", exc.code
    finally:
        _restore(saved)
    print("test_input_errors_are_never_hidden_by_the_fallback PASSED")


def test_offline_reports_are_rules_only_and_never_safe() -> None:
    cases = [
        offline_message_report("URGENT! Your Kaspi card is blocked. Send me the SMS code now.", "timeout"),
        offline_message_report("Hi team, the class notes for tomorrow are attached.", "timeout"),
        offline_message_report("ok", "timeout"),  # too short to judge
        offline_url_report("http://kaspi-bonus.site/verify", "unreachable"),
        offline_url_report("https://github.com", "unreachable"),
    ]
    for report in cases:
        assert report.verdict != "safe", report.subject_preview
        assert report.trust_score <= OFFLINE_CAP and report.confidence == OFFLINE_CAP
        assert all(e.kind == "heuristic" for e in report.evidence), "no AI evidence offline"
        assert report.explanation_key.startswith("trust.offline.explain.")
        assert not report.explanation, "no free text pretending to be an AI explanation"
    scam, calm, short, bad_link, good_link = cases
    assert scam.verdict == "danger" and bad_link.verdict == "danger"
    assert calm.verdict == "caution" and good_link.verdict == "caution"
    assert short.risk_level == "inconclusive"
    assert scam.source == "scam_analyzer" and bad_link.source == "url_scanner"  # pages find them
    assert "otp" in scam.analysis_metadata["risk_contributions"]
    print("test_offline_reports_are_rules_only_and_never_safe PASSED")


def test_every_offline_text_exists_in_three_languages() -> None:
    reports = [
        offline_message_report(text, "timeout")
        for text in ("Send me the SMS code now", "Pay now, urgent", "hello there friend", "ok")
    ] + [offline_url_report("http://kaspi-bonus.site/verify", "timeout")]
    keys = {"trust.offline.banner", "trust.offline.bot_note"}
    for report in reports:
        keys.add(report.explanation_key)
        keys.update(report.recommended_action_keys + report.confidence_reason_keys)
    for level in ("inconclusive", "low", "moderate", "high", "critical"):
        keys.add(f"trust.offline.explain.{level}")
    for lang in ("en", "ru", "kk"):
        data = json.loads((ROOT / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))
        for key in keys:
            node = data
            for part in key.split("."):
                node = node[part]
            assert isinstance(node, str) and node.strip(), (lang, key)
        for code in PROVIDER_FAILURES:  # the banner's reason line
            assert data["errors"].get(code), (lang, code)
    print("test_every_offline_text_exists_in_three_languages PASSED")


def test_quota_refund_returns_one_check() -> None:
    os.environ["TUMAR_DAILY_LIMIT_BOT"] = "1"
    try:
        quota = DailyQuota()
        assert quota.consume("tg:1", "bot", "message").allowed
        assert not quota.consume("tg:1", "bot", "message").allowed
        quota.refund("tg:1", "bot", "message")
        assert quota.consume("tg:1", "bot", "message").allowed
        for _ in range(3):  # never below zero
            quota.refund("tg:1", "bot", "message")
        assert quota.consume("tg:1", "bot", "message").allowed
        assert not quota.consume("tg:1", "bot", "message").allowed
        quota.refund("tg:1", "bot", "password")  # uncounted kind: no-op
        assert not quota.consume("tg:1", "bot", "message").allowed
    finally:
        os.environ.pop("TUMAR_DAILY_LIMIT_BOT", None)
    print("test_quota_refund_returns_one_check PASSED")


if __name__ == "__main__":
    test_engine_falls_back_only_when_asked()
    test_input_errors_are_never_hidden_by_the_fallback()
    test_offline_reports_are_rules_only_and_never_safe()
    test_every_offline_text_exists_in_three_languages()
    test_quota_refund_returns_one_check()
    print("All offline report tests passed.")
