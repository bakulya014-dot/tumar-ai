"""Offline tests for services/heuristics.py (no network calls).

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_heuristics.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.heuristics import scan_message


def test_clean_message() -> None:
    report = scan_message("Hi mom, I'll be home at 7.")
    assert report.urgency_score == 0
    assert not report.otp_requested
    assert not report.suspicious_urls
    assert not report.financial_indicators
    print("test_clean_message PASSED")


def test_english_scam_signals() -> None:
    report = scan_message(
        "URGENT! Act now or your account will be suspended. "
        "Enter the SMS code we sent you: http://bit.ly/x2f and "
        "confirm at http://kaspi-verify.xyz/login"
    )
    assert report.urgency_score >= 60
    # The message mentions a code but does not ask the reader to hand
    # it over — what makes this dangerous is the links, and the strong
    # signals must reflect that rather than the word "code".
    assert report.otp_signal in ("entry", "delivery")
    assert "url" in report.strong_signals
    urls = {finding.url: finding.reasons for finding in report.suspicious_urls}
    assert any("shortener" in reasons for reasons in urls.values())
    assert any("brand_lookalike" in reasons for reasons in urls.values())
    assert any("suspicious_tld" in reasons for reasons in urls.values())
    print("test_english_scam_signals PASSED")


def test_russian_scam_signals() -> None:
    report = scan_message(
        "СРОЧНО! Немедленно подтвердите личность и назовите код из СМС, "
        "иначе карта будет заблокирована."
    )
    assert report.urgency_score >= 60
    assert report.otp_requested
    assert report.credential_indicators
    print("test_russian_scam_signals PASSED")


def test_kazakh_scam_signals() -> None:
    report = scan_message(
        "ШҰҒЫЛ! Картаңыз бұғатталды. Растау коды керек — дереу жіберіңіз."
    )
    assert report.urgency_score >= 60
    # Kazakh separates the noun from the verb; proximity catches it.
    assert report.otp_requested
    print("test_kazakh_scam_signals PASSED")


def test_misleading_subdomain() -> None:
    report = scan_message("Login here: http://kaspi.kz.secure-login.top/auth")
    assert report.suspicious_urls
    reasons = report.suspicious_urls[0].reasons
    assert "misleading_subdomain" in reasons
    assert "suspicious_tld" in reasons
    print("test_misleading_subdomain PASSED")


def test_official_domain_not_flagged() -> None:
    report = scan_message("Docs: https://google.com/search?q=security")
    assert not report.suspicious_urls
    print("test_official_domain_not_flagged PASSED")


def test_english_code_requests_are_disclosure() -> None:
    """English ways of asking for the code (found missing in the Phase 1
    review: "send me your SMS code" was read as an ordinary delivery)."""
    requests = [
        "send me your SMS code",
        "Hi mom, it's me. Send me the code that just came to your phone",
        "Please share your one-time password to confirm the refund",
        "Bank security here. Read me the code we just sent.",
        "Text me the 6-digit code you received",
        "Give me your verification code so I can unlock your card",
        "Send us your OTP to cancel the transaction",
    ]
    for text in requests:
        assert scan_message(text).otp_signal == "disclosure", text
    print("test_english_code_requests_are_disclosure PASSED")


def test_ordinary_code_messages_stay_calm() -> None:
    """Delivery, entry, warnings and non-security "code" are not requests."""
    calm = [
        "Your SMS code is 482913. Do not share it with anyone.",
        "We will send you a verification code by SMS.",
        "We'll send a code to your phone to finish signing in.",
        "Your one-time password is 552310. Don't share your one-time password with anyone.",
        "Never share your OTP. Halyk Bank will never ask for it.",
        "Enter the code we sent to your email to continue.",
        "Can you send me the meeting notes and the code review link?",
        "Please send me the source code by Friday.",
        "Give me a call when the dress code is decided.",
        "Send me the promo code for the store",
        "Please give me the ZIP code for the delivery",
    ]
    for text in calm:
        assert scan_message(text).otp_signal != "disclosure", text
    print("test_ordinary_code_messages_stay_calm PASSED")


if __name__ == "__main__":
    test_english_code_requests_are_disclosure()
    test_ordinary_code_messages_stay_calm()
    test_clean_message()
    test_english_scam_signals()
    test_russian_scam_signals()
    test_kazakh_scam_signals()
    test_misleading_subdomain()
    test_official_domain_not_flagged()
    print("ALL HEURISTICS TESTS PASSED")
