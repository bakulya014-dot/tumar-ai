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
    assert report.otp_requested
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


if __name__ == "__main__":
    test_clean_message()
    test_english_scam_signals()
    test_russian_scam_signals()
    test_kazakh_scam_signals()
    test_misleading_subdomain()
    test_official_domain_not_flagged()
    print("ALL HEURISTICS TESTS PASSED")
