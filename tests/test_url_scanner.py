"""Offline tests for services/url_scanner.py (no network calls).

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_url_scanner.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.heuristics import url_reasons
from services.scam_analysis import ScamAnalysisError, analyze_message
from services.url_scanner import (
    UrlAnalysis,
    UrlScanError,
    build_report,
    normalize_url,
)


def test_normalize_url_defaults_to_https() -> None:
    # A bare domain gets the charitable https:// default, so the
    # no_https heuristic never fires on user typing habits.
    assert normalize_url("kaspi.kz") == "https://kaspi.kz"
    assert normalize_url("  example.com/path  ") == "https://example.com/path"
    # An explicit scheme is preserved — http stays visible and flagged.
    assert normalize_url("http://example.com") == "http://example.com"
    print("test_normalize_url_defaults_to_https PASSED")


def test_normalize_url_rejects_garbage() -> None:
    for bad in ("", "   ", "not a url", "no-dot-here", "ftp://example.com"):
        try:
            normalize_url(bad)
        except UrlScanError as error:
            assert error.code == "invalid_url"
        else:
            raise AssertionError(f"{bad!r} was not rejected")
    print("test_normalize_url_rejects_garbage PASSED")


def test_bare_domain_gets_no_false_no_https_flag() -> None:
    assert "no_https" not in url_reasons(normalize_url("kaspi.kz"))
    assert "no_https" in url_reasons("http://example-login-secure.com")
    print("test_bare_domain_gets_no_false_no_https_flag PASSED")


def test_example_url_triggers_heuristics() -> None:
    # The i18n example URL must actually demo the scanner well.
    reasons = url_reasons("http://kaspi-bonus-security.xyz/login")
    assert "brand_lookalike" in reasons
    assert "suspicious_tld" in reasons
    assert "no_https" in reasons
    print("test_example_url_triggers_heuristics PASSED")


def test_build_report_combines_both_layers() -> None:
    analysis = UrlAnalysis(
        verdict="danger",
        risk_score=88,
        confidence=80,
        red_flags=["Brand imitation"],
        explanation="This address imitates Kaspi and hides behind a cheap zone.",
        recommended_actions=["Do not open this link"],
    )
    url = "http://kaspi-bonus-security.xyz/login"
    report = build_report(url, url_reasons(url), analysis)

    assert report.source == "url_scanner"
    assert report.subject_type == "url"
    assert report.verdict == "danger"
    assert report.trust_score == 12  # 100 - risk 88
    kinds = {item.kind for item in report.evidence}
    assert kinds == {"heuristic", "ai"}
    # Shared "url_" vocabulary, same as the scam analyzer's link findings.
    heuristic_codes = [i.code for i in report.evidence if i.kind == "heuristic"]
    assert "url_brand_lookalike" in heuristic_codes
    assert report.subject_preview.startswith("http://kaspi-bonus")
    print("test_build_report_combines_both_layers PASSED")


def test_clean_url_report_keeps_ai_verdict() -> None:
    analysis = UrlAnalysis(
        verdict="safe",
        risk_score=10,
        confidence=70,
        red_flags=[],
        explanation="Nothing suspicious in the address itself.",
        recommended_actions=["Stay alert on the page itself"],
    )
    report = build_report("https://kaspi.kz", [], analysis)
    assert report.verdict == "safe"
    assert report.trust_score == 90
    assert report.evidence == []
    print("test_clean_url_report_keeps_ai_verdict PASSED")


def test_scam_analyzer_error_contract_survived_refactor() -> None:
    # After extracting the shared Gemini client, the scam analyzer
    # must still raise its own error type with the same codes.
    try:
        analyze_message("hello", api_key="")
    except ScamAnalysisError as error:
        assert error.code == "missing_key"
    else:
        raise AssertionError("missing key did not raise ScamAnalysisError")
    print("test_scam_analyzer_error_contract_survived_refactor PASSED")


if __name__ == "__main__":
    test_normalize_url_defaults_to_https()
    test_normalize_url_rejects_garbage()
    test_bare_domain_gets_no_false_no_https_flag()
    test_example_url_triggers_heuristics()
    test_build_report_combines_both_layers()
    test_clean_url_report_keeps_ai_verdict()
    test_scam_analyzer_error_contract_survived_refactor()
    print("ALL URL SCANNER TESTS PASSED")
