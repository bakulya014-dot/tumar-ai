"""Regression tests for defects the evaluation harness exposed.

Every case here failed once, in a measured run. They are kept as
tests so the same mistake cannot come back quietly — a heuristic
tweak that helps one scam family and silently reopens one of these is
exactly the kind of change that would otherwise ship unnoticed.

Each test names the failure it locks down.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_regressions.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.confidence import estimate
from services.heuristics import (
    is_official_domain,
    is_suspicious_url,
    scan_message,
    url_reasons,
)


# --- Codes: delivery is not a request (legit-en/ru/kk-real-otp) ---


def test_delivered_code_is_not_treated_as_a_request() -> None:
    """A legitimate code delivery used to be flagged as a scam."""
    for text in (
        "Your verification code is 481920. Do not share this code with anyone.",
        "Код подтверждения: 274815. Никому не сообщайте его.",
        "Растау коды: 593014. Оны ешкімге айтпаңыз.",
    ):
        report = scan_message(text)
        assert report.otp_signal == "delivery", text
        assert report.otp_requested is False, text
        assert "otp_disclosure" not in report.strong_signals, text
    print("test_delivered_code_is_not_treated_as_a_request PASSED")


def test_asking_for_the_code_is_still_a_strong_signal() -> None:
    """The real attack must keep firing — the fix must not blunt it."""
    for text in (
        "Please reply with the code we just sent to your phone.",
        "Назовите код из СМС оператору для отмены перевода.",
        "SMS кодын операторға айтыңыз.",
    ):
        report = scan_message(text)
        assert report.otp_signal == "disclosure", text
        assert report.otp_requested is True, text
        assert "otp_disclosure" in report.strong_signals, text
    print("test_asking_for_the_code_is_still_a_strong_signal PASSED")


def test_typing_a_code_is_ambiguous_not_damning() -> None:
    """Two-factor setup (adv-legit-en/ru-2fa-setup) asks you to type a code."""
    report = scan_message(
        "To finish setting up two-factor authentication, enter the code from "
        "your authenticator app into the field on this page."
    )
    assert report.otp_signal == "entry"
    assert "otp_entry" in report.weak_signals
    assert not report.strong_signals
    print("test_typing_a_code_is_ambiguous_not_damning PASSED")


def test_security_advice_is_recognized(  ) -> None:
    """A bank warning about codes (adv-legit-*-bank-warning) is not a scam."""
    for text in (
        "We will never ask for your one-time code, PIN or password.",
        "Мы никогда не просим назвать код из СМС, ПИН-код или пароль.",
    ):
        assert scan_message(text).security_advice is True, text
    print("test_security_advice_is_recognized PASSED")


# --- URLs: official domains (url-legit-halyk, apple, microsoft) ---


def test_official_domains_are_not_judged_by_word_spotting() -> None:
    """Real banks have "bank" in the name; support sites have "support"."""
    for url in (
        "https://halykbank.kz/ru/private",
        "https://support.apple.com/en-us",
        "https://login.microsoftonline.com",
        "https://accounts.google.com/signin",
        "https://secure.jusan.kz/login",
        "https://kaspi.kz/shop/p/telefon",
    ):
        reasons = url_reasons(url)
        assert "trust_bait" not in reasons, f"{url} -> {reasons}"
        assert "brand_lookalike" not in reasons, f"{url} -> {reasons}"
        assert not is_suspicious_url(url), f"{url} -> {reasons}"
    print("test_official_domains_are_not_judged_by_word_spotting PASSED")


def test_official_domain_recognition_is_not_a_substring_match() -> None:
    """"kaspi.kz.evil.top" must not pass as official."""
    assert is_official_domain("kaspi.kz")
    assert is_official_domain("shop.kaspi.kz")
    assert not is_official_domain("kaspi.kz.login.secure-verify.top")
    assert not is_official_domain("notkaspi.kz")
    print("test_official_domain_recognition_is_not_a_substring_match PASSED")


def test_impersonation_still_caught_on_lookalike_domains() -> None:
    for url in (
        "http://kaspi-bonus-security.xyz/login",
        "http://halykbank.kz.secure-login.top/enter",
        "http://kaspi.kz.login.secure-verify.top/session",
        "http://jusan-online-cabinet.site/auth",
    ):
        assert is_suspicious_url(url), url
    print("test_impersonation_still_caught_on_lookalike_domains PASSED")


# --- URLs: typosquats (url-phish-typo-kaspi was missed) ---


def test_transposed_letters_are_caught() -> None:
    """"kapsi" for "kaspi" — the eye corrects it, the scanner must not."""
    assert "misspelled_domain" in url_reasons("https://kapsi.kz/login")
    assert "misspelled_domain" in url_reasons("https://googel.com/account")
    assert is_suspicious_url("https://kapsi.kz/login")
    print("test_transposed_letters_are_caught PASSED")


def test_homoglyph_domains_are_caught() -> None:
    """A Cyrillic letter inside a Latin domain is invisible to the reader."""
    assert "homoglyph" in url_reasons("http://kаspi-bonus.kz/login")
    assert is_suspicious_url("http://kаspi-bonus.kz/login")
    # An all-Cyrillic or all-Latin host is not a homoglyph attack.
    assert "homoglyph" not in url_reasons("https://kaspi.kz")
    print("test_homoglyph_domains_are_caught PASSED")


# --- URLs: weak signals alone (url-legit-hyphen-domain) ---


def test_hyphens_alone_do_not_condemn_a_domain() -> None:
    """Ordinary hyphenated domains were being reported as suspicious."""
    for url in (
        "https://open-source-lab.org/projects",
        "https://open-data-portal.org/datasets",
    ):
        assert not is_suspicious_url(url), url
    print("test_hyphens_alone_do_not_condemn_a_domain PASSED")


def test_weak_signals_still_add_up() -> None:
    """Several weak findings together are worth flagging."""
    url = "http://secure-account-verify-login.click/session"
    assert is_suspicious_url(url)
    print("test_weak_signals_still_add_up PASSED")


# --- Confidence: never inflated, always explained ---


def _report(text: str):
    return scan_message(text)


def test_confidence_drops_when_only_the_ai_flags_it() -> None:
    heuristics = _report("See you tomorrow at the cafe around six o'clock.")
    result = estimate(95, "danger", heuristics, text_length=200)
    assert result.value < 95
    assert "confidence.ai_only" in result.reason_keys
    print("test_confidence_drops_when_only_the_ai_flags_it PASSED")


def test_confidence_rises_when_both_layers_agree() -> None:
    heuristics = _report("Please reply with the code we just sent to your phone.")
    agreed = estimate(80, "danger", heuristics, text_length=200)
    assert agreed.value > 80
    assert "confidence.agreement" in agreed.reason_keys
    print("test_confidence_rises_when_both_layers_agree PASSED")


def test_confidence_drops_on_contradiction() -> None:
    heuristics = _report("Назовите код из СМС оператору.")
    result = estimate(90, "safe", heuristics, text_length=200)
    assert result.value < 90
    assert "confidence.contradiction" in result.reason_keys
    print("test_confidence_drops_on_contradiction PASSED")


def test_confidence_never_claims_certainty() -> None:
    heuristics = _report("Please reply with the code we just sent to your phone.")
    result = estimate(100, "danger", heuristics, text_length=500)
    assert result.value <= 95, "no verdict from this system is a certainty"
    print("test_confidence_never_claims_certainty PASSED")


def test_confidence_always_explains_itself() -> None:
    heuristics = _report("Your verification code is 481920.")
    result = estimate(88, "safe", heuristics, text_length=120)
    assert result.reason_keys, "a confidence with no reason is decoration"
    print("test_confidence_always_explains_itself PASSED")


if __name__ == "__main__":
    test_delivered_code_is_not_treated_as_a_request()
    test_asking_for_the_code_is_still_a_strong_signal()
    test_typing_a_code_is_ambiguous_not_damning()
    test_security_advice_is_recognized()
    test_official_domains_are_not_judged_by_word_spotting()
    test_official_domain_recognition_is_not_a_substring_match()
    test_impersonation_still_caught_on_lookalike_domains()
    test_transposed_letters_are_caught()
    test_homoglyph_domains_are_caught()
    test_hyphens_alone_do_not_condemn_a_domain()
    test_weak_signals_still_add_up()
    test_confidence_drops_when_only_the_ai_flags_it()
    test_confidence_rises_when_both_layers_agree()
    test_confidence_drops_on_contradiction()
    test_confidence_never_claims_certainty()
    test_confidence_always_explains_itself()
    print("ALL REGRESSION TESTS PASSED")
