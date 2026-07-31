"""Offline tests for services/password_check.py (no network calls).

The privacy properties are tested as hard as the logic: what leaves
this process, and what ends up inside a report, are security
guarantees rather than implementation details.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_password_check.py
"""

import hashlib
import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.password_check import (
    PREFIX_LENGTH,
    PasswordCheckError,
    assess_strength,
    build_report,
    check_password,
    count_matches,
    hash_parts,
)

# A real HIBP range response: "SUFFIX:COUNT" per line, plus the padding
# entries the Add-Padding header asks for (count 0).
_SAMPLE_BODY = "\n".join(
    [
        "003D68EB55068C33ACE09247EE4C639306B:3",
        "012C192B2F16F82EA0EB9EF18D9D539B0DD:0",
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:37359195",
        "20597F5AC10A2F67701B4AD1D3A09F0B650:3",
    ]
)


def test_only_five_hash_characters_are_shareable() -> None:
    # The k-anonymity contract: the prefix is what goes over the wire,
    # so it must be short and must not be the whole hash.
    prefix, suffix = hash_parts("password123")
    assert len(prefix) == PREFIX_LENGTH == 5
    full = hashlib.sha1(b"password123").hexdigest().upper()
    assert full == prefix + suffix
    assert len(prefix) < len(suffix)  # most of the hash never leaves
    print("test_only_five_hash_characters_are_shareable PASSED")


def test_hash_parts_are_uppercase_hex() -> None:
    # HIBP compares uppercase; a lowercase digest would never match and
    # every password would look clean — a silent false "safe".
    prefix, suffix = hash_parts("Correct Horse Battery Staple")
    assert (prefix + suffix).isupper()
    assert all(char in "0123456789ABCDEF" for char in prefix + suffix)
    print("test_hash_parts_are_uppercase_hex PASSED")


def test_count_matches_finds_and_misses_correctly() -> None:
    assert count_matches(_SAMPLE_BODY, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 37359195
    assert count_matches(_SAMPLE_BODY, "003D68EB55068C33ACE09247EE4C639306B") == 3
    # Padding entries report zero, and an absent suffix is simply zero.
    assert count_matches(_SAMPLE_BODY, "012C192B2F16F82EA0EB9EF18D9D539B0DD") == 0
    assert count_matches(_SAMPLE_BODY, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0
    print("test_count_matches_finds_and_misses_correctly PASSED")


def test_count_matches_survives_malformed_lines() -> None:
    body = "GARBAGE\n\nAAA:notanumber\nBBB:5"
    assert count_matches(body, "BBB") == 5
    assert count_matches(body, "AAA") == 0  # bad count, not a crash
    print("test_count_matches_survives_malformed_lines PASSED")


def test_common_passwords_score_low_regardless_of_shape() -> None:
    for password in ("password", "qwerty", "Password123", "letmein"):
        strength = assess_strength(password)
        assert strength.score <= 10, password
        assert "pw_common" in strength.codes
    print("test_common_passwords_score_low_regardless_of_shape PASSED")


def test_strength_rewards_length_and_variety() -> None:
    weak = assess_strength("abcd")
    decent = assess_strength("horse battery staple")
    strong = assess_strength("Tr0ub4dor&3xKcd!Long")
    assert weak.score < decent.score <= strong.score
    assert "pw_too_short" in weak.codes
    print("test_strength_rewards_length_and_variety PASSED")


def test_strength_flags_patterns() -> None:
    assert "pw_sequential" in assess_strength("myabcdefpass").codes
    assert "pw_sequential" in assess_strength("login1234now").codes
    assert "pw_repeated" in assess_strength("shhhhhbeQuiet").codes
    assert "pw_single_class" in assess_strength("onlyletters").codes
    print("test_strength_flags_patterns PASSED")


def test_report_never_contains_the_password_or_its_length() -> None:
    # The report is stored in session history and would be returned by
    # a future API, so it must carry nothing derived from the secret.
    secret = "hunter2-super-secret-passphrase"
    report = build_report(assess_strength(secret), breach_count=0)
    serialized = report.model_dump_json()
    assert secret not in serialized
    assert "hunter" not in serialized
    assert str(len(secret)) not in report.subject_preview
    assert set(report.subject_preview) == {"•"}
    print("test_report_never_contains_the_password_or_its_length PASSED")


def test_breached_password_is_dangerous_however_strong() -> None:
    # Strength stops mattering once a password is on attacker lists.
    strong = assess_strength("Tr0ub4dor&3xKcd!Long")
    report = build_report(strong, breach_count=42)
    assert report.verdict == "danger"
    assert report.trust_score <= 20
    assert report.explanation_key == "password.explanation_breached"
    external = [item for item in report.evidence if item.kind == "external"]
    assert external and external[0].detail == "42"
    print("test_breached_password_is_dangerous_however_strong PASSED")


def test_weak_but_unbreached_password_warns() -> None:
    report = build_report(assess_strength("abcd"), breach_count=0)
    assert report.verdict == "caution"
    assert report.explanation_key == "password.explanation_weak"
    print("test_weak_but_unbreached_password_warns PASSED")


def test_clean_password_is_never_fully_trusted() -> None:
    report = build_report(assess_strength("Tr0ub4dor&3xKcd!Long"), breach_count=0)
    assert report.verdict == "safe"
    # "Not in the breaches we know about" is not certainty.
    assert report.trust_score < 100
    assert report.confidence < 100
    print("test_clean_password_is_never_fully_trusted PASSED")


def test_strength_metric_counts_up_not_down() -> None:
    report = build_report(assess_strength("abcd"), breach_count=0)
    metric = report.metrics[0]
    assert metric.label_key == "password.metric_strength"
    # Strength is the one metric where a high number is good news.
    assert metric.higher_is_worse is False
    print("test_strength_metric_counts_up_not_down PASSED")


def test_empty_password_is_rejected_before_any_request() -> None:
    try:
        check_password("")
    except PasswordCheckError as error:
        assert error.code == "empty_password"
    else:
        raise AssertionError("empty password did not raise")
    print("test_empty_password_is_rejected_before_any_request PASSED")


if __name__ == "__main__":
    test_only_five_hash_characters_are_shareable()
    test_hash_parts_are_uppercase_hex()
    test_count_matches_finds_and_misses_correctly()
    test_count_matches_survives_malformed_lines()
    test_common_passwords_score_low_regardless_of_shape()
    test_strength_rewards_length_and_variety()
    test_strength_flags_patterns()
    test_report_never_contains_the_password_or_its_length()
    test_breached_password_is_dangerous_however_strong()
    test_weak_but_unbreached_password_warns()
    test_clean_password_is_never_fully_trusted()
    test_strength_metric_counts_up_not_down()
    test_empty_password_is_rejected_before_any_request()
    print("ALL PASSWORD CHECK TESTS PASSED")
