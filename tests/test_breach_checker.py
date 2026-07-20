"""Offline tests for services/breach_checker.py (no network calls).

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_breach_checker.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.breach_checker import (
    _BREACHED_RECOMMENDATIONS,
    _CLEAN_TIP_GROUPS,
    BreachCheckError,
    _build_result,
    check_email,
    is_valid_email,
)

_ALL_CLEAN_TIPS = {tip for group in _CLEAN_TIP_GROUPS for tip in group}


def test_email_validation() -> None:
    assert is_valid_email("user@example.com")
    assert is_valid_email("first.last@sub.domain.kz")
    assert not is_valid_email("not-an-email")
    assert not is_valid_email("missing@tld")
    assert not is_valid_email("spaces in@example.com")
    print("test_email_validation PASSED")


def test_invalid_email_raises_coded_error() -> None:
    try:
        check_email("definitely-not-an-email")
    except BreachCheckError as error:
        assert error.code == "invalid_email"
        print("test_invalid_email_raises_coded_error PASSED")
    else:
        raise AssertionError("invalid email did not raise BreachCheckError")


def test_clean_result_varied_tips() -> None:
    result = _build_result("a@b.co", [])
    assert result.breached is False
    assert result.risk_level == "none"
    # One tip per topic group, all drawn from the known pool.
    assert len(result.recommendations) == len(_CLEAN_TIP_GROUPS)
    assert set(result.recommendations) <= _ALL_CLEAN_TIPS
    assert len(set(result.recommendations)) == len(result.recommendations)
    print("test_clean_result_varied_tips PASSED")


def test_medium_risk_result() -> None:
    result = _build_result("a@b.co", ["Adobe"])
    assert result.breached is True
    assert result.breach_count == 1
    assert result.risk_level == "medium"
    assert result.recommendations == list(_BREACHED_RECOMMENDATIONS)
    print("test_medium_risk_result PASSED")


def test_high_risk_result() -> None:
    result = _build_result("a@b.co", ["Adobe", "LinkedIn", "Canva"])
    assert result.risk_level == "high"
    assert result.breach_count == 3
    print("test_high_risk_result PASSED")


if __name__ == "__main__":
    test_email_validation()
    test_invalid_email_raises_coded_error()
    test_clean_result_varied_tips()
    test_medium_risk_result()
    test_high_risk_result()
    print("ALL BREACH CHECKER TESTS PASSED")
