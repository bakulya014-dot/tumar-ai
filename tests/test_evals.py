"""Tests for the evaluation harness and the labelled corpus.

The harness is the instrument the product's quality is measured with,
so the instrument itself needs checking: a metric that quietly
computes the wrong number is worse than no metric, because decisions
get made on it.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_evals.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.runner import (
    AiResult,
    by_language,
    calibration,
    evaluate_scanner,
    evaluate_urls,
    load_messages,
    load_urls,
    rate,
    score,
    scanner_fired,
)

_LANGUAGES = {"en", "ru", "kk"}


def _result(
    case_id: str,
    expected_scam: bool,
    verdict: str,
    confidence: int,
    language: str = "en",
) -> AiResult:
    return AiResult(
        case_id=case_id,
        language=language,
        expected_scam=expected_scam,
        verdict=verdict,
        confidence=confidence,
        risk_score=90 if verdict == "Dangerous" else 10,
    )


def test_message_corpus_is_well_formed() -> None:
    cases = load_messages()
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for case in cases:
        assert case.label in ("scam", "legitimate"), case.id
        assert case.language in _LANGUAGES, case.id
        assert case.text.strip(), case.id
    print("test_message_corpus_is_well_formed PASSED")


def test_message_corpus_is_balanced_across_classes_and_languages() -> None:
    # A corpus of only scams would score a "flag everything" detector
    # at 100%. Both classes, and all three languages, must be present.
    cases = load_messages()
    scams = [case for case in cases if case.is_scam]
    legit = [case for case in cases if not case.is_scam]
    assert scams and legit
    assert abs(len(scams) - len(legit)) <= max(3, len(cases) // 5)
    assert {case.language for case in cases} == _LANGUAGES
    print("test_message_corpus_is_balanced_across_classes_and_languages PASSED")


def test_corpus_contains_hard_negatives() -> None:
    # Legitimate messages that look alarming — real OTP codes, real
    # security alerts — are what expose false positives. Without them
    # the false-positive rate is meaningless.
    cases = load_messages()
    hard = [
        case
        for case in cases
        if not case.is_scam and "hard-negative" in case.tags
    ]
    assert len(hard) >= 5, "corpus needs legitimate look-alike cases"
    print("test_corpus_contains_hard_negatives PASSED")


def test_url_corpus_is_well_formed() -> None:
    cases = load_urls()
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids)), "duplicate url case ids"
    for case in cases:
        assert case.label in ("malicious", "legitimate"), case.id
        assert "." in case.url, case.id
    assert any(case.is_malicious for case in cases)
    assert any(not case.is_malicious for case in cases)
    print("test_url_corpus_is_well_formed PASSED")


def test_rate_handles_empty_denominator() -> None:
    assert rate(0, 0) == 0.0  # must not divide by zero
    assert rate(1, 3) == 33.3
    assert rate(3, 3) == 100.0
    print("test_rate_handles_empty_denominator PASSED")


def test_scanner_fired_separates_obvious_cases() -> None:
    assert scanner_fired("URGENT! Send the SMS code to unblock your card")
    assert not scanner_fired("See you tomorrow at the cafe around six")
    print("test_scanner_fired_separates_obvious_cases PASSED")


def test_score_counts_both_error_types_separately() -> None:
    results = [
        _result("a", True, "Dangerous", 95),   # caught
        _result("b", True, "Safe", 80),        # missed scam
        _result("c", False, "Safe", 90),       # correct
        _result("d", False, "Suspicious", 70), # false alarm
        _result("e", False, "Dangerous", 88),  # hard false alarm
    ]
    summary = score(results)
    assert summary["cases"] == 5
    assert summary["accuracy"] == 40.0  # only a and c are correct, of 5
    assert summary["recall_on_scams"] == 50.0  # 1 of 2 scams flagged
    assert summary["false_positive_rate"] == 66.7  # 2 of 3 legitimate
    assert summary["missed_scams"] == ["b"]
    assert summary["false_alarms"] == ["d", "e"]
    # A confident "Dangerous" on a legitimate message is the worse
    # kind of false alarm, so it is counted on its own.
    assert summary["hard_false_alarms"] == ["e"]
    print("test_score_counts_both_error_types_separately PASSED")


def test_caution_counts_as_flagged() -> None:
    # A "Suspicious" verdict still interrupts the user, so it must
    # count against the false-positive rate rather than being excused.
    results = [_result("a", False, "Suspicious", 60)]
    assert score(results)["false_positive_rate"] == 100.0
    print("test_caution_counts_as_flagged PASSED")


def test_calibration_reports_overconfidence_as_positive_gap() -> None:
    # Four cases claiming ~95 confidence, only half of them right:
    # the model is overconfident and the gap must show it.
    results = [
        _result("a", True, "Dangerous", 95),
        _result("b", True, "Dangerous", 95),
        _result("c", True, "Safe", 95),
        _result("d", True, "Safe", 95),
    ]
    bands = calibration(results)
    assert len(bands) == 1
    band = bands[0]
    assert band["band"] == "90-100"
    assert band["cases"] == 4
    assert band["mean_confidence"] == 95.0
    assert band["accuracy"] == 50.0
    assert band["gap"] == 45.0  # claimed 95, delivered 50
    print("test_calibration_reports_overconfidence_as_positive_gap PASSED")


def test_calibration_skips_empty_bands() -> None:
    results = [_result("a", True, "Dangerous", 95)]
    assert [band["band"] for band in calibration(results)] == ["90-100"]
    print("test_calibration_skips_empty_bands PASSED")


def test_by_language_breaks_out_each_language() -> None:
    results = [
        _result("a", True, "Dangerous", 90, "kk"),
        _result("b", True, "Safe", 90, "kk"),
        _result("c", True, "Dangerous", 90, "en"),
    ]
    breakdown = by_language(results)
    assert breakdown["kk"] == {"cases": 2, "accuracy": 50.0}
    assert breakdown["en"] == {"cases": 1, "accuracy": 100.0}
    print("test_by_language_breaks_out_each_language PASSED")


def test_offline_evaluation_runs_over_the_real_corpus() -> None:
    # The offline path is what CI enforces, so it must work end to end
    # against the shipped corpus with no API key present.
    scanner = evaluate_scanner(load_messages())
    urls = evaluate_urls(load_urls())
    assert scanner["scam_cases"] > 0 and scanner["legitimate_cases"] > 0
    assert 0 <= scanner["signal_rate_on_scams"] <= 100
    assert 0 <= scanner["risk_rate_on_scams"] <= 100
    for rule in ("any_finding_rule", "weighted_rule"):
        assert 0 <= urls[rule]["false_positive_rate"] <= 100
    print("test_offline_evaluation_runs_over_the_real_corpus PASSED")


if __name__ == "__main__":
    test_message_corpus_is_well_formed()
    test_message_corpus_is_balanced_across_classes_and_languages()
    test_corpus_contains_hard_negatives()
    test_url_corpus_is_well_formed()
    test_rate_handles_empty_denominator()
    test_scanner_fired_separates_obvious_cases()
    test_score_counts_both_error_types_separately()
    test_caution_counts_as_flagged()
    test_calibration_reports_overconfidence_as_positive_gap()
    test_calibration_skips_empty_bands()
    test_by_language_breaks_out_each_language()
    test_offline_evaluation_runs_over_the_real_corpus()
    print("ALL EVAL HARNESS TESTS PASSED")
