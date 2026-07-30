"""Offline tests for services/trust_report.py (no network calls).

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_trust_report.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.breach_checker import EmailBreachResult
from services.heuristics import HeuristicReport, SuspiciousURL
from services.scam_analysis import ScamAnalysis, ScamReport
from services.trust_report import (
    TrustReport,
    from_breach_result,
    from_scam_report,
    mask_email,
    preview_text,
)


def _sample_scam_report() -> ScamReport:
    """A dangerous message: heuristic matches plus an AI verdict."""
    ai = ScamAnalysis(
        verdict="Dangerous",
        risk_score=90,
        confidence=85,
        credential_theft_risk=80,
        financial_scam_risk=70,
        red_flags=["Impersonates a bank", "Requests an OTP code"],
        explanation="This message imitates Kaspi bank and asks for a code.",
        recommended_actions=["Do not reply", "Block the sender"],
    )
    heuristics = HeuristicReport(
        urgency_score=35,
        urgency_matches=["urgent"],
        otp_requested=True,
        otp_matches=["verification code"],
        credential_indicators=[],
        financial_indicators=[],
        manipulation_indicators=[],
        suspicious_urls=[
            SuspiciousURL(url="http://kaspi-secure.xyz", reasons=["brand_lookalike"])
        ],
    )
    return ScamReport(ai=ai, heuristics=heuristics)


def test_scam_adapter_maps_verdict_and_score() -> None:
    report = from_scam_report(_sample_scam_report(), "Urgent! Send the code")
    assert report.source == "scam_analyzer"
    assert report.subject_type == "message"
    assert report.verdict == "danger"  # "Dangerous" -> platform code
    assert report.trust_score == 10  # risk 90 -> trust 100 - 90
    assert report.confidence == 85
    assert report.explanation  # AI free text present…
    assert report.explanation_key == ""  # …so no translation key
    print("test_scam_adapter_maps_verdict_and_score PASSED")


def test_scam_adapter_collects_all_evidence_layers() -> None:
    report = from_scam_report(_sample_scam_report(), "Urgent! Send the code")
    kinds = {item.kind for item in report.evidence}
    assert kinds == {"heuristic", "ai"}
    codes = [item.code for item in report.evidence]
    assert "urgency" in codes
    assert "otp" in codes
    assert "url_brand_lookalike" in codes
    assert codes.count("red_flag") == 2
    print("test_scam_adapter_collects_all_evidence_layers PASSED")


def test_breach_adapter_breached_email() -> None:
    result = EmailBreachResult(
        email="bakytzhan@gmail.com",
        breached=True,
        breach_count=3,
        breaches=["Adobe", "LinkedIn", "Canva"],
        risk_level="high",
        recommendations=["rec_change_passwords", "rec_enable_mfa"],
    )
    report = from_breach_result(result)
    assert report.verdict == "danger"
    assert report.trust_score == 15
    assert "@" in report.subject_preview
    assert "bakytzhan" not in report.subject_preview  # masked
    assert [item.detail for item in report.evidence] == ["Adobe", "LinkedIn", "Canva"]
    assert all(item.kind == "external" for item in report.evidence)
    # Full dotted i18n keys — any consumer renders them with t(key).
    assert report.recommended_action_keys == [
        "breach.rec_change_passwords",
        "breach.rec_enable_mfa",
    ]
    assert report.explanation_key == "breach.explanation_high"
    assert report.recommended_actions == []  # keys, not free text
    print("test_breach_adapter_breached_email PASSED")


def test_breach_adapter_clean_email_is_not_certainty() -> None:
    result = EmailBreachResult(
        email="a@b.co",
        breached=False,
        breach_count=0,
        breaches=[],
        risk_level="none",
        recommendations=["rec_enable_mfa"],
    )
    report = from_breach_result(result)
    assert report.verdict == "safe"
    # Clean means "not in known breaches", never "guaranteed safe".
    assert report.trust_score < 100
    assert report.evidence == []
    print("test_breach_adapter_clean_email_is_not_certainty PASSED")


def test_report_survives_json_round_trip() -> None:
    # History (Step 3) and the API (Step 4) both depend on this.
    original = from_scam_report(_sample_scam_report(), "Urgent! Send the code")
    restored = TrustReport.model_validate_json(original.model_dump_json())
    assert restored == original
    print("test_report_survives_json_round_trip PASSED")


def test_preview_text_truncates_and_flattens() -> None:
    assert preview_text("short message") == "short message"
    assert preview_text("line one\nline two\t end") == "line one line two end"
    long_preview = preview_text("x" * 500)
    assert len(long_preview) == 80
    assert long_preview.endswith("…")
    print("test_preview_text_truncates_and_flattens PASSED")


def test_mask_email_hides_local_part() -> None:
    assert mask_email("bakytzhan@gmail.com") == "b*******n@gmail.com"
    assert mask_email("ab@x.kz") == "a*@x.kz"
    assert mask_email("a@x.kz") == "a*@x.kz"
    print("test_mask_email_hides_local_part PASSED")


if __name__ == "__main__":
    test_scam_adapter_maps_verdict_and_score()
    test_scam_adapter_collects_all_evidence_layers()
    test_breach_adapter_breached_email()
    test_breach_adapter_clean_email_is_not_certainty()
    test_report_survives_json_round_trip()
    test_preview_text_truncates_and_flattens()
    test_mask_email_hides_local_part()
    print("ALL TRUST REPORT TESTS PASSED")
