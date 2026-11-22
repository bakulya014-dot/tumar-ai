"""Evidence-first risk card: category, severity, confidence, evidence split,
Contain now, and what Tumar protected.

    venv\\Scripts\\python.exe tests\\test_risk_card.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

from i18n import LANGUAGES, _load, translate  # noqa: E402
from services import risk_card  # noqa: E402
from services.offline_report import offline_message_report, offline_url_report  # noqa: E402
from services.trust_report import Evidence, TrustReport  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

DEMO = (
    "Kaspi Bank: your card is blocked due to suspicious activity. To unlock, confirm your "
    "details at http://kaspi-secure-verify.xyz/unlock and tell the operator the code from the SMS."
)


def _report(kind="message", verdict="danger", trust=10, confidence=80, evidence=(), level="", meta=None):
    return TrustReport(
        source="test", subject_type=kind, subject_preview="x", verdict=verdict,
        trust_score=trust, confidence=confidence, evidence=list(evidence),
        risk_level=level, analysis_metadata=meta or {},
    )


def E(code, kind="heuristic"):
    return Evidence(kind=kind, code=code, detail="")


def test_demo_message_is_phishing_with_contain_now() -> None:
    card = risk_card.build(offline_message_report(DEMO, "missing_key"))
    assert card.category == "phishing", card.category
    assert card.severity in {"high", "critical"} and card.contain_keys
    assert "link_not_opened" in card.protected_keys and "masked" in card.protected_keys
    assert card.protected_keys[-1] == "no_action"
    print("test_demo_message_is_phishing_with_contain_now PASSED")


def test_categories() -> None:
    assert risk_card.category(_report(evidence=[E("url_brand_lookalike")])) == "impersonation"
    assert risk_card.category(_report(evidence=[E("url_brand_lookalike"), E("credential")])) == "phishing"
    assert risk_card.category(_report(evidence=[E("otp_disclosure")])) == "account_takeover"
    assert risk_card.category(_report(evidence=[E("financial")])) == "payment_fraud"
    assert risk_card.category(_report(kind="email", evidence=[E("breach", "external")])) == "breach_exposure"
    assert risk_card.category(_report(kind="password")) == "account_takeover"
    assert risk_card.category(_report(kind="image", meta={"categories": "fake_payment_request, phishing"})) == "payment_fraud"
    assert risk_card.category(_report(verdict="safe", evidence=[E("urgency")])) == "unknown"
    assert risk_card.category(_report(evidence=[])) == "unknown"
    print("test_categories PASSED")


def test_undetectable_categories_are_never_assigned() -> None:
    # No Tumar check detects malware or misinformation today: never claim them.
    reports = [_report(evidence=[E(c)]) for c in (
        "urgency", "otp_disclosure", "credential", "financial", "manipulation", "red_flag",
        "url_ip_address", "url_shortener", "prompt_injection", "qr_link",
    )]
    assert not {risk_card.category(r) for r in reports} & {"malware", "misinformation"}
    print("test_undetectable_categories_are_never_assigned PASSED")


def test_severity_and_confidence_band() -> None:
    assert risk_card.severity(_report(verdict="danger", trust=10)) == "critical"
    assert risk_card.severity(_report(verdict="danger", trust=40)) == "high"
    assert risk_card.severity(_report(verdict="caution", trust=55)) == "medium"
    assert risk_card.severity(_report(verdict="safe", trust=90)) == "low"
    assert risk_card.severity(_report(kind="image", level="moderate")) == "medium"
    assert [risk_card.confidence_band(c) for c in (30, 60, 90)] == ["low", "medium", "high"]
    print("test_severity_and_confidence_band PASSED")


def test_evidence_is_split_by_certainty() -> None:
    card = risk_card.build(_report(evidence=[
        E("url_ip_address"), E("breach", "external"), E("url_brand_lookalike"),
        E("urgency"), E("red_flag", "ai"), E("vision_brand", "ai"),
    ]))
    assert {e.code for e in card.confirmed} == {"url_ip_address", "breach"}
    assert {e.code for e in card.suspicious} == {"url_brand_lookalike", "urgency"}
    assert {e.code for e in card.ai_assessment} == {"red_flag", "vision_brand"}  # never "confirmed"
    print("test_evidence_is_split_by_certainty PASSED")


def test_contain_now_only_for_dangerous_results() -> None:
    assert risk_card.build(_report(verdict="caution", trust=50, evidence=[E("urgency")])).contain_keys == []
    assert risk_card.build(_report(verdict="safe", trust=95)).contain_keys == []
    assert risk_card.build(offline_url_report("http://185.199.44.12/bank/login.php", "missing_key")).protected_keys[0] == "link_not_opened"
    print("test_contain_now_only_for_dangerous_results PASSED")


def test_every_card_string_exists_in_all_languages() -> None:
    keys = {f"protect.category.{c}" for c in risk_card.CATEGORIES}
    keys |= {f"protect.why.{c}" for c in risk_card.CATEGORIES} | {f"protect.exposure.{c}" for c in risk_card.CATEGORIES}
    keys |= {f"protect.severity.{s}" for s in risk_card.SEVERITIES} | {f"protect.band.{b}" for b in risk_card.CONFIDENCE_BANDS}
    keys |= {f"protect.contain.{k}" for v in risk_card.CONTAIN_KEYS.values() for k in v}
    keys |= {f"protect.done.{k}" for k in ("masked", "link_not_opened", "image_not_stored", "email_not_stored", "password_prefix", "no_action")}
    keys |= {"protect.contain_title", "protect.contain_note", "protect.done_title", "protect.ai_assessment"}
    for language in LANGUAGES:
        missing = sorted(keys - set(_load(language)))
        assert not missing, (language, missing)
    print(f"test_every_card_string_exists_in_all_languages PASSED ({len(keys)} keys)")


def _render_app():
    import sys as _sys

    import streamlit as st

    _sys.path.insert(0, st.session_state["root"])
    from report_view import render_trust_report
    from services.offline_report import offline_message_report

    render_trust_report(offline_message_report(st.session_state["text"], "missing_key"))


def test_report_shows_card_contain_now_and_protections() -> None:
    at = AppTest.from_function(_render_app, default_timeout=60)
    at.session_state["root"] = str(ROOT)
    at.session_state["text"] = DEMO
    at.run()
    assert not at.exception, at.exception
    text = "\n".join(m.value for m in at.markdown)
    assert translate("protect.contain_title", "en") in text
    assert translate("protect.contain.no_click", "en") in text
    assert translate("protect.done.link_not_opened", "en") in text
    assert translate("protect.category.phishing", "en") in text
    assert "kaspi-secure-verify" not in "".join(m.value for m in at.markdown if "t-chip" in m.value)
    print("test_report_shows_card_contain_now_and_protections PASSED")


if __name__ == "__main__":
    test_demo_message_is_phishing_with_contain_now()
    test_categories()
    test_undetectable_categories_are_never_assigned()
    test_severity_and_confidence_band()
    test_evidence_is_split_by_certainty()
    test_contain_now_only_for_dangerous_results()
    test_every_card_string_exists_in_all_languages()
    test_report_shows_card_contain_now_and_protections()
    print("All risk card tests passed.")
