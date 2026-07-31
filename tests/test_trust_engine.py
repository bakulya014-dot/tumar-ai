"""Offline tests for services/trust_engine.py (no network calls).

Detection and routing are pure logic, so everything here runs
offline; analyze() flows are exercised through a fake analyzer.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_trust_engine.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.trust_engine import (
    AnalysisContext,
    Analyzer,
    EngineError,
    TrustEngine,
    TrustSubject,
    default_analyzers,
)
from services.trust_report import TrustReport


def _kind_for(content: str | bytes, declared: str = "") -> str | None:
    subject = TrustSubject(content=content, declared_kind=declared)
    analyzer = TrustEngine().detect(subject)
    return analyzer.kind if analyzer else None


def test_detection_routes_by_content_shape() -> None:
    assert _kind_for("user@example.com") == "email"
    assert _kind_for("https://kaspi.kz/pay") == "url"
    assert _kind_for("kaspi.kz") == "url"  # bare domain
    assert _kind_for("URGENT! Your card is blocked, send the code") == "message"
    print("test_detection_routes_by_content_shape PASSED")


def test_email_wins_over_url_by_registration_order() -> None:
    # "user@example.com" also parses as a URL (host example.com), so
    # only the registry order makes routing deterministic. This test
    # pins that contract.
    ordered_kinds = [analyzer.kind for analyzer in default_analyzers()]
    assert ordered_kinds.index("email") < ordered_kinds.index("url")
    assert ordered_kinds.index("url") < ordered_kinds.index("message")
    assert _kind_for("user@example.com") == "email"
    print("test_email_wins_over_url_by_registration_order PASSED")


def test_declared_kind_bypasses_detection() -> None:
    # A consumer that KNOWS its payload routes directly — this is how
    # ambiguous structured text (agent logs, itineraries) will route.
    assert _kind_for("kaspi.kz", declared="message") == "message"
    assert _kind_for("anything at all", declared="url") == "url"
    assert _kind_for("text", declared="no_such_analyzer") is None
    print("test_declared_kind_bypasses_detection PASSED")


def test_passwords_are_never_auto_detected() -> None:
    """A password must never be routed by guesswork.

    The fallback analyzer sends text to the AI provider, so a wrong
    guess here would mean shipping a user's password to a third party.
    Password routing is therefore opt-in by name only.
    """
    password_like = (
        "hunter2",
        "Tr0ub4dor&3",
        "correct horse battery staple",
        "P@ssw0rd!2026",
    )
    for candidate in password_like:
        kind = _kind_for(candidate)
        assert kind != "password", candidate
        assert kind == "message"  # falls through to the scam analyzer

    # …but the Password Health page reaches it by declaring the kind.
    assert _kind_for("hunter2", declared="password") == "password"
    print("test_passwords_are_never_auto_detected PASSED")


def test_unsupported_input_raises_coded_error() -> None:
    engine = TrustEngine()
    subject = TrustSubject(content=b"\x89PNG...", mime_type="image/png")
    assert engine.detect(subject) is None
    try:
        engine.analyze(subject, AnalysisContext())
    except EngineError as error:
        assert error.code == "unsupported_input"
    else:
        raise AssertionError("binary subject did not raise EngineError")
    print("test_unsupported_input_raises_coded_error PASSED")


def test_empty_text_is_not_claimed_by_anyone() -> None:
    assert _kind_for("") is None
    assert _kind_for("   ") is None
    print("test_empty_text_is_not_claimed_by_anyone PASSED")


class _FakePdfAnalyzer(Analyzer):
    """A future module, written without touching the engine."""

    kind = "pdf"

    def can_handle(self, subject: TrustSubject) -> bool:
        return subject.mime_type == "application/pdf"

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        return TrustReport(
            source="pdf_analyzer",
            subject_type="message",
            subject_preview=subject.filename,
            verdict="caution",
            trust_score=50,
            confidence=40,
        )


def test_open_closed_principle_new_analyzer_no_engine_change() -> None:
    # The whole point of the architecture: extending the platform is
    # registering one more analyzer — TrustEngine code is untouched.
    engine = TrustEngine(list(default_analyzers()) + [_FakePdfAnalyzer()])
    subject = TrustSubject(
        content=b"%PDF-1.7 ...",
        mime_type="application/pdf",
        filename="itinerary.pdf",
    )
    detected = engine.detect(subject)
    assert detected is not None and detected.kind == "pdf"

    report = engine.analyze(subject, AnalysisContext())
    assert report.source == "pdf_analyzer"
    assert report.subject_preview == "itinerary.pdf"
    # Text detection is unaffected by the new registration.
    assert engine.detect(TrustSubject(content="user@example.com")).kind == "email"
    print("test_open_closed_principle_new_analyzer_no_engine_change PASSED")


if __name__ == "__main__":
    test_detection_routes_by_content_shape()
    test_email_wins_over_url_by_registration_order()
    test_declared_kind_bypasses_detection()
    test_passwords_are_never_auto_detected()
    test_unsupported_input_raises_coded_error()
    test_empty_text_is_not_claimed_by_anyone()
    test_open_closed_principle_new_analyzer_no_engine_change()
    print("ALL TRUST ENGINE TESTS PASSED")
