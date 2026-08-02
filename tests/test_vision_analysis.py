"""Tests for vision analysis and its route into the Trust Engine.

A stub provider stands in for the model, so these run offline. What
matters here is the boundary: the vision layer reports facts, the
engine reaches the verdict, and nothing derived from the image bytes
escapes into a report.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_vision_analysis.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import BaseModel

from services.confidence import estimate
from services.heuristics import scan_message
from services.providers.base import AIProvider, ProviderError
from services.scam_analysis import ScamAnalysis, ScamReport
from services.trust_engine import (
    AnalysisContext,
    ImageAnalyzer,
    TrustEngine,
    TrustSubject,
)
from services.trust_report import from_image_analysis
from services.vision_analysis import (
    MAX_IMAGE_BYTES,
    VisionAnalysisError,
    VisionFinding,
    analyze_image,
    to_analysis_text,
)

_PNG = b"\x89PNG\r\n\x1a\n" + b"pretend-image-bytes" * 4

_SAMPLE = VisionFinding(
    language="ru",
    detected_text="СРОЧНО! Карта заблокирована. Назовите код оператору.",
    urls=["http://kaspi-verify.xyz/login"],
    brands=["Kaspi"],
    otp_requests=["Назовите код оператору"],
    phone_numbers=["+7 701 234 5678"],
    risk_indicators=["Address bar does not match the brand"],
    summary="A page imitating Kaspi asking for a one-time code.",
    confidence=88,
)


class _StubProvider(AIProvider):
    """A vision provider that returns whatever the test wants."""

    name = "stub"

    def __init__(self, finding: VisionFinding | None = None, error: str = ""):
        self.finding = finding or _SAMPLE
        self.error = error
        self.seen: dict = {}

    def available(self) -> bool:
        return True

    def supports_vision(self) -> bool:
        return True

    def generate_structured(self, system_prompt, contents, schema):
        raise NotImplementedError

    def analyze_image(
        self, image_bytes, mime_type, system_prompt, schema, instruction=""
    ):
        self.seen = {"bytes": image_bytes, "mime": mime_type}
        if self.error:
            raise ProviderError(self.error)
        return self.finding


def _scam_report(verdict: str = "Dangerous", confidence: int = 90) -> ScamReport:
    text = to_analysis_text(_SAMPLE)
    return ScamReport(
        ai=ScamAnalysis(
            verdict=verdict,
            risk_score=95 if verdict == "Dangerous" else 10,
            confidence=confidence,
            credential_theft_risk=90,
            financial_scam_risk=40,
            red_flags=["Fake bank identity"],
            explanation="A page imitating a bank, asking for a code.",
            recommended_actions=["Do not enter anything"],
        ),
        heuristics=scan_message(text),
    )


# --- Input validation, before anything is uploaded ---


def test_oversized_and_unsupported_images_are_refused_locally() -> None:
    provider = _StubProvider()
    for payload, mime, code in (
        (b"", "image/png", "empty_image"),
        (b"x" * (MAX_IMAGE_BYTES + 1), "image/png", "image_too_large"),
        (_PNG, "image/gif", "unsupported_image"),
    ):
        try:
            analyze_image(payload, mime, provider)
        except VisionAnalysisError as error:
            assert error.code == code, mime
        else:
            raise AssertionError(f"{code} was not refused")
    # Nothing reached the provider — refusing early costs nothing.
    assert provider.seen == {}
    print("test_oversized_and_unsupported_images_are_refused_locally PASSED")


def test_provider_failures_become_platform_codes() -> None:
    try:
        analyze_image(_PNG, "image/png", _StubProvider(error="rate_limited"))
    except VisionAnalysisError as error:
        assert error.code == "rate_limited"
    else:
        raise AssertionError("a provider failure did not surface")
    print("test_provider_failures_become_platform_codes PASSED")


def test_findings_are_tidied() -> None:
    messy = VisionFinding(
        language="  ru  ",
        detected_text="  text  ",
        urls=["http://a.xyz", "", "http://a.xyz", " http://b.xyz "],
        brands=["", "Kaspi"],
        confidence=140,
    )
    tidied = analyze_image(_PNG, "image/png", _StubProvider(messy))
    assert tidied.urls == ["http://a.xyz", "http://b.xyz"]  # deduped, trimmed
    assert tidied.brands == ["Kaspi"]  # blanks dropped
    assert tidied.confidence == 100  # clamped
    print("test_findings_are_tidied PASSED")


# --- The boundary: facts in, engine verdict out ---


def test_extracted_text_feeds_the_existing_detectors() -> None:
    """A screenshot of a scam must hit the same measured pipeline."""
    text = to_analysis_text(_SAMPLE)
    scanned = scan_message(text)
    # The one-time-code direction model and URL heuristics both fire on
    # text that came out of an image, with no second implementation.
    assert scanned.otp_signal == "disclosure"
    assert "otp_disclosure" in scanned.strong_signals
    assert any(
        "brand_lookalike" in finding.reasons for finding in scanned.suspicious_urls
    )
    print("test_extracted_text_feeds_the_existing_detectors PASSED")


def test_the_report_never_carries_the_image() -> None:
    """Raw bytes must not reach anything storable."""
    report = from_image_analysis(_scam_report(), _SAMPLE, "screenshot.png")
    serialized = report.model_dump_json()
    assert "PNG" not in serialized
    assert "base64" not in serialized
    assert "pretend-image-bytes" not in serialized
    assert report.subject_preview == "screenshot.png"
    assert report.subject_type == "image"
    print("test_the_report_never_carries_the_image PASSED")


def test_vision_observations_appear_as_their_own_evidence() -> None:
    report = from_image_analysis(_scam_report(), _SAMPLE, "shot.png")
    codes = {item.code for item in report.evidence}
    assert "vision_indicator" in codes
    assert "vision_brand" in codes
    # And the engine's own findings are still there.
    assert "otp_disclosure" in codes
    print("test_vision_observations_appear_as_their_own_evidence PASSED")


# --- Confidence: agreement and disagreement ---


def test_agreement_between_layers_raises_confidence() -> None:
    heuristics = scan_message(to_analysis_text(_SAMPLE))
    without = estimate(80, "danger", heuristics, 400)
    with_vision = estimate(
        80, "danger", heuristics, 400, vision_flagged=True, vision_legibility=88
    )
    assert with_vision.value > without.value
    assert "confidence.vision_agreement" in with_vision.reason_keys
    print("test_agreement_between_layers_raises_confidence PASSED")


def test_disagreement_lowers_confidence() -> None:
    heuristics = scan_message(to_analysis_text(_SAMPLE))
    disagreeing = estimate(
        80, "danger", heuristics, 400, vision_flagged=False, vision_legibility=90
    )
    agreeing = estimate(
        80, "danger", heuristics, 400, vision_flagged=True, vision_legibility=90
    )
    assert disagreeing.value < agreeing.value
    assert "confidence.vision_conflict" in disagreeing.reason_keys
    print("test_disagreement_lowers_confidence PASSED")


def test_an_unreadable_image_does_not_vote() -> None:
    # A provider that could not read the screenshot is describing the
    # screenshot's legibility, not its danger.
    heuristics = scan_message(to_analysis_text(_SAMPLE))
    baseline = estimate(80, "danger", heuristics, 400)
    blurred = estimate(
        80, "danger", heuristics, 400, vision_flagged=False, vision_legibility=20
    )
    assert blurred.value == baseline.value
    assert "confidence.vision_unreadable" in blurred.reason_keys
    print("test_an_unreadable_image_does_not_vote PASSED")


def test_text_analysis_is_unchanged_when_no_vision_is_involved() -> None:
    """Backward compatibility: the default path must not move."""
    heuristics = scan_message("URGENT! reply with the code we sent")
    before = estimate(85, "danger", heuristics, 300)
    after = estimate(85, "danger", heuristics, 300, vision_flagged=None)
    assert before.value == after.value
    assert before.reason_keys == after.reason_keys
    print("test_text_analysis_is_unchanged_when_no_vision_is_involved PASSED")


# --- Routing, and life without a provider ---


def test_images_are_declined_when_no_provider_is_configured() -> None:
    """The platform must keep working with no vision provider at all."""
    import os

    saved = {
        name: os.environ.pop(name, None)
        for name in ("KIMI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")
    }
    try:
        subject = TrustSubject(content=_PNG, mime_type="image/png")
        assert ImageAnalyzer().can_handle(subject) is False
        # …and the engine says so rather than failing.
        engine = TrustEngine()
        assert engine.detect(subject) is None
    finally:
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value
    print("test_images_are_declined_when_no_provider_is_configured PASSED")


def test_text_routing_is_untouched_by_the_image_analyzer() -> None:
    engine = TrustEngine()
    for content, kind in (
        ("user@example.com", "email"),
        ("https://kaspi.kz", "url"),
        ("URGENT! send the code", "message"),
    ):
        detected = engine.detect(TrustSubject(content=content))
        assert detected is not None and detected.kind == kind, content
    print("test_text_routing_is_untouched_by_the_image_analyzer PASSED")


if __name__ == "__main__":
    test_oversized_and_unsupported_images_are_refused_locally()
    test_provider_failures_become_platform_codes()
    test_findings_are_tidied()
    test_extracted_text_feeds_the_existing_detectors()
    test_the_report_never_carries_the_image()
    test_vision_observations_appear_as_their_own_evidence()
    test_agreement_between_layers_raises_confidence()
    test_disagreement_lowers_confidence()
    test_an_unreadable_image_does_not_vote()
    test_text_analysis_is_unchanged_when_no_vision_is_involved()
    test_images_are_declined_when_no_provider_is_configured()
    test_text_routing_is_untouched_by_the_image_analyzer()
    print("ALL VISION ANALYSIS TESTS PASSED")
