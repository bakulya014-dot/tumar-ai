"""Trust Engine — the platform's core orchestration layer.

Every consumer (Streamlit app, REST API, browser extension, bot,
mobile app, AI agent integrations) talks to Tumar.AI the same way:

    subject = TrustSubject(content="http://suspicious.link")
    report = TrustEngine().analyze(subject, AnalysisContext(api_key=key))

The engine detects what the subject is, routes it to the right
analyzer, and returns the unified TrustReport. It is open for
extension and closed for modification (the Open/Closed Principle):
adding a capability means writing a new Analyzer and registering it —
the engine's routing logic is never edited.

Design decisions:
- TrustSubject is an envelope, not a string: `content` may be text or
  bytes, with mime_type/filename metadata. Future analyzers for PDFs,
  screenshots, QR codes, or audio just claim the payloads they
  understand — no engine change.
- Detection order is an explicit contract: analyzers are registered
  most-specific first, and the first `can_handle` win takes the
  subject. "user@example.com" is a valid email AND parses as a URL
  AND is readable message text — order, not cleverness, resolves such
  ties (and a test pins it).
- `declared_kind` bypasses detection: consumers that already know
  what they hold ("this is an agent log") route directly, which is
  how ambiguous structured text reaches the right analyzer.
- AnalysisContext carries everything analyzers need beyond the
  subject (today: the API key). New needs become new optional fields
  here — analyzer signatures never change again.
"""

from abc import ABC, abstractmethod
from typing import Sequence

from pydantic import BaseModel

from services import telemetry
from services.breach_checker import check_email, is_valid_email
from services.common import ServiceError
from services.image_scanner import SUPPORTED_MIME_TYPES, scan_image, to_trust_report
from services.offline_report import (
    is_provider_failure,
    offline_message_report,
    offline_url_report,
)
from services.password_check import check_password
from services.scam_analysis import analyze_message
from services.trust_report import (
    TrustReport,
    from_breach_result,
    from_scam_report,
)
from services.url_scanner import UrlScanError, normalize_url, scan_url


class TrustSubject(BaseModel):
    """One thing to analyze, wrapped with the metadata routing needs."""

    content: str | bytes
    mime_type: str = "text/plain"
    declared_kind: str = ""  # consumer override; empty = auto-detect
    language: str = "en"
    filename: str = ""


class AnalysisContext(BaseModel):
    """Everything analyzers may need beyond the subject itself.

    Extend with new OPTIONAL fields (tenant id, cache policy, user
    plan…) — existing analyzers keep working untouched.
    """

    api_key: str = ""
    # Which optional vision provider to prefer. Empty means "whatever
    # is configured", and no provider at all is a normal state.
    vision_provider: str = ""
    # The user's privacy choice: may image bytes and extracted text be
    # sent to external AI providers? False keeps every analysis local
    # (OCR, QR, URL heuristics, the message scanner, risk scoring).
    allow_external_ai: bool = True
    # When the AI provider fails (unreachable, timeout, rate limit, no
    # valid key), answer message and link checks with a rules-only
    # report labelled "offline" instead of raising. Off by default so
    # API clients keep receiving the provider error they can act on;
    # the web app and the Telegram bot turn it on.
    offline_fallback: bool = False
    # Where the request came from (web, telegram, api), for telemetry
    # only. Never affects the analysis.
    channel: str = "unknown"


class EngineError(ServiceError):
    """Routing failed. `code` selects a localized message in the UI."""


class Analyzer(ABC):
    """The interface every Tumar.AI capability implements."""

    # Stable machine id ("email", "url", …) used by declared_kind
    # routing and by TrustReport.source conventions.
    kind: str

    @abstractmethod
    def can_handle(self, subject: TrustSubject) -> bool:
        """Cheap, offline check: does this subject look like mine?"""

    @abstractmethod
    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        """Run the full analysis. May raise a ServiceError subclass."""


class EmailAnalyzer(Analyzer):
    """Email addresses → breach lookup. Registered first: an email is
    the most specific text shape (it would also pass the URL check)."""

    kind = "email"

    def can_handle(self, subject: TrustSubject) -> bool:
        content = subject.content
        return isinstance(content, str) and is_valid_email(content.strip().lower())

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        assert isinstance(subject.content, str)
        return from_breach_result(check_email(subject.content))


class UrlAnalyzer(Analyzer):
    """Single-token URLs and bare domains → URL trust scan."""

    kind = "url"

    def can_handle(self, subject: TrustSubject) -> bool:
        content = subject.content
        if not isinstance(content, str):
            return False
        try:
            normalize_url(content)
        except UrlScanError:
            return False
        return True

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        assert isinstance(subject.content, str)
        return scan_url(
            subject.content, api_key=context.api_key, language=subject.language
        )


class MessageAnalyzer(Analyzer):
    """Any other text → scam message analysis. The fallback, so it is
    registered last and simply accepts all non-empty text."""

    kind = "message"

    def can_handle(self, subject: TrustSubject) -> bool:
        content = subject.content
        return isinstance(content, str) and bool(content.strip())

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        assert isinstance(subject.content, str)
        message = subject.content.strip()
        return from_scam_report(
            analyze_message(message, api_key=context.api_key), message
        )


class ImageAnalyzer(Analyzer):
    """Screenshots → Visual Threat Intelligence (services/image_scanner).

    The image is validated and re-encoded, read by OCR (Kazakh,
    Russian, English), searched for QR codes, and every link found is
    run through the platform's URL heuristics. The transcript then
    passes through the same measured message pipeline as pasted text
    — the same urgency patterns, the same one-time-code direction
    model, the same prompt when an AI provider is allowed. A vision
    model, when configured and permitted, adds what it *saw*; it never
    decides.

    No layer is required. Without Tesseract the OCR stage reports
    "unavailable"; without a provider the AI stages report "skipped";
    the verdict is still evidence-based, and the report says which
    layers ran. The analyzer therefore claims every supported image,
    and the only way to be refused is to upload something that is not
    one.
    """

    kind = "image"

    def can_handle(self, subject: TrustSubject) -> bool:
        return (
            isinstance(subject.content, bytes)
            and subject.mime_type in SUPPORTED_MIME_TYPES
        )

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        assert isinstance(subject.content, bytes)
        result = scan_image(
            subject.content,
            api_key=context.api_key,
            language=subject.language,
            allow_external=context.allow_external_ai,
            preferred_vision=context.vision_provider,
        )
        return to_trust_report(result, subject.filename)


class PasswordAnalyzer(Analyzer):
    """Passwords → breach lookup. Reachable ONLY via declared_kind.

    can_handle() always returns False, deliberately. A password is
    indistinguishable from ordinary text, so any detection rule would
    be a guess — and both possible mistakes are unacceptable:

    - Guessing "password" for a real message would refuse to analyze
      something the user needed checked.
    - Guessing "message" for a real password would send that password
      to a third-party AI provider, which this product promises never
      to do.

    So passwords are routed only when the caller states outright that
    it holds one, which the Password Health page does explicitly.
    """

    kind = "password"

    def can_handle(self, subject: TrustSubject) -> bool:
        return False

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        assert isinstance(subject.content, str)
        return check_password(subject.content)


def default_analyzers() -> tuple[Analyzer, ...]:
    """The platform registry, most-specific first.

    Adding a module to Tumar.AI = write an Analyzer, add one line
    here, in the right specificity slot. Nothing else changes.

    PasswordAnalyzer sits last because order never reaches it: it opts
    out of detection entirely and is addressed by name.
    """
    # ImageAnalyzer is placed before the text analyzers because it
    # claims by mime type, which no text subject carries — and after
    # nothing, because a screenshot is never also an email address.
    return (
        ImageAnalyzer(),
        EmailAnalyzer(),
        UrlAnalyzer(),
        MessageAnalyzer(),
        PasswordAnalyzer(),
    )


class TrustEngine:
    """Routes TrustSubjects to analyzers. Never grows module logic."""

    def __init__(self, analyzers: Sequence[Analyzer] | None = None):
        self._analyzers = (
            tuple(analyzers) if analyzers is not None else default_analyzers()
        )

    def detect(self, subject: TrustSubject) -> Analyzer | None:
        """Return the analyzer that would handle this subject, if any."""
        if subject.declared_kind:
            for analyzer in self._analyzers:
                if analyzer.kind == subject.declared_kind:
                    return analyzer
            return None
        for analyzer in self._analyzers:
            if analyzer.can_handle(subject):
                return analyzer
        return None

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        """Detect, route, and analyze one subject.

        Raises:
            EngineError: code "unsupported_input" when no analyzer
                claims the subject.
            ServiceError: whatever the chosen analyzer raises.
        """
        with telemetry.request_scope():
            timer = telemetry.Timer()
            analyzer = self.detect(subject)
            kind = analyzer.kind if analyzer else "unknown"

            def record(outcome: str, error_code: str | None = None, report: TrustReport | None = None) -> None:
                # Content-free by construction: kind, outcome, codes, timings.
                telemetry.emit(
                    "analysis",
                    channel=context.channel,
                    kind=kind,
                    outcome=outcome,
                    error_code=error_code,
                    mode=report.analysis_metadata.get("mode", "full") if report else None,
                    verdict=report.verdict if report else None,
                    risk_level=(report.risk_level or None) if report else None,
                    duration_ms=timer.ms,
                )

            if analyzer is None:
                record("error", "unsupported_input")
                raise EngineError("unsupported_input")
            try:
                report = analyzer.analyze(subject, context)
            except ServiceError as exc:
                fallback = _OFFLINE_BUILDERS.get(analyzer.kind)
                if (
                    context.offline_fallback
                    and fallback is not None
                    and isinstance(subject.content, str)
                    and is_provider_failure(exc.code)
                ):
                    report = fallback(subject.content, exc.code)
                    record("offline", exc.code, report)
                    return report
                record("error", exc.code)
                raise
            except Exception:
                record("error", "internal_error")
                raise
            record("ok", report=report)
            return report


# Analyzers whose AI layer has a rules-only stand-in. Email, image and
# password checks need no AI to reach a verdict, so they have none.
_OFFLINE_BUILDERS = {
    "message": offline_message_report,
    "url": offline_url_report,
}
