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

from services.breach_checker import check_email, is_valid_email
from services.common import ServiceError
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
    return (EmailAnalyzer(), UrlAnalyzer(), MessageAnalyzer(), PasswordAnalyzer())


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
        analyzer = self.detect(subject)
        if analyzer is None:
            raise EngineError("unsupported_input")
        return analyzer.analyze(subject, context)
