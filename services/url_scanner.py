"""URL trust scanner — the first native TrustReport module.

Takes one URL, runs the same deterministic URL checks the scam
analyzer uses on embedded links (services/heuristics.url_reasons),
asks Gemini for a structured judgement of the address, and returns
the platform's unified TrustReport directly — no adapter needed.

The page behind the URL is never fetched: fetching untrusted URLs
from our server would let attackers use Tumar.AI as a proxy and would
slow every check. The verdict is about the address itself, and the
prompt instructs the AI to say so honestly.

This module knows nothing about Streamlit — it can be reused unchanged
by the future Trust Engine, API server, bot, or browser extension.
"""

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from services.common import ServiceError
from services.gemini_client import GeminiError, generate_structured
from services.heuristics import url_reasons
from services.trust_report import Evidence, TrustReport, preview_text

PROMPT_FILE = Path(__file__).resolve().parent.parent / "prompts" / "url_scanner_v1.md"

# Unicode letters and digits, "-" and "."; must start and end with a
# letter or digit. (IPv6 literals never reach this check: the "." rule
# above already rejects them — a known limitation.)
_HOSTNAME = re.compile(r"[^\W_](?:[\w.-]*[^\W_])?", re.IGNORECASE)


class UrlAnalysis(BaseModel):
    """Validated AI judgement of one URL.

    Speaks the platform's verdict language (safe/caution/danger)
    directly — native modules should not need translation layers.
    """

    verdict: Literal["safe", "caution", "danger"]
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    red_flags: list[str]
    explanation: str
    recommended_actions: list[str]


class UrlScanError(ServiceError):
    """Scan failed. `code` selects a localized message in the UI."""


@lru_cache(maxsize=1)
def _load_system_prompt() -> str:
    """Read the system prompt from disk (cached after the first read)."""
    try:
        return PROMPT_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise UrlScanError("prompt_missing") from exc


def normalize_url(raw: str) -> str:
    """Clean up user input and reject anything that is not one URL.

    A missing scheme defaults to https:// — the charitable assumption.
    Users often type bare domains ("kaspi.kz"); defaulting to http://
    would make the no_https heuristic fire on every such input, and a
    false alarm teaches users to ignore real ones. An explicit http://
    pasted by the user still gets flagged.

    Raises:
        UrlScanError: code "invalid_url" when the input is unusable.
    """
    candidate = raw.strip()
    if not candidate or any(ch.isspace() for ch in candidate):
        raise UrlScanError("invalid_url")
    if "://" not in candidate:
        candidate = "https://" + candidate
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
    except ValueError:  # e.g. "http://[::1" — an unbalanced IPv6 bracket
        raise UrlScanError("invalid_url") from None
    if parsed.scheme not in ("http", "https") or "." not in host:
        raise UrlScanError("invalid_url")
    # A hostname is letters, digits, hyphens and dots. Letters may be
    # non-Latin on purpose — a mixed-script look-alike such as
    # "kаspi.kz" (Cyrillic а) must still reach the homoglyph check —
    # but markup and punctuation never form a host. Without this,
    # "<script>alert(document.cookie)</script>" parsed as a URL.
    if not _HOSTNAME.fullmatch(host):
        raise UrlScanError("invalid_url")
    return candidate


def scan_url(url: str, api_key: str, language: str = "en") -> TrustReport:
    """Scan one URL and return a validated TrustReport.

    Args:
        url: The link the user wants checked (scheme optional).
        api_key: Gemini API key, provided by the caller.
        language: Two-letter code the AI should answer in — a URL has
            no language of its own, unlike a scam message.

    Raises:
        UrlScanError: With a short error code on any failure.
    """
    normalized = normalize_url(url)
    reasons = url_reasons(normalized)

    try:
        analysis = generate_structured(
            api_key=api_key,
            system_prompt=_load_system_prompt(),
            contents=_build_contents(normalized, reasons, language),
            schema=UrlAnalysis,
        )
    except GeminiError as exc:
        raise UrlScanError(exc.code) from exc

    return build_report(normalized, reasons, analysis)


def build_report(
    url: str, reasons: list[str], analysis: UrlAnalysis
) -> TrustReport:
    """Assemble the TrustReport from both evidence layers.

    Public (not underscored) so offline tests can exercise the whole
    report assembly without a network call.
    """
    # "url_" prefix matches the scam analyzer's vocabulary for link
    # findings, so one shared renderer presents both identically.
    evidence = [
        Evidence(kind="heuristic", code=f"url_{code}", detail=url)
        for code in reasons
    ]
    evidence.extend(
        Evidence(kind="ai", code="red_flag", detail=flag)
        for flag in analysis.red_flags
    )
    return TrustReport(
        source="url_scanner",
        subject_type="url",
        subject_preview=preview_text(url),
        verdict=analysis.verdict,
        trust_score=100 - analysis.risk_score,
        confidence=analysis.confidence,
        evidence=evidence,
        explanation=analysis.explanation,
        recommended_actions=list(analysis.recommended_actions),
    )


def _build_contents(url: str, reasons: list[str], language: str) -> str:
    """Combine the untrusted URL with the scanner's findings."""
    findings = "\n".join(f"- {code}" for code in reasons)
    summary = findings or "- The scanner detected nothing."
    return (
        f"LANGUAGE: {language}\n\n"
        "URL TO ANALYZE (untrusted data between the markers):\n"
        f"<<<URL\n{url}\nURL>>>\n\n"
        f"AUTOMATED SCANNER FINDINGS:\n{summary}"
    )
