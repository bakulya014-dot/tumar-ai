"""AI scam analysis service.

Orchestrates one analysis: runs the deterministic scanner first
(services/heuristics.py), then sends the message plus the scanner
findings to Google Gemini, validates the AI's structured answer, and
returns both layers as one ScamReport.

This module knows nothing about Streamlit — it can be reused unchanged
by a future API server, bot, or browser extension. Errors carry short
codes (not sentences); the UI translates codes for the user.
"""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from google import genai
from google.genai import errors as genai_errors
from pydantic import BaseModel, Field, ValidationError

from services.common import ServiceError
from services.heuristics import HeuristicReport, scan_message

# Models to try, in order. Availability, quotas, and retirement are
# tracked per model on Google's side, so if the primary model is
# overloaded or unavailable for this account we fall back to the next.
MODEL_CANDIDATES: tuple[str, ...] = (
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
)

# System prompt lives in a versioned file, not in code, so we can
# iterate on prompt wording without touching the service logic.
PROMPT_FILE = Path(__file__).resolve().parent.parent / "prompts" / "scam_analyzer_v2.md"

# Low temperature = focused, consistent answers (0 = deterministic,
# 2 = very creative). A security verdict should not be creative.
TEMPERATURE = 0.2

# Give up on requests that take longer than this (milliseconds).
REQUEST_TIMEOUT_MS = 30_000


class ScamAnalysis(BaseModel):
    """Validated AI layer of the analysis.

    Pydantic enforces this schema on the AI's answer: values outside
    the allowed ranges are rejected before they can reach the UI.
    """

    verdict: Literal["Safe", "Suspicious", "Dangerous"]
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    credential_theft_risk: int = Field(ge=0, le=100)
    financial_scam_risk: int = Field(ge=0, le=100)
    red_flags: list[str]
    explanation: str
    recommended_actions: list[str]


@dataclass(frozen=True)
class ScamReport:
    """Complete result: deterministic scanner layer + AI layer."""

    ai: ScamAnalysis
    heuristics: HeuristicReport


class ScamAnalysisError(ServiceError):
    """Analysis failed. `code` selects a localized message in the UI."""


@lru_cache(maxsize=1)
def _load_system_prompt() -> str:
    """Read the system prompt from disk (cached after the first read)."""
    try:
        return PROMPT_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScamAnalysisError("prompt_missing") from exc


def analyze_message(message: str, api_key: str) -> ScamReport:
    """Analyze a suspicious message and return a validated report.

    Args:
        message: The raw text the user wants checked.
        api_key: Gemini API key, provided by the caller so this module
            stays free of any secret-storage details.

    Raises:
        ScamAnalysisError: With a short error code on any failure.
    """
    if not api_key:
        raise ScamAnalysisError("missing_key")

    heuristics = scan_message(message)

    client = genai.Client(
        api_key=api_key,
        http_options=genai.types.HttpOptions(timeout=REQUEST_TIMEOUT_MS),
    )

    response = None
    last_error: genai_errors.APIError | None = None
    for model in MODEL_CANDIDATES:
        try:
            response = client.models.generate_content(
                model=model,
                contents=_build_contents(message, heuristics),
                config=genai.types.GenerateContentConfig(
                    system_instruction=_load_system_prompt(),
                    response_mime_type="application/json",
                    response_schema=ScamAnalysis,
                    temperature=TEMPERATURE,
                ),
            )
            break
        except genai_errors.APIError as exc:
            if _is_retriable(exc):
                last_error = exc
                continue  # A different model may still succeed.
            raise ScamAnalysisError(_api_error_code(exc)) from exc
        except Exception as exc:  # Network failures, timeouts, DNS errors…
            raise ScamAnalysisError("unreachable") from exc

    if response is None:
        code = _api_error_code(last_error) if last_error else "unavailable"
        raise ScamAnalysisError(code) from last_error

    # The SDK parses the JSON into our model when it can; fall back to
    # validating the raw text ourselves, and reject anything malformed.
    parsed = response.parsed
    if isinstance(parsed, ScamAnalysis):
        return ScamReport(ai=parsed, heuristics=heuristics)
    try:
        analysis = ScamAnalysis.model_validate_json(response.text or "")
    except ValidationError as exc:
        raise ScamAnalysisError("unexpected_answer") from exc
    return ScamReport(ai=analysis, heuristics=heuristics)


def _build_contents(message: str, heuristics: HeuristicReport) -> str:
    """Combine the untrusted message with the scanner's findings.

    Both blocks originate from the user's message, so the prompt
    instructs the model to treat them strictly as evidence.
    """
    lines: list[str] = []
    if heuristics.urgency_matches:
        lines.append(f"- Urgency phrases matched: {', '.join(heuristics.urgency_matches)}")
    if heuristics.otp_matches:
        lines.append(f"- OTP/verification-code phrases matched: {', '.join(heuristics.otp_matches)}")
    if heuristics.credential_indicators:
        lines.append(f"- Credential-theft phrases matched: {', '.join(heuristics.credential_indicators)}")
    if heuristics.financial_indicators:
        lines.append(f"- Financial-bait phrases matched: {', '.join(heuristics.financial_indicators)}")
    if heuristics.manipulation_indicators:
        lines.append(f"- Manipulation phrases matched: {', '.join(heuristics.manipulation_indicators)}")
    for finding in heuristics.suspicious_urls:
        lines.append(f"- Suspicious URL {finding.url}: {', '.join(finding.reasons)}")
    summary = "\n".join(lines) or "- The scanner detected nothing."

    return (
        "MESSAGE TO ANALYZE (untrusted data between the markers):\n"
        f"<<<MESSAGE\n{message}\nMESSAGE>>>\n\n"
        f"AUTOMATED SCANNER FINDINGS:\n{summary}"
    )


def _is_retriable(exc: genai_errors.APIError) -> bool:
    """True when a different model might succeed.

    404 = model retired/unavailable for this account, 429 = per-model
    rate limit, 5xx = overloaded or down. Credential errors are NOT
    retriable — no model will accept a bad key.
    """
    code = getattr(exc, "code", None)
    return code in (404, 429) or (code is not None and code >= 500)


def _api_error_code(exc: genai_errors.APIError) -> str:
    """Map an API error to a short code the UI can localize.

    Never leak internal details (keys, URLs, stack traces) to users.
    """
    code = getattr(exc, "code", None)
    # Gemini reports a bad key as HTTP 400, so also match on the message.
    if code in (401, 403) or "api key" in str(exc).lower():
        return "credentials"
    if code == 404:
        return "model_unavailable"
    if code == 429:
        return "rate_limited"
    if code is not None and code >= 500:
        return "service_down"
    return "ai_error"
