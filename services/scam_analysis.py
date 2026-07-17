"""AI scam analysis service.

Sends a suspicious message to Google Gemini and returns a validated,
structured verdict. This module knows nothing about Streamlit — it can
be reused unchanged by a future API server, bot, or browser extension.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from google import genai
from google.genai import errors as genai_errors
from pydantic import BaseModel, Field, ValidationError

# Models to try, in order. Availability, quotas, and retirement are
# tracked per model on Google's side, so if the primary model is
# overloaded or unavailable for this account we fall back to the next.
MODEL_CANDIDATES: tuple[str, ...] = (
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
)

# System prompt lives in a versioned file, not in code, so we can
# iterate on prompt wording without touching the service logic.
PROMPT_FILE = Path(__file__).resolve().parent.parent / "prompts" / "scam_analyzer_v1.md"

# Low temperature = focused, consistent answers (0 = deterministic,
# 2 = very creative). A security verdict should not be creative.
TEMPERATURE = 0.2

# Give up on requests that take longer than this (milliseconds).
REQUEST_TIMEOUT_MS = 30_000


class ScamAnalysis(BaseModel):
    """Validated result of one scam analysis.

    Pydantic enforces this schema on the AI's answer: a verdict outside
    the three allowed values or a risk score outside 0–100 is rejected
    before it can ever reach the UI.
    """

    verdict: Literal["Safe", "Suspicious", "Dangerous"]
    risk_score: int = Field(ge=0, le=100)
    red_flags: list[str]
    explanation: str
    recommended_actions: list[str]


class ScamAnalysisError(Exception):
    """Analysis failed. The exception message is safe to show to users."""


@lru_cache(maxsize=1)
def _load_system_prompt() -> str:
    """Read the system prompt from disk (cached after the first read)."""
    try:
        return PROMPT_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScamAnalysisError(
            "The analysis engine is misconfigured (prompt file missing). "
            "Please contact support."
        ) from exc


def analyze_message(message: str, api_key: str) -> ScamAnalysis:
    """Analyze a suspicious message and return a validated verdict.

    Args:
        message: The raw text the user wants checked.
        api_key: Gemini API key, provided by the caller so this module
            stays free of any secret-storage details.

    Raises:
        ScamAnalysisError: With a user-friendly message on any failure.
    """
    if not api_key:
        raise ScamAnalysisError("The AI engine is not configured (missing API key).")

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
                # The user's text goes in as plain content, clearly separated
                # from our instructions (which travel as system_instruction).
                contents=message,
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
            raise ScamAnalysisError(_friendly_api_error(exc)) from exc
        except Exception as exc:  # Network failures, timeouts, DNS errors…
            raise ScamAnalysisError(
                "Could not reach the AI service. Check your internet "
                "connection and try again."
            ) from exc

    if response is None:
        friendly = (
            _friendly_api_error(last_error)
            if last_error is not None
            else "The AI service is unavailable right now. Please try again."
        )
        raise ScamAnalysisError(friendly) from last_error

    # The SDK parses the JSON into our model when it can; fall back to
    # validating the raw text ourselves, and reject anything malformed.
    parsed = response.parsed
    if isinstance(parsed, ScamAnalysis):
        return parsed
    try:
        return ScamAnalysis.model_validate_json(response.text or "")
    except ValidationError as exc:
        raise ScamAnalysisError(
            "The AI returned an unexpected answer. Please try again."
        ) from exc


def _is_retriable(exc: genai_errors.APIError) -> bool:
    """True when a different model might succeed.

    404 = model retired/unavailable for this account, 429 = per-model
    rate limit, 5xx = overloaded or down. Credential errors are NOT
    retriable — no model will accept a bad key.
    """
    code = getattr(exc, "code", None)
    return code in (404, 429) or (code is not None and code >= 500)


def _friendly_api_error(exc: genai_errors.APIError) -> str:
    """Translate an API error into a message safe to show users.

    Never leak internal details (keys, URLs, stack traces) into the UI.
    """
    code = getattr(exc, "code", None)
    # Gemini reports a bad key as HTTP 400, so also match on the message.
    if code in (401, 403) or "api key" in str(exc).lower():
        return (
            "The AI service rejected our credentials. Please check the "
            "configured API key."
        )
    if code == 404:
        return (
            "The AI models are unavailable for this account right now. "
            "Please contact support."
        )
    if code == 429:
        return (
            "The AI service is busy right now (rate limit reached). "
            "Please wait a few seconds and try again."
        )
    if code is not None and code >= 500:
        return (
            "The AI service is temporarily unavailable. Please try again "
            "in a moment."
        )
    return "The AI service reported an error. Please try again."
