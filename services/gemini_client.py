"""Shared Google Gemini client for every AI-powered module.

One place owns the messy realities of calling a hosted AI service:
which models to try and in which order, what counts as retriable, and
how provider errors map to the short codes the UI localizes. Thanks to
this module, an AI feature is ~30 lines: build the input text, declare
a Pydantic schema for the answer, call generate_structured().

Extracted from scam_analysis.py the moment a second AI module (the
URL scanner) appeared — shared plumbing belongs to the platform, not
to whichever module happened to be written first.
"""

from google import genai
from google.genai import errors as genai_errors
from pydantic import BaseModel, ValidationError

from services import telemetry
from services.common import ServiceError

# Models to try, in order. Availability, quotas, and retirement are
# tracked per model on Google's side, so if the primary model is
# overloaded or unavailable for this account we fall back to the next.
MODEL_CANDIDATES: tuple[str, ...] = (
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
)

# Low temperature = focused, consistent answers (0 = deterministic,
# 2 = very creative). A security verdict should not be creative.
TEMPERATURE = 0.2

# Give up on requests that take longer than this (milliseconds).
REQUEST_TIMEOUT_MS = 30_000


class GeminiError(ServiceError):
    """AI call failed. `code` selects a localized message in the UI."""


def generate_structured[ModelT: BaseModel](
    api_key: str,
    system_prompt: str,
    contents: str,
    schema: type[ModelT],
) -> ModelT:
    """Call Gemini and return its answer validated against `schema`.

    Args:
        api_key: Gemini API key, provided by the caller so this module
            stays free of any secret-storage details.
        system_prompt: The module's system instruction text.
        contents: The user-turn input (untrusted data + findings).
        schema: Pydantic model the answer must conform to; anything
            malformed is rejected before it can reach the UI.

    Raises:
        GeminiError: With a short error code on any failure.
    """
    if not api_key:
        raise GeminiError("missing_key")

    client = genai.Client(
        api_key=api_key,
        http_options=genai.types.HttpOptions(timeout=REQUEST_TIMEOUT_MS),
    )

    response = None
    last_error: genai_errors.APIError | None = None
    for attempt, model in enumerate(MODEL_CANDIDATES, start=1):
        timer = telemetry.Timer()
        try:
            response = client.models.generate_content(
                model=model,
                contents=contents,
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    response_schema=schema,
                    temperature=TEMPERATURE,
                ),
            )
            _record_call(model, attempt, timer, "ok", response=response)
            break
        except genai_errors.APIError as exc:
            code = _api_error_code(exc)
            _record_call(model, attempt, timer, "error", code, getattr(exc, "code", None))
            if _is_retriable(exc):
                last_error = exc
                continue  # A different model may still succeed.
            raise GeminiError(code) from exc
        except Exception as exc:  # Network failures, timeouts, DNS errors…
            _record_call(model, attempt, timer, "error", "unreachable")
            raise GeminiError("unreachable") from exc

    if response is None:
        code = _api_error_code(last_error) if last_error else "unavailable"
        raise GeminiError(code) from last_error

    # The SDK parses the JSON into our model when it can; fall back to
    # validating the raw text ourselves, and reject anything malformed.
    parsed = response.parsed
    if isinstance(parsed, schema):
        return parsed
    try:
        return schema.model_validate_json(response.text or "")
    except ValidationError as exc:
        raise GeminiError("unexpected_answer") from exc


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


def _record_call(
    model: str,
    attempt: int,
    timer: telemetry.Timer,
    outcome: str,
    error_code: str | None = None,
    http_status: int | None = None,
    response: object = None,
) -> None:
    """One telemetry event per model attempt: timing, tokens, cost.

    Only counts and codes are logged; prompts and answers never are.
    """
    usage = getattr(response, "usage_metadata", None)
    input_tokens = _int_or_none(getattr(usage, "prompt_token_count", None))
    output_tokens = _int_or_none(getattr(usage, "candidates_token_count", None))
    telemetry.emit(
        "provider_call",
        provider="gemini",
        model=model,
        attempt=attempt,
        outcome=outcome,
        error_code=error_code,
        http_status=http_status if isinstance(http_status, int) else None,
        duration_ms=timer.ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=telemetry.approximate_cost(model, input_tokens, output_tokens),
    )


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
