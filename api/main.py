"""Tumar.AI REST API — the Trust Engine, over HTTP.

The engine, the analyzers, and the report schema are used unchanged.
This module adds only what a network boundary needs: authentication,
rate limiting, input limits, error translation, and logging. No
detection logic lives here, and none should — a second copy of it
would drift from the one the evaluation harness measures.

Run locally:

    uvicorn api.main:app --reload

Interactive documentation is served at /docs.
"""

import logging
import os
import sys
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Make the project root importable when uvicorn is started from it.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api import settings as settings_module  # noqa: E402
from api.schemas import (  # noqa: E402
    AnalyzeRequest,
    AnalyzersResponse,
    AnalyzeResponse,
    AnalyzerInfo,
    ErrorBody,
    ErrorResponse,
    HealthResponse,
)
from api.security import RateLimiter, key_fingerprint, verify_key  # noqa: E402
from services.common import ServiceError  # noqa: E402
from services.trust_engine import (  # noqa: E402
    AnalysisContext,
    TrustEngine,
    TrustSubject,
    default_analyzers,
)

VERSION = "0.1.0"

# Short error codes from the services layer, mapped to the status that
# tells a client what to do about it. Anything unmapped becomes a 502:
# an unrecognized failure is an upstream problem until proven
# otherwise, and guessing 500 would blame the caller's request.
_STATUS_BY_CODE = {
    # The caller can fix these.
    "unsupported_input": 400,
    "invalid_url": 400,
    "invalid_email": 400,
    "empty_password": 400,
    # We can fix these; the caller cannot, and must not see why.
    "missing_key": 503,
    "credentials": 503,
    "prompt_missing": 503,
    "model_unavailable": 503,
    "service_down": 503,
    "unavailable": 503,
    # Upstream is slow or refusing.
    "timeout": 504,
    "unreachable": 504,
    "rate_limited": 429,
}

_GENERIC_MESSAGES = {
    400: "The request could not be analyzed as submitted.",
    429: "Too many requests. Please retry later.",
    503: "The analysis service is temporarily unavailable.",
    504: "The analysis service did not respond in time.",
    502: "The analysis service returned an unexpected result.",
}

logger = logging.getLogger("tumar.api")

settings = settings_module.load()
limiter = RateLimiter(settings.rate_limit, settings.rate_window_seconds)

# Passwords are not analyzable over HTTP — see api/schemas.py. Building
# the engine without that analyzer makes it structurally impossible
# rather than merely undocumented.
_API_ANALYZERS = tuple(
    analyzer for analyzer in default_analyzers() if analyzer.kind != "password"
)
engine = TrustEngine(_API_ANALYZERS)

app = FastAPI(
    title="Tumar.AI Trust API",
    version=VERSION,
    description=(
        "Analyze a message, link, or email address and receive a Trust "
        "Report: a verdict, a trust score, the evidence behind it, and "
        "how confident the platform is in its own answer."
    ),
)

if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_methods=["POST", "GET"],
        allow_headers=["Authorization", "Content-Type"],
    )


def _error(request_id: str, status: int, code: str) -> JSONResponse:
    """Build an error response that reveals nothing internal."""
    body = ErrorResponse(
        request_id=request_id,
        error=ErrorBody(
            code=code,
            message=_GENERIC_MESSAGES.get(status, _GENERIC_MESSAGES[502]),
        ),
    )
    return JSONResponse(status_code=status, content=body.model_dump())


@app.middleware("http")
async def observability(request: Request, call_next):
    """Tag every request and record how it went.

    This is the platform's first observability: without it there is no
    way to know the error rate, the latency, or whether the AI provider
    is failing. What is logged is deliberately narrow — never the
    content, never a key, never the report preview, which for a message
    contains the message itself.
    """
    request_id = uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        # Log the traceback for us; return nothing revealing to them.
        logger.exception(
            "request_failed request_id=%s path=%s", request_id, request.url.path
        )
        return _error(request_id, 500, "internal_error")

    logger.info(
        "request request_id=%s path=%s status=%s duration_ms=%d",
        request_id,
        request.url.path,
        response.status_code,
        int((time.monotonic() - started) * 1000),
    )
    response.headers["X-Request-ID"] = request_id
    return response


async def authenticate(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Authenticate and rate-limit one caller.

    Returns the caller's log fingerprint. Raises nothing — failures are
    surfaced by the endpoint, so every rejection carries a request id.
    """
    provided = ""
    if authorization and authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()
    elif x_api_key:
        provided = x_api_key.strip()
    request.state.api_key = provided
    return key_fingerprint(provided)


@app.get("/v1/health", response_model=HealthResponse, tags=["service"])
async def health() -> HealthResponse:
    """Liveness check. Unauthenticated on purpose, and says nothing secret."""
    return HealthResponse(
        status="ok" if settings.configured else "unconfigured", version=VERSION
    )


@app.get("/v1/analyzers", response_model=AnalyzersResponse, tags=["service"])
async def analyzers() -> AnalyzersResponse:
    """What this deployment can analyze.

    Read from the live registry rather than a hand-written list, so a
    new analyzer appears here the moment it is registered.
    """
    return AnalyzersResponse(
        analyzers=[
            AnalyzerInfo(
                kind=analyzer.kind,
                auto_detected=analyzer.can_handle(
                    TrustSubject(content="probe@example.com")
                )
                or analyzer.kind in ("url", "message"),
            )
            for analyzer in _API_ANALYZERS
        ]
    )


@app.post(
    "/v1/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    tags=["analysis"],
)
async def analyze(
    payload: AnalyzeRequest,
    request: Request,
    caller: str = Depends(authenticate),
):
    """Analyze one subject and return its Trust Report."""
    request_id = request.state.request_id

    if not settings.configured:
        # Fail closed rather than serving an open, unmetered endpoint.
        return _error(request_id, 503, "not_configured")

    if not verify_key(request.state.api_key, settings.api_keys):
        logger.warning("auth_failed request_id=%s caller=%s", request_id, caller)
        return _error(request_id, 401, "unauthorized")

    allowed, reset_in = limiter.check(caller, time.time())
    if not allowed:
        response = _error(request_id, 429, "rate_limited")
        response.headers["Retry-After"] = str(reset_in)
        return response

    if len(payload.content) > settings.max_content_length:
        # Checked before any AI call: an oversized body should cost us
        # nothing.
        return _error(request_id, 413, "content_too_large")

    subject = TrustSubject(
        content=payload.content,
        declared_kind=payload.kind or "",
        language=payload.language,
    )
    analyzer = engine.detect(subject)
    if analyzer is None:
        return _error(request_id, 400, "unsupported_input")

    try:
        report = engine.analyze(
            subject, AnalysisContext(api_key=settings.gemini_api_key)
        )
    except ServiceError as error:
        status = _STATUS_BY_CODE.get(error.code, 502)
        logger.warning(
            "analysis_failed request_id=%s caller=%s kind=%s code=%s",
            request_id,
            caller,
            analyzer.kind,
            error.code,
        )
        return _error(request_id, status, error.code)

    logger.info(
        "analysis request_id=%s caller=%s kind=%s verdict=%s confidence=%d",
        request_id,
        caller,
        analyzer.kind,
        report.verdict,
        report.confidence,
    )
    return AnalyzeResponse(
        request_id=request_id, detected_kind=analyzer.kind, report=report
    )


def _configure_logging() -> None:
    """Send structured lines to stdout, which is where platforms read."""
    level = os.environ.get("TUMAR_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


_configure_logging()
