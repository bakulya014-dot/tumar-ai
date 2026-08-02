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
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Make the project root importable when uvicorn is started from it.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api import corpus_store, keystore  # noqa: E402
from api import settings as settings_module  # noqa: E402
from api.schemas import (  # noqa: E402
    AnalyzeRequest,
    AnalyzersResponse,
    AnalyzeResponse,
    AnalyzerInfo,
    ContributionItem,
    ContributionRequest,
    ContributionsResponse,
    ContributionStoredResponse,
    ErrorBody,
    ErrorResponse,
    HealthResponse,
    WithdrawalResponse,
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
    "quota_exceeded": 429,
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
    401: "A valid API key is required.",
    413: "The submitted content is too large.",
    429: "Too many requests, or the monthly quota is spent.",
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


@dataclass(frozen=True)
class Caller:
    """Who is making this request, as far as we can establish."""

    fingerprint: str  # safe to log; never the key itself
    key: keystore.ApiKey | None  # a real issued key, when there is one
    authenticated: bool


def authenticate(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Caller:
    """Identify the caller from an issued key, or a bootstrap key.

    Issued keys are checked first: they are the ones that carry an
    owner, a quota and a metering trail. The environment keys remain as
    a development convenience and are recorded as anonymous traffic.

    Nothing is raised here — failures are returned by the endpoint, so
    every rejection carries a request id a customer can quote.
    """
    provided = ""
    if authorization and authorization.lower().startswith("bearer "):
        provided = authorization[7:].strip()
    elif x_api_key:
        provided = x_api_key.strip()

    fingerprint = key_fingerprint(provided)
    if not provided:
        return Caller(fingerprint, None, authenticated=False)

    record = keystore.verify(provided, settings.database_path)
    if record is not None:
        return Caller(fingerprint, record, authenticated=True)

    # Bootstrap keys from the environment, for development.
    if verify_key(provided, settings.api_keys):
        return Caller(fingerprint, None, authenticated=True)

    return Caller(fingerprint, None, authenticated=False)


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
def analyze(
    payload: AnalyzeRequest,
    request: Request,
    caller: Caller = Depends(authenticate),
):
    """Analyze one subject and return its Trust Report.

    Defined with `def`, not `async def`, on purpose. The work inside is
    blocking — an HTTP call to the AI provider and a local database
    write — and FastAPI runs a synchronous endpoint in a worker thread.
    Declaring it async would have run that blocking work on the event
    loop, where one slow provider response stalls every other request
    on the process.
    """
    request_id = request.state.request_id
    started = time.monotonic()

    def finish(status: int, code: str, kind: str = "", verdict: str = ""):
        """Record the call, then answer. Metering happens either way:
        a customer's failed requests are exactly what support needs."""
        keystore.record_usage(
            key_id=caller.key.id if caller.key else None,
            endpoint="/v1/analyze",
            status=status,
            kind=kind,
            verdict=verdict,
            duration_ms=int((time.monotonic() - started) * 1000),
            path=settings.database_path,
        )
        return _error(request_id, status, code)

    if not settings.configured:
        # Fail closed rather than serving an endpoint that cannot work.
        return finish(503, "not_configured")

    if not caller.authenticated:
        logger.warning(
            "auth_failed request_id=%s caller=%s", request_id, caller.fingerprint
        )
        return finish(401, "unauthorized")

    allowed, reset_in = limiter.check(caller.fingerprint, time.time())
    if not allowed:
        response = finish(429, "rate_limited")
        response.headers["Retry-After"] = str(reset_in)
        return response

    if caller.key and keystore.over_quota(caller.key, path=settings.database_path):
        logger.warning(
            "quota_exceeded request_id=%s key_id=%s", request_id, caller.key.id
        )
        return finish(429, "quota_exceeded")

    if len(payload.content) > settings.max_content_length:
        # Checked before any AI call: an oversized body costs us nothing.
        return finish(413, "content_too_large")

    subject = TrustSubject(
        content=payload.content,
        declared_kind=payload.kind or "",
        language=payload.language,
    )
    analyzer = engine.detect(subject)
    if analyzer is None:
        return finish(400, "unsupported_input")

    try:
        report = engine.analyze(
            subject, AnalysisContext(api_key=settings.gemini_api_key)
        )
    except ServiceError as error:
        status = _STATUS_BY_CODE.get(error.code, 502)
        logger.warning(
            "analysis_failed request_id=%s caller=%s kind=%s code=%s",
            request_id,
            caller.fingerprint,
            analyzer.kind,
            error.code,
        )
        return finish(status, error.code, analyzer.kind)

    # Opt-in, per request, and only ever after the analysis succeeded.
    contributed = False
    if payload.contribute:
        contributed = corpus_store.contribute(
            key_id=caller.key.id if caller.key else None,
            content=payload.content,
            kind=analyzer.kind,
            language=payload.language,
            verdict=report.verdict,
            confidence=report.confidence,
            path=settings.database_path,
        )

    keystore.record_usage(
        key_id=caller.key.id if caller.key else None,
        endpoint="/v1/analyze",
        status=200,
        kind=analyzer.kind,
        verdict=report.verdict,
        duration_ms=int((time.monotonic() - started) * 1000),
        path=settings.database_path,
    )
    logger.info(
        "analysis request_id=%s caller=%s kind=%s verdict=%s confidence=%d",
        request_id,
        caller.fingerprint,
        analyzer.kind,
        report.verdict,
        report.confidence,
    )
    return AnalyzeResponse(
        request_id=request_id,
        detected_kind=analyzer.kind,
        report=report,
        contributed=contributed,
    )


@app.post(
    "/v1/contributions",
    response_model=ContributionStoredResponse,
    responses={401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
    tags=["corpus"],
)
def store_contribution(
    payload: ContributionRequest,
    request: Request,
    caller: Caller = Depends(authenticate),
):
    """Store an already-analyzed sample.

    This is what lets a front end run on a host with no durable disk:
    the app keeps nothing locally and hands consented samples to the
    service that owns the database. It also keeps the app from paying
    for a second analysis just to record one it already has.
    """
    request_id = request.state.request_id
    if not caller.authenticated or caller.key is None:
        return _error(request_id, 401, "unauthorized")

    allowed, reset_in = limiter.check(caller.fingerprint, time.time())
    if not allowed:
        response = _error(request_id, 429, "rate_limited")
        response.headers["Retry-After"] = str(reset_in)
        return response

    stored = corpus_store.contribute(
        key_id=None if payload.session_id else caller.key.id,
        content=payload.content,
        kind=payload.kind,
        language=payload.language,
        verdict=payload.verdict,
        confidence=payload.confidence,
        session_id=payload.session_id,
        path=settings.database_path,
    )
    logger.info(
        "contribution request_id=%s key_id=%s stored=%s",
        request_id,
        caller.key.id,
        stored,
    )
    return ContributionStoredResponse(stored=stored)


@app.get(
    "/v1/contributions",
    response_model=ContributionsResponse,
    responses={401: {"model": ErrorResponse}},
    tags=["corpus"],
)
def list_contributions(request: Request, caller: Caller = Depends(authenticate)):
    """Show everything stored for this key, as it is stored.

    A customer should be able to read back exactly what we hold, in
    the redacted form we hold it, rather than take our word for it.
    """
    if not caller.authenticated or caller.key is None:
        return _error(request.state.request_id, 401, "unauthorized")

    stored = corpus_store.for_key(caller.key.id, settings.database_path)
    return ContributionsResponse(
        count=len(stored),
        consent_version=corpus_store.CONSENT_VERSION,
        contributions=[
            ContributionItem(
                id=item.id,
                created_at=item.created_at,
                consent_version=item.consent_version,
                kind=item.kind,
                language=item.language,
                redacted_content=item.redacted_content,
                verdict=item.verdict,
            )
            for item in stored
        ],
    )


@app.delete(
    "/v1/contributions",
    response_model=WithdrawalResponse,
    responses={401: {"model": ErrorResponse}},
    tags=["corpus"],
)
def withdraw_contributions(
    request: Request,
    caller: Caller = Depends(authenticate),
    session_id: str = "",
):
    """Delete contributed samples — this key's, or one app session's.

    Self-service and immediate: withdrawing consent should not require
    opening a support ticket. The rows are deleted rather than
    flagged — a promise to delete that leaves the data in place is not
    a promise.

    `session_id` lets a front end pass on a withdrawal from one of its
    users. Session ids are unguessable, so holding the app's key does
    not reveal whose samples to remove.
    """
    if not caller.authenticated or caller.key is None:
        return _error(request.state.request_id, 401, "unauthorized")

    if session_id:
        deleted = corpus_store.withdraw_session(
            session_id, settings.database_path
        )
    else:
        deleted = corpus_store.withdraw(caller.key.id, settings.database_path)
    logger.info(
        "contributions_withdrawn request_id=%s key_id=%s deleted=%d",
        request.state.request_id,
        caller.key.id,
        deleted,
    )
    return WithdrawalResponse(
        deleted=deleted,
        message=(
            "Deleted. Samples already exported into our reviewed corpus "
            "have left this store and are not covered by this deletion."
        ),
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
