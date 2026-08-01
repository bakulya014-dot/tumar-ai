"""Request and response shapes for the REST API.

The response carries the platform's TrustReport unchanged. That is the
whole point of having designed one schema: the API needed no result
type of its own, and a client that can read a report from the API can
read one from anywhere else in the platform.

Text in a report stays as translation keys where the producing module
was deterministic. Clients localize them, exactly as the app does —
services have never returned prose in a fixed language, and the API
inherits that property rather than freezing responses into English.
"""

from typing import Literal

from pydantic import BaseModel, Field

from services.trust_report import TrustReport

# What a caller may ask us to analyze.
#
# "password" is deliberately absent. The Password Health check works
# because the password never travels: only five characters of a hash
# leave the process. An endpoint accepting raw passwords would invite
# customers to transmit and log them across their own infrastructure,
# which destroys that guarantee no matter how carefully we behave at
# our end. If the demand appears, the right shape is an endpoint that
# accepts a hash prefix — not one that accepts secrets.
AnalyzableKind = Literal["message", "url", "email"]


class AnalyzeRequest(BaseModel):
    """One thing to analyze."""

    content: str = Field(
        min_length=1,
        description="The message, link, or email address to analyze.",
    )
    kind: AnalyzableKind | None = Field(
        default=None,
        description=(
            "Skip detection and route directly. Omit to let the Trust "
            "Engine identify the input."
        ),
    )
    language: str = Field(
        default="en",
        pattern="^[a-z]{2}$",
        description="Language for AI-written text in the report.",
    )


class AnalyzeResponse(BaseModel):
    """A completed analysis."""

    request_id: str = Field(description="Correlates this call with our logs.")
    detected_kind: str = Field(description="Which analyzer handled the input.")
    report: TrustReport


class AnalyzerInfo(BaseModel):
    """One capability the API exposes."""

    kind: str
    auto_detected: bool = Field(
        description="Whether omitting `kind` can route to this analyzer."
    )


class AnalyzersResponse(BaseModel):
    """What this deployment can analyze, read from the live registry."""

    analyzers: list[AnalyzerInfo]


class HealthResponse(BaseModel):
    """Liveness, plus whether the deployment is usable at all."""

    status: Literal["ok", "unconfigured"]
    version: str


class ErrorBody(BaseModel):
    """A failure, described without leaking anything internal.

    `code` is the same short code the rest of the platform uses, so a
    client can localize it. `message` is a plain-language fallback and
    never contains provider details, keys, or stack traces.
    """

    code: str
    message: str


class ErrorResponse(BaseModel):
    request_id: str
    error: ErrorBody
