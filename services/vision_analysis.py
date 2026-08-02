"""Read a screenshot and return structured facts — never a verdict.

This service extracts what is *in* an image: the text, the links, the
brands being shown, whether a code is being asked for. It deliberately
stops there. The Trust Engine decides what those facts mean, exactly as
it does for a pasted message, and remains the only component that
produces a TrustReport.

That boundary is the whole design. A vision model asked "is this a
scam?" would be a second, unmeasured opinion competing with the engine
the evaluation harness actually scores. Asked "what does this image
say?", it becomes an input adapter: the same heuristics, the same
prompt, the same confidence model, now reachable from a screenshot.

`confidence` in the returned JSON is the model's confidence in its own
reading of the image — whether the text came out right, not whether
the content is dangerous.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field

from services.common import ServiceError
from services.providers import AIProvider, ProviderError

PROMPT_FILE = (
    Path(__file__).resolve().parent.parent / "prompts" / "vision_analyzer_v1.md"
)

# Images larger than this are refused before any upload. Screenshots
# are small; anything much bigger is a photograph or a mistake, and
# both cost money to send.
MAX_IMAGE_BYTES = 6 * 1024 * 1024

SUPPORTED_MIME_TYPES = frozenset(
    {"image/png", "image/jpeg", "image/webp"}
)


class VisionFinding(BaseModel):
    """Structured facts read out of one image.

    Field names are part of the provider contract: the prompt asks for
    exactly these, and any provider may fill them.
    """

    language: str = Field(default="", description="Language of the text shown.")
    detected_text: str = Field(default="", description="Text read from the image.")
    urls: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    otp_requests: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    risk_indicators: list[str] = Field(default_factory=list)
    summary: str = Field(default="")
    # Range is not enforced here on purpose. This is a third party's
    # answer, and rejecting an otherwise perfect reading of a
    # screenshot because the model wrote 105 would throw away the
    # useful part over a trivial one. It is clamped in _tidy(), and the
    # TrustReport it eventually feeds is strictly validated — liberal
    # in what we accept, strict in what we emit.
    confidence: int = Field(default=0)


class VisionAnalysisError(ServiceError):
    """Vision analysis failed. `code` selects a localized message."""


@lru_cache(maxsize=1)
def _load_system_prompt() -> str:
    try:
        return PROMPT_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise VisionAnalysisError("prompt_missing") from exc


def analyze_image(
    image_bytes: bytes,
    mime_type: str,
    provider: AIProvider,
    language: str = "en",
) -> VisionFinding:
    """Extract structured facts from one image.

    Raises:
        VisionAnalysisError: with a short error code on any failure.
    """
    if not image_bytes:
        raise VisionAnalysisError("empty_image")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise VisionAnalysisError("image_too_large")
    if mime_type not in SUPPORTED_MIME_TYPES:
        raise VisionAnalysisError("unsupported_image")
    if not provider.supports_vision() or not provider.available():
        raise VisionAnalysisError("vision_unavailable")

    try:
        finding = provider.analyze_image(
            image_bytes=image_bytes,
            mime_type=mime_type,
            system_prompt=_load_system_prompt(),
            schema=VisionFinding,
            instruction=f"Answer in JSON. Write `summary` in {language}.",
        )
    except ProviderError as exc:
        raise VisionAnalysisError(exc.code) from exc

    return _tidy(finding)


def _tidy(finding: VisionFinding) -> VisionFinding:
    """Normalize a model's answer into something predictable.

    Models pad lists with empty strings and repeat themselves. Cleaning
    here keeps every consumer — the engine, the corpus, the UI — from
    having to guess what a blank entry meant.
    """

    def clean(values: list[str]) -> list[str]:
        seen: list[str] = []
        for value in values:
            text = (value or "").strip()
            if text and text not in seen:
                seen.append(text)
        return seen

    return VisionFinding(
        language=finding.language.strip()[:8],
        detected_text=finding.detected_text.strip(),
        urls=clean(finding.urls),
        brands=clean(finding.brands),
        otp_requests=clean(finding.otp_requests),
        phone_numbers=clean(finding.phone_numbers),
        risk_indicators=clean(finding.risk_indicators),
        summary=finding.summary.strip(),
        confidence=max(0, min(100, finding.confidence)),
    )


def to_analysis_text(finding: VisionFinding) -> str:
    """Render the findings as text the Trust Engine can analyze.

    The engine's scanner and prompt were built for messages, and a
    screenshot of a message is still a message. Presenting the read-out
    this way means the whole measured pipeline — urgency patterns, the
    one-time-code direction model, URL heuristics, the scam prompt —
    applies to images with no second implementation to keep in step.
    """
    lines = [finding.detected_text] if finding.detected_text else []
    if finding.urls:
        lines.append("Links shown: " + ", ".join(finding.urls))
    if finding.brands:
        lines.append("Brands shown: " + ", ".join(finding.brands))
    if finding.otp_requests:
        lines.append("Code requests seen: " + "; ".join(finding.otp_requests))
    if finding.phone_numbers:
        lines.append("Phone numbers shown: " + ", ".join(finding.phone_numbers))
    if finding.risk_indicators:
        lines.append("Visual risk indicators: " + "; ".join(finding.risk_indicators))
    return "\n".join(lines).strip()
