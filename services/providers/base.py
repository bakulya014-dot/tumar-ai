"""The interface every AI provider implements.

Tumar.AI's verdicts are produced by the Trust Engine, never by a
model. A provider is an *instrument* the engine uses: it turns text or
an image into structured facts, and the engine decides what those
facts mean. Keeping that boundary is what makes providers swappable —
switching from one to another changes how evidence is gathered, never
how a verdict is reached.

Two capabilities, deliberately separate:

    generate_structured — text in, validated schema out
    analyze_image       — image in, validated schema out

A provider declares which it supports. Nothing in the platform assumes
a provider can do both, because most cannot, and a missing capability
must degrade to "we did not look at that" rather than an exception at
the point of use.
"""

from abc import ABC, abstractmethod

from pydantic import BaseModel

from services.common import ServiceError


class ProviderError(ServiceError):
    """A provider failed. `code` selects a localized message in the UI.

    Codes are the platform's existing ones — "timeout", "credentials",
    "rate_limited" — so a new provider needs no new error handling
    anywhere upstream.
    """


class ProviderUnsupported(ProviderError):
    """The provider cannot do what was asked of it."""

    def __init__(self, capability: str = "unsupported_capability"):
        super().__init__("unsupported_capability")
        self.capability = capability


class AIProvider(ABC):
    """One interchangeable source of structured analysis."""

    # Stable identifier used in configuration and logs.
    name: str = "provider"

    @abstractmethod
    def available(self) -> bool:
        """Whether this provider is configured enough to be called.

        Checked before use so an unconfigured provider is skipped
        quietly rather than failing a user's request. A platform that
        breaks when an optional provider is absent is not optional.
        """

    def supports_vision(self) -> bool:
        """Whether analyze_image() will work. False unless overridden."""
        return False

    @abstractmethod
    def generate_structured[ModelT: BaseModel](
        self, system_prompt: str, contents: str, schema: type[ModelT]
    ) -> ModelT:
        """Analyze text and return an answer validated against `schema`."""

    def analyze_image[ModelT: BaseModel](
        self,
        image_bytes: bytes,
        mime_type: str,
        system_prompt: str,
        schema: type[ModelT],
        instruction: str = "",
    ) -> ModelT:
        """Analyze an image and return an answer validated against `schema`."""
        raise ProviderUnsupported("vision")
