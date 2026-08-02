"""Google Gemini, the platform's existing text provider.

A thin wrapper over services/gemini_client.py rather than a rewrite.
That module already carries hard-won behaviour — the model fallback
chain, which failures are worth retrying, how provider errors map to
the codes the UI localizes — and it is the path every measured
evaluation result was produced through. Reimplementing it to fit a new
interface would have thrown that away and invalidated the benchmarks.
"""

from pydantic import BaseModel

from services.gemini_client import GeminiError, generate_structured
from services.providers.base import AIProvider, ProviderError


class GeminiProvider(AIProvider):
    """Text analysis through the existing, measured Gemini client."""

    name = "gemini"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def available(self) -> bool:
        return bool(self.api_key)

    def supports_vision(self) -> bool:
        # Gemini models do accept images, but this provider does not
        # claim the capability until it is implemented and measured.
        # Declaring a capability we have not tested would route images
        # here and fail at the point of use.
        return False

    def generate_structured[ModelT: BaseModel](
        self, system_prompt: str, contents: str, schema: type[ModelT]
    ) -> ModelT:
        try:
            return generate_structured(
                api_key=self.api_key,
                system_prompt=system_prompt,
                contents=contents,
                schema=schema,
            )
        except GeminiError as exc:
            # Same short codes, so nothing upstream needs to know which
            # provider produced the failure.
            raise ProviderError(exc.code) from exc
