"""Interchangeable AI providers, and the registry that selects one.

    AIProvider
    ├── GeminiProvider              text   (the platform's measured default)
    ├── KimiProvider                vision (optional second opinion)
    ├── OpenAIProvider              text + vision
    └── ClaudeProvider              text + vision

Adding a provider means writing a class and adding one line to
`_BUILDERS`. Nothing else in the platform learns its name: callers ask
for a capability — "a provider that can read an image" — and take
whatever is configured, or carry on without one.

That last part is the important guarantee. Every provider here is
optional except the one already measured; `vision_provider()` returns
None rather than raising when nothing is configured, so an absent or
broken provider degrades to "we did not look at that" instead of a
failed analysis.
"""

import os

from services.providers.base import (
    AIProvider,
    ProviderError,
    ProviderUnsupported,
)
from services.providers.claude import ClaudeProvider
from services.providers.gemini import GeminiProvider
from services.providers.kimi import KimiProvider
from services.providers.openai import OpenAIProvider
from services.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "AIProvider",
    "ClaudeProvider",
    "GeminiProvider",
    "KimiProvider",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "ProviderError",
    "ProviderUnsupported",
    "build",
    "vision_provider",
]

_BUILDERS = {
    "gemini": lambda: GeminiProvider(os.environ.get("GEMINI_API_KEY", "")),
    "kimi": KimiProvider,
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
}


def build(name: str) -> AIProvider | None:
    """Construct one provider by name, or None if the name is unknown."""
    builder = _BUILDERS.get(name.strip().lower())
    return builder() if builder else None


def vision_provider(preferred: str = "") -> AIProvider | None:
    """A configured provider that can read an image, if there is one.

    Order is preference, then whatever is configured. Returning None is
    a normal outcome: the Trust Engine has never needed a vision
    provider, and the product must keep working without one.
    """
    names = [preferred] if preferred else []
    names += [os.environ.get("TUMAR_VISION_PROVIDER", "")]
    names += ["kimi", "openai", "claude"]

    seen: set[str] = set()
    for name in names:
        key = name.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        provider = build(key)
        if provider and provider.available() and provider.supports_vision():
            return provider
    return None
