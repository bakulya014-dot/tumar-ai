"""Interchangeable AI providers, and the registry that selects one.

    AIProvider
    ├── GeminiProvider              text   (the platform's measured default)
    ├── DeepSeekProvider            text   (+ vision once confirmed)
    ├── OpenAIProvider              text + vision
    └── ClaudeProvider              text + vision

Adding a provider means writing a class and adding one line to
`_BUILDERS`. Nothing else in the platform learns its name: callers ask
for a capability — "a provider that can read an image" — and take
whatever is configured, or carry on without one.

Two rules make this safe to grow.

**Absence is normal.** `vision_provider()` returns None rather than
raising when nothing is configured, so a missing or broken provider
degrades to "we did not look at that" instead of a failed analysis.

**A new model never becomes the default by accident.** Adopting one
changes what every verdict is based on, so it is an explicit choice
(`TUMAR_TEXT_PROVIDER`) and should be a measured one — run the
evaluation harness against the new provider before trusting it, the
same way the current default earned its place.
"""

import os

from services.providers.base import (
    AIProvider,
    ProviderError,
    ProviderUnsupported,
)
from services.providers.claude import ClaudeProvider
from services.providers.deepseek import DeepSeekProvider
from services.providers.gemini import GeminiProvider
from services.providers.openai import OpenAIProvider
from services.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "AIProvider",
    "ClaudeProvider",
    "DeepSeekProvider",
    "GeminiProvider",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "ProviderError",
    "ProviderUnsupported",
    "build",
    "text_provider",
    "vision_provider",
]

_BUILDERS = {
    "gemini": lambda: GeminiProvider(os.environ.get("GEMINI_API_KEY", "")),
    "deepseek": DeepSeekProvider,
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
}


def build(name: str) -> AIProvider | None:
    """Construct one provider by name, or None if the name is unknown."""
    builder = _BUILDERS.get(name.strip().lower())
    return builder() if builder else None


def text_provider(preferred: str = "") -> AIProvider | None:
    """A configured provider for text analysis, if one is chosen.

    Returns None unless a provider is named — by the caller or by
    TUMAR_TEXT_PROVIDER. That silence is deliberate: swapping the model
    behind every scam verdict is not something that should happen
    because a key appeared in the environment. Callers fall back to
    their existing behaviour when this returns None.
    """
    name = (preferred or os.environ.get("TUMAR_TEXT_PROVIDER", "")).strip().lower()
    if not name:
        return None
    provider = build(name)
    return provider if provider and provider.available() else None


def vision_provider(preferred: str = "") -> AIProvider | None:
    """A configured provider that can read an image, if there is one.

    Order is preference, then whatever is configured. Returning None is
    a normal outcome: the Trust Engine has never needed a vision
    provider, and the product must keep working without one.
    """
    names = [preferred] if preferred else []
    names += [os.environ.get("TUMAR_VISION_PROVIDER", "")]
    names += ["deepseek", "openai", "claude"]

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
