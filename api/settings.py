"""Configuration for the Tumar.AI REST API, read from the environment.

Everything here fails closed. An API that starts up without keys
configured and happily answers anyone is worse than one that refuses
to serve: the first leaks a paid AI budget and a security service to
the internet, the second sends a clear signal that setup is
incomplete.
"""

import os
from dataclasses import dataclass, field


def _split(value: str) -> tuple[str, ...]:
    """Parse a comma-separated environment value."""
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    """Runtime configuration. Secrets are never logged or echoed back."""

    # Keys allowed to call the API. Empty means the API is unconfigured
    # and will refuse every analysis request.
    api_keys: tuple[str, ...] = ()

    # Key for the AI provider, passed through to the services layer.
    gemini_api_key: str = ""

    # Requests per key per window. Without this an exposed endpoint is
    # an unbounded bill and an abuse channel.
    rate_limit: int = 60
    rate_window_seconds: int = 60

    # Longest input accepted. Matches the app's own limit; oversized
    # bodies are rejected before any AI call is made.
    max_content_length: int = 5000

    # Browser origins allowed to call the API. Empty means none, which
    # is correct for a server-to-server API — a wildcard alongside key
    # auth would let any page spend a customer's quota.
    allowed_origins: tuple[str, ...] = field(default_factory=tuple)

    @property
    def configured(self) -> bool:
        """True when the API has everything it needs to answer."""
        return bool(self.api_keys) and bool(self.gemini_api_key)


def load() -> Settings:
    """Build settings from environment variables."""
    return Settings(
        api_keys=_split(os.environ.get("TUMAR_API_KEYS", "")),
        gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
        rate_limit=int(os.environ.get("TUMAR_RATE_LIMIT", "60")),
        rate_window_seconds=int(os.environ.get("TUMAR_RATE_WINDOW", "60")),
        max_content_length=int(os.environ.get("TUMAR_MAX_CONTENT", "5000")),
        allowed_origins=_split(os.environ.get("TUMAR_ALLOWED_ORIGINS", "")),
    )
