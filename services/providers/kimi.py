"""Kimi, hosted on NVIDIA's inference endpoints.

NVIDIA exposes third-party models behind an OpenAI-compatible API, so
this provider is configuration over the shared transport rather than
new client code.

**Verify the model id before relying on this.** The default below is a
placeholder: the exact slug, and whether the version you want accepts
images at all, must be read from NVIDIA's model catalogue. Both are
environment variables precisely so confirming them is a config change
and not a code change:

    KIMI_API_KEY      key for the NVIDIA endpoint
    KIMI_MODEL        model id from the catalogue
    KIMI_BASE_URL     override if the endpoint moves
    KIMI_VISION       "0" to declare this model text-only

If the model turns out not to accept images, set KIMI_VISION=0 and the
platform carries on without vision — the Trust Engine has never
depended on this provider existing.
"""

import os

from services.providers.openai_compatible import OpenAICompatibleProvider

DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"

# Placeholder. Confirm against the catalogue and set KIMI_MODEL.
DEFAULT_MODEL = "moonshotai/kimi-k2-instruct"


class KimiProvider(OpenAICompatibleProvider):
    """Kimi via NVIDIA, used as an optional second opinion."""

    name = "kimi"

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        vision: bool | None = None,
    ):
        super().__init__(
            api_key=api_key or os.environ.get("KIMI_API_KEY", ""),
            base_url=base_url or os.environ.get("KIMI_BASE_URL", DEFAULT_BASE_URL),
            model=model or os.environ.get("KIMI_MODEL", DEFAULT_MODEL),
            vision=(
                vision
                if vision is not None
                else os.environ.get("KIMI_VISION", "1") != "0"
            ),
        )
