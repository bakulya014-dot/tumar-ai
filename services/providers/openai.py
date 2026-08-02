"""OpenAI, through the same chat-completions transport.

Configuration over the shared client. Untested in this repository —
no key was available — so it is present as a supported shape rather
than a verified integration. Set OPENAI_API_KEY and OPENAI_MODEL, and
confirm with the evaluation harness before trusting it with verdicts.
"""

import os

from services.providers.openai_compatible import OpenAICompatibleProvider

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI models, text and vision."""

    name = "openai"

    def __init__(
        self, api_key: str = "", model: str = "", base_url: str = ""
    ):
        super().__init__(
            api_key=api_key or os.environ.get("OPENAI_API_KEY", ""),
            base_url=base_url or os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL),
            model=model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL),
            vision=True,
        )
