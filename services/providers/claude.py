"""Claude, through the Anthropic Messages API.

A different request shape from the chat-completions dialect — the
system prompt is a top-level field and images are inline base64 source
blocks — so it gets its own small client rather than being bent into
the shared one.

Untested in this repository: no key was available. Present as a
supported shape, not a verified integration. Confirm with the
evaluation harness before trusting it with verdicts.
"""

import base64
import os

import requests
from pydantic import BaseModel

from services.providers.base import AIProvider, ProviderError
from services.providers.openai_compatible import (
    REQUEST_TIMEOUT_S,
    TEMPERATURE,
    OpenAICompatibleProvider,
)

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_MODEL = "claude-sonnet-4-5"
API_VERSION = "2023-06-01"
MAX_TOKENS = 2048


class ClaudeProvider(AIProvider):
    """Anthropic models, text and vision."""

    name = "claude"

    def __init__(
        self, api_key: str = "", model: str = "", base_url: str = ""
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
        self.base_url = (
            base_url or os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")

    def available(self) -> bool:
        return bool(self.api_key and self.model)

    def supports_vision(self) -> bool:
        return True

    def generate_structured[ModelT: BaseModel](
        self, system_prompt: str, contents: str, schema: type[ModelT]
    ) -> ModelT:
        return self._send(schema, system_prompt, [{"type": "text", "text": contents}])

    def analyze_image[ModelT: BaseModel](
        self,
        image_bytes: bytes,
        mime_type: str,
        system_prompt: str,
        schema: type[ModelT],
        instruction: str = "",
    ) -> ModelT:
        blocks: list[dict] = []
        if instruction:
            blocks.append({"type": "text", "text": instruction})
        blocks.append(
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": mime_type,
                    "data": base64.b64encode(image_bytes).decode("ascii"),
                },
            }
        )
        return self._send(schema, system_prompt, blocks)

    def _send[ModelT: BaseModel](
        self, schema: type[ModelT], system_prompt: str, blocks: list[dict]
    ) -> ModelT:
        if not self.available():
            raise ProviderError("missing_key")
        try:
            response = requests.post(
                f"{self.base_url}/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": API_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": MAX_TOKENS,
                    "temperature": TEMPERATURE,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": blocks}],
                },
                timeout=REQUEST_TIMEOUT_S,
            )
        except requests.exceptions.Timeout as exc:
            raise ProviderError("timeout") from exc
        except requests.exceptions.RequestException as exc:
            raise ProviderError("unreachable") from exc

        OpenAICompatibleProvider._raise_for_status(response.status_code)

        try:
            body = response.json()
            text = body["content"][0]["text"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected_answer") from exc

        return OpenAICompatibleProvider._validate(text, schema)
