"""Providers that speak the OpenAI chat-completions dialect.

Several hosts expose that same shape — NVIDIA's inference endpoints,
OpenAI itself, and most self-hosted gateways — so the transport is
written once here and each provider becomes configuration: a base URL,
a model id, a key.

Only `requests` is used, which the project already depends on. A
vendor SDK per provider would be four more dependencies to pin, audit
and keep in step for no behaviour we need.
"""

import base64
import json

import requests
from pydantic import BaseModel, ValidationError

from services.providers.base import AIProvider, ProviderError

REQUEST_TIMEOUT_S = 60

# Low temperature: a security judgement should not be creative.
TEMPERATURE = 0.2


class OpenAICompatibleProvider(AIProvider):
    """Shared transport for chat-completions style APIs."""

    name = "openai-compatible"

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        vision: bool = False,
        timeout: int = REQUEST_TIMEOUT_S,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._vision = vision
        self.timeout = timeout
        # Token counts from the most recent call, when the endpoint
        # reports them. Read by the evaluation harness so a provider
        # comparison can weigh cost against quality; never logged, and
        # never part of a user-facing report.
        self.last_usage: dict | None = None

    def available(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    def supports_vision(self) -> bool:
        return self._vision

    def generate_structured[ModelT: BaseModel](
        self, system_prompt: str, contents: str, schema: type[ModelT]
    ) -> ModelT:
        return self._complete(
            schema,
            system_prompt,
            [{"type": "text", "text": contents}],
        )

    def analyze_image[ModelT: BaseModel](
        self,
        image_bytes: bytes,
        mime_type: str,
        system_prompt: str,
        schema: type[ModelT],
        instruction: str = "",
    ) -> ModelT:
        if not self.supports_vision():
            from services.providers.base import ProviderUnsupported

            raise ProviderUnsupported("vision")

        encoded = base64.b64encode(image_bytes).decode("ascii")
        parts: list[dict] = []
        if instruction:
            parts.append({"type": "text", "text": instruction})
        parts.append(
            {
                "type": "image_url",
                "image_url": {"url": f"data:{mime_type};base64,{encoded}"},
            }
        )
        return self._complete(schema, system_prompt, parts)

    def _complete[ModelT: BaseModel](
        self, schema: type[ModelT], system_prompt: str, parts: list[dict]
    ) -> ModelT:
        """One request, and a validated answer or a coded failure."""
        if not self.available():
            raise ProviderError("missing_key")

        payload = {
            "model": self.model,
            "temperature": TEMPERATURE,
            # Asking for JSON is a hint, not a guarantee; the answer is
            # validated against the schema either way.
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": parts},
            ],
        }
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout as exc:
            raise ProviderError("timeout") from exc
        except requests.exceptions.RequestException as exc:
            raise ProviderError("unreachable") from exc

        self._raise_for_status(response.status_code)

        try:
            body = response.json()
            text = self._extract_text(body)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected_answer") from exc

        usage = body.get("usage") if isinstance(body, dict) else None
        self.last_usage = usage if isinstance(usage, dict) else None

        return self._validate(text, schema)

    @staticmethod
    def _extract_text(body: dict) -> str:
        """Pull the answer out, tolerating shape differences.

        The chat-completions shape is a convention, not a standard, and
        hosts vary: some return the message content as a list of parts,
        some put a reasoning trace alongside the answer. Reading a few
        known shapes costs little and avoids a provider integration
        that fails on a detail unrelated to what it was asked.
        """
        choice = body["choices"][0]
        message = choice.get("message") or {}

        content = message.get("content")
        if isinstance(content, list):
            # Content returned as parts: keep the text ones in order.
            content = "".join(
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and part.get("type") in (None, "text")
            )
        if isinstance(content, str) and content.strip():
            return content

        # Some endpoints separate a reasoning trace from the answer; if
        # the answer came back empty, the JSON may be in the trace.
        for fallback in ("reasoning_content", "reasoning", "text"):
            value = message.get(fallback) or choice.get(fallback)
            if isinstance(value, str) and value.strip():
                return value

        raise KeyError("no textual content in the response")

    @staticmethod
    def _raise_for_status(status: int) -> None:
        """Map HTTP status onto the platform's error codes."""
        if status == 200:
            return
        if status in (401, 403):
            raise ProviderError("credentials")
        if status == 404:
            raise ProviderError("model_unavailable")
        if status == 429:
            raise ProviderError("rate_limited")
        if status >= 500:
            raise ProviderError("service_down")
        raise ProviderError("ai_error")

    @staticmethod
    def _validate[ModelT: BaseModel](text: str, schema: type[ModelT]) -> ModelT:
        """Parse the answer, tolerating the wrappers models add.

        Models sometimes fence JSON in markdown despite being asked
        not to. Recovering from that is worth a few lines; failing a
        user's analysis over a stray backtick is not.
        """
        candidate = (text or "").strip()
        if candidate.startswith("```"):
            candidate = candidate.strip("`")
            if candidate.lower().startswith("json"):
                candidate = candidate[4:]
        start, end = candidate.find("{"), candidate.rfind("}")
        if start != -1 and end > start:
            candidate = candidate[start : end + 1]
        try:
            return schema.model_validate_json(candidate)
        except ValidationError as exc:
            raise ProviderError("unexpected_answer") from exc
        except json.JSONDecodeError as exc:
            raise ProviderError("unexpected_answer") from exc
