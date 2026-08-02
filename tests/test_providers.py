"""Tests for the provider abstraction (no network).

`requests` is stubbed, so these assert on what would have been sent
and how answers and failures are handled.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_providers.py
"""

import base64
import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import BaseModel

from services.providers import (
    ClaudeProvider,
    GeminiProvider,
    DeepSeekProvider,
    OpenAIProvider,
    ProviderError,
    ProviderUnsupported,
    build,
    vision_provider,
)
from services.providers import openai_compatible
from services.providers.base import AIProvider


class _Answer(BaseModel):
    verdict: str
    score: int


class _Response:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self._text = text

    def json(self):
        if self.status_code != 200:
            raise ValueError("no body")
        return {"choices": [{"message": {"content": self._text}}]}


class _Recorder:
    def __init__(self, response=None, raises: Exception | None = None):
        self.response = response
        self.raises = raises
        self.last: dict = {}

    def post(self, url, headers=None, json=None, timeout=None):
        self.last = {"url": url, "headers": headers, "json": json}
        if self.raises:
            raise self.raises
        return self.response


def _stub(recorder: _Recorder):
    """Swap in the recorder, keeping the real exception classes.

    The module catches requests.exceptions.*, so a stub that drops
    them would turn a handled timeout into an AttributeError.
    """
    import requests as real_requests

    recorder.exceptions = real_requests.exceptions
    openai_compatible.requests = recorder
    return recorder


def _restore() -> None:
    import requests

    openai_compatible.requests = requests


# --- The interface ---


def test_every_provider_implements_the_interface() -> None:
    for provider in (
        GeminiProvider("k"),
        DeepSeekProvider("k"),
        OpenAIProvider("k"),
        ClaudeProvider("k"),
    ):
        assert isinstance(provider, AIProvider)
        assert provider.name
        assert isinstance(provider.available(), bool)
        assert isinstance(provider.supports_vision(), bool)
    print("test_every_provider_implements_the_interface PASSED")


def test_a_provider_without_a_key_is_unavailable() -> None:
    """Unconfigured must mean skipped, not broken at the point of use."""
    assert not DeepSeekProvider(api_key="").available()
    assert not GeminiProvider("").available()
    assert not ClaudeProvider(api_key="").available()
    print("test_a_provider_without_a_key_is_unavailable PASSED")


def test_a_text_only_provider_refuses_images() -> None:
    provider = DeepSeekProvider("k", vision=False)
    try:
        provider.analyze_image(b"x", "image/png", "prompt", _Answer)
    except ProviderUnsupported:
        print("test_a_text_only_provider_refuses_images PASSED")
    else:
        raise AssertionError("a text-only provider accepted an image")


def test_gemini_does_not_claim_vision() -> None:
    # Declaring an untested capability would route images to it and
    # fail where the user is standing.
    assert GeminiProvider("k").supports_vision() is False
    print("test_gemini_does_not_claim_vision PASSED")


# --- The registry ---


def test_registry_builds_by_name_and_ignores_strangers() -> None:
    assert isinstance(build("deepseek"), DeepSeekProvider)
    assert isinstance(build("OpenAI"), OpenAIProvider)
    assert build("not-a-provider") is None
    print("test_registry_builds_by_name_and_ignores_strangers PASSED")


def test_no_vision_provider_configured_returns_none() -> None:
    """The platform must work with no optional provider at all."""
    import os

    saved = {
        name: os.environ.pop(name, None)
        for name in (
            "DEEPSEEK_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "TUMAR_VISION_PROVIDER",
        )
    }
    try:
        assert vision_provider() is None
    finally:
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value
    print("test_no_vision_provider_configured_returns_none PASSED")


def test_vision_stays_off_until_the_model_is_confirmed() -> None:
    """A key alone must not imply the model can read images.

    Claiming an unconfirmed capability would route screenshots to it
    and fail where the user is standing. Enabling it is a deliberate
    act, taken after watching it work.
    """
    import os

    os.environ["DEEPSEEK_API_KEY"] = "test-key"
    os.environ.pop("DEEPSEEK_VISION", None)
    try:
        assert vision_provider() is None
        os.environ["DEEPSEEK_VISION"] = "1"
        found = vision_provider()
        assert found is not None and found.name == "deepseek"
    finally:
        os.environ.pop("DEEPSEEK_API_KEY", None)
        os.environ.pop("DEEPSEEK_VISION", None)
    print("test_vision_stays_off_until_the_model_is_confirmed PASSED")


def test_a_new_model_never_becomes_the_default_by_accident() -> None:
    """Swapping the model behind every verdict must be chosen, not inherited.

    A key appearing in the environment is not consent to change what
    the whole product's judgements are based on — that is a decision
    to make against the evaluation harness.
    """
    import os

    from services.providers import text_provider

    os.environ["DEEPSEEK_API_KEY"] = "test-key"
    os.environ.pop("TUMAR_TEXT_PROVIDER", None)
    try:
        assert text_provider() is None  # configured, but not chosen
        os.environ["TUMAR_TEXT_PROVIDER"] = "deepseek"
        chosen = text_provider()
        assert chosen is not None and chosen.name == "deepseek"
    finally:
        os.environ.pop("DEEPSEEK_API_KEY", None)
        os.environ.pop("TUMAR_TEXT_PROVIDER", None)
    print("test_a_new_model_never_becomes_the_default_by_accident PASSED")


# --- The transport ---


def test_an_image_is_sent_as_a_data_uri() -> None:
    recorder = _stub(_Recorder(_Response(200, '{"verdict":"danger","score":90}')))
    try:
        # vision=True explicitly: the provider does not assume the
        # capability, so a test of the image path must declare it.
        answer = DeepSeekProvider("test-key", model="m", vision=True).analyze_image(
            b"\x89PNG-bytes", "image/png", "system", _Answer, "read it"
        )
        assert answer.verdict == "danger"
        parts = recorder.last["json"]["messages"][1]["content"]
        image = next(p for p in parts if p["type"] == "image_url")
        expected = base64.b64encode(b"\x89PNG-bytes").decode()
        assert image["image_url"]["url"] == f"data:image/png;base64,{expected}"
        assert recorder.last["headers"]["Authorization"] == "Bearer test-key"
    finally:
        _restore()
    print("test_an_image_is_sent_as_a_data_uri PASSED")


def test_json_wrapped_in_a_markdown_fence_is_recovered() -> None:
    # Models add fences despite being asked not to. Failing a user's
    # analysis over a stray backtick would be indefensible.
    fenced = '```json\n{"verdict":"safe","score":10}\n```'
    _stub(_Recorder(_Response(200, fenced)))
    try:
        answer = DeepSeekProvider("k", model="m").generate_structured("s", "c", _Answer)
        assert answer.verdict == "safe"
    finally:
        _restore()
    print("test_json_wrapped_in_a_markdown_fence_is_recovered PASSED")


def test_http_failures_map_to_platform_error_codes() -> None:
    for status, code in (
        (401, "credentials"),
        (404, "model_unavailable"),
        (429, "rate_limited"),
        (500, "service_down"),
        (418, "ai_error"),
    ):
        _stub(_Recorder(_Response(status)))
        try:
            DeepSeekProvider("k", model="m").generate_structured("s", "c", _Answer)
        except ProviderError as error:
            assert error.code == code, status
        else:
            raise AssertionError(f"status {status} did not raise")
        finally:
            _restore()
    print("test_http_failures_map_to_platform_error_codes PASSED")


def test_network_failure_and_garbage_are_coded_not_raw() -> None:
    import requests as real_requests

    _stub(_Recorder(raises=real_requests.exceptions.Timeout("slow")))
    try:
        DeepSeekProvider("k", model="m").generate_structured("s", "c", _Answer)
    except ProviderError as error:
        assert error.code == "timeout"
    finally:
        _restore()

    _stub(_Recorder(_Response(200, "not json at all")))
    try:
        DeepSeekProvider("k", model="m").generate_structured("s", "c", _Answer)
    except ProviderError as error:
        assert error.code == "unexpected_answer"
    finally:
        _restore()
    print("test_network_failure_and_garbage_are_coded_not_raw PASSED")


def test_the_model_id_is_configuration_not_code() -> None:
    # The exact DeepSeek model id could not be verified here, so it must
    # be changeable without touching source.
    import os

    os.environ["DEEPSEEK_MODEL"] = "vendor/some-other-model"
    try:
        assert DeepSeekProvider("k").model == "vendor/some-other-model"
    finally:
        os.environ.pop("DEEPSEEK_MODEL", None)
    print("test_the_model_id_is_configuration_not_code PASSED")


if __name__ == "__main__":
    test_every_provider_implements_the_interface()
    test_a_provider_without_a_key_is_unavailable()
    test_a_text_only_provider_refuses_images()
    test_gemini_does_not_claim_vision()
    test_registry_builds_by_name_and_ignores_strangers()
    test_no_vision_provider_configured_returns_none()
    test_vision_stays_off_until_the_model_is_confirmed()
    test_a_new_model_never_becomes_the_default_by_accident()
    test_an_image_is_sent_as_a_data_uri()
    test_json_wrapped_in_a_markdown_fence_is_recovered()
    test_http_failures_map_to_platform_error_codes()
    test_network_failure_and_garbage_are_coded_not_raw()
    test_the_model_id_is_configuration_not_code()
    print("ALL PROVIDER TESTS PASSED")
