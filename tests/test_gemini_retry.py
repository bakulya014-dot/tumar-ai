"""How services/gemini_client.py reacts to slow, dropped and failing calls.

No network: the SDK client is replaced by a fake that raises or answers
in a scripted order, and the retry pause is recorded instead of slept.

    venv\\Scripts\\python.exe tests\\test_gemini_retry.py
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import httpx  # noqa: E402
from google.genai import errors as genai_errors  # noqa: E402
from pydantic import BaseModel  # noqa: E402

import services.gemini_client as gemini_client  # noqa: E402
from services import telemetry  # noqa: E402

PRIMARY, FALLBACK = gemini_client.MODEL_CANDIDATES[:2]


class _Answer(BaseModel):
    verdict: str = "safe"


ANSWER = SimpleNamespace(parsed=_Answer(), text="", usage_metadata=None)


def _api_error(code: int) -> genai_errors.APIError:
    return genai_errors.APIError(code, {"error": {"message": "x", "status": "X"}})


class _Scenario:
    """Fake SDK client answering from a script; records models and pauses."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.models: list[str] = []
        self.pauses: list[float] = []

    def __enter__(self):
        self._client, self._sleep = gemini_client.genai.Client, gemini_client._sleep
        gemini_client.genai.Client = lambda **_kw: SimpleNamespace(models=self)
        gemini_client._sleep = self.pauses.append
        telemetry.metrics.reset()
        return self

    def __exit__(self, *exc):
        gemini_client.genai.Client, gemini_client._sleep = self._client, self._sleep

    def generate_content(self, model, contents, config):
        self.models.append(model)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _call():
    return gemini_client.generate_structured("fake-key", "system", "text", _Answer)


def _code(fn) -> str:
    try:
        fn()
    except gemini_client.GeminiError as exc:
        return exc.code
    raise AssertionError("expected GeminiError")


def test_a_slow_model_hands_over_to_the_next() -> None:
    # Seen live: an overloaded primary held requests for 30 s. A timeout
    # moves on to the next model instead of failing the check.
    with _Scenario(httpx.ReadTimeout("read timed out"), ANSWER) as fake:
        assert _call().verdict == "safe"
    assert fake.models == [PRIMARY, FALLBACK], fake.models
    assert fake.pauses == []
    print("test_a_slow_model_hands_over_to_the_next PASSED")


def test_timeouts_everywhere_are_reported_as_timeout() -> None:
    every_model = list(gemini_client.MODEL_CANDIDATES)
    with _Scenario(*[httpx.ReadTimeout("slow")] * len(every_model)) as fake:
        assert _code(_call) == "timeout"
    assert fake.models == every_model, fake.models  # each tried once, never twice
    print("test_timeouts_everywhere_are_reported_as_timeout PASSED")


def test_each_attempt_gets_a_bounded_timeout() -> None:
    seen: list[int] = []

    class _Recording(_Scenario):
        def generate_content(self, model, contents, config):
            seen.append(config.http_options.timeout)
            return super().generate_content(model, contents, config)

    with _Recording(_api_error(503), _api_error(503), _api_error(503), ANSWER):
        assert _call().verdict == "safe"
    assert all(t <= gemini_client.MODEL_TIMEOUT_MS for t in seen[:-1]), seen
    assert seen[-1] <= gemini_client.REQUEST_TIMEOUT_MS, seen
    print("test_each_attempt_gets_a_bounded_timeout PASSED")


def test_the_total_budget_stops_the_chain() -> None:
    original = gemini_client.TOTAL_BUDGET_MS
    gemini_client.TOTAL_BUDGET_MS = gemini_client.MIN_ATTEMPT_MS - 1  # no time for any attempt
    try:
        with _Scenario() as fake:
            assert _code(_call) == "unavailable"
        assert fake.models == []
    finally:
        gemini_client.TOTAL_BUDGET_MS = original
    print("test_the_total_budget_stops_the_chain PASSED")


def test_fast_connection_drop_is_retried_once() -> None:
    with _Scenario(httpx.ConnectError("connection reset"), ANSWER) as fake:
        assert _call().verdict == "safe"
    assert fake.models == [PRIMARY, PRIMARY], fake.models
    assert fake.pauses == [gemini_client.RETRY_DELAY_S]
    counts = telemetry.metrics.summary()["counts"]
    assert counts == {"provider_call:gemini:error": 1, "provider_call:gemini:ok": 1}, counts
    print("test_fast_connection_drop_is_retried_once PASSED")


def test_second_connection_drop_gives_up() -> None:
    drop = httpx.RemoteProtocolError("server disconnected")
    with _Scenario(drop, drop) as fake:
        assert _code(_call) == "unreachable"
    assert fake.models == [PRIMARY, PRIMARY], fake.models  # not a third call
    print("test_second_connection_drop_gives_up PASSED")


def test_slow_connection_failure_is_not_retried() -> None:
    saved = gemini_client.FAST_FAILURE_S
    gemini_client.FAST_FAILURE_S = 0  # every failure now counts as slow
    try:
        with _Scenario(httpx.ConnectError("refused")) as fake:
            assert _code(_call) == "unreachable"
    finally:
        gemini_client.FAST_FAILURE_S = saved
    assert fake.models == [PRIMARY] and fake.pauses == []
    print("test_slow_connection_failure_is_not_retried PASSED")


def test_overload_still_falls_back_to_the_next_model() -> None:
    with _Scenario(_api_error(503), ANSWER) as fake:
        assert _call().verdict == "safe"
    assert fake.models == [PRIMARY, FALLBACK], fake.models
    every_model = list(gemini_client.MODEL_CANDIDATES)
    with _Scenario(*[_api_error(429)] * len(every_model)) as fake:
        assert _code(_call) == "rate_limited"
    assert fake.models == every_model  # each model in the chain is tried once
    print("test_overload_still_falls_back_to_the_next_model PASSED")


def test_bad_key_is_not_retried() -> None:
    with _Scenario(_api_error(403)) as fake:
        assert _code(_call) == "credentials"
    assert fake.models == [PRIMARY] and fake.pauses == []
    print("test_bad_key_is_not_retried PASSED")


def test_drop_then_overload_uses_both_models() -> None:
    # A retry on the primary does not use up the fallback model.
    with _Scenario(httpx.ConnectError("reset"), _api_error(503), ANSWER) as fake:
        assert _call().verdict == "safe"
    assert fake.models == [PRIMARY, PRIMARY, FALLBACK], fake.models
    print("test_drop_then_overload_uses_both_models PASSED")


if __name__ == "__main__":
    test_a_slow_model_hands_over_to_the_next()
    test_timeouts_everywhere_are_reported_as_timeout()
    test_each_attempt_gets_a_bounded_timeout()
    test_the_total_budget_stops_the_chain()
    test_fast_connection_drop_is_retried_once()
    test_second_connection_drop_gives_up()
    test_slow_connection_failure_is_not_retried()
    test_overload_still_falls_back_to_the_next_model()
    test_bad_key_is_not_retried()
    test_drop_then_overload_uses_both_models()
    print("All Gemini retry tests passed.")
