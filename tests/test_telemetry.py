"""Structured telemetry (services/telemetry.py) and where it is wired in.

The privacy tests matter most: whatever a user sends must never reach
the logs, only kinds, outcomes, codes, timings and token counts.

    venv\\Scripts\\python.exe tests\\test_telemetry.py
"""

import json
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from google.genai import errors as genai_errors  # noqa: E402
from pydantic import BaseModel  # noqa: E402

import services.gemini_client as gemini_client  # noqa: E402
from services import telemetry  # noqa: E402
from services.quota import DailyQuota  # noqa: E402
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject  # noqa: E402

_PROVIDER_VARS = (
    "GEMINI_API_KEY", "TUMAR_TEXT_PROVIDER", "TUMAR_VISION_PROVIDER",
    "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KIMI_API_KEY",
)


class _Capture(logging.Handler):
    """Collects the JSON lines telemetry writes."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())

    @property
    def events(self) -> list[dict]:
        return [json.loads(line) for line in self.lines]


def _capture() -> _Capture:
    handler = _Capture()
    logging.getLogger(telemetry.LOGGER_NAME).addHandler(handler)
    return handler


def _release(handler: _Capture) -> None:
    logging.getLogger(telemetry.LOGGER_NAME).removeHandler(handler)


def test_only_allow_listed_identifier_values_pass() -> None:
    cleaned = telemetry.sanitize(
        {
            "kind": "message",
            "model": "gemini-3.5-flash",
            "duration_ms": 412,
            "error_code": "Your code is 4821, send it to me",  # content in a code field
            "channel": "https://evil.example/login",
            "tier": "someone@example.com",
            "content": "should never appear",  # not an allowed field at all
            "user_id": 123456,
        }
    )
    assert cleaned == {
        "kind": "message",
        "model": "gemini-3.5-flash",
        "duration_ms": 412,
        "error_code": telemetry.REDACTED,
        "channel": telemetry.REDACTED,
        "tier": telemetry.REDACTED,
    }, cleaned
    print("test_only_allow_listed_identifier_values_pass PASSED")


def test_engine_logs_no_user_content() -> None:
    # A real check, offline (no key), with distinctive content.
    saved = {name: os.environ.pop(name, None) for name in _PROVIDER_VARS}
    handler = _capture()
    message = "Urgent: send the code 739154 to verify at kaspi-secure-login.example now, Aigerim"
    try:
        report = TrustEngine().analyze(
            TrustSubject(content=message, declared_kind="message"),
            AnalysisContext(offline_fallback=True, channel="web"),
        )
    finally:
        _release(handler)
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value
    log = "\n".join(handler.lines)
    for fragment in ("739154", "kaspi-secure-login", "Aigerim", "Urgent", "verify at"):
        assert fragment not in log, (fragment, log)
    [event] = [e for e in handler.events if e["event"] == "analysis"]
    assert event["channel"] == "web" and event["kind"] == "message", event
    assert event["outcome"] == "offline" and event["error_code"] == "missing_key", event
    assert event["mode"] == "offline" and event["verdict"] == report.verdict, event
    assert isinstance(event["duration_ms"], int) and event["request_id"], event
    print("test_engine_logs_no_user_content PASSED")


def test_one_request_id_from_quota_to_engine() -> None:
    saved = {name: os.environ.pop(name, None) for name in _PROVIDER_VARS}
    handler = _capture()
    try:
        request_id = telemetry.begin_request()
        quota = DailyQuota()
        quota.consume("user:a@example.com", "user", "url")
        TrustEngine().analyze(
            TrustSubject(content="http://example.com", declared_kind="url"),
            AnalysisContext(offline_fallback=True, channel="telegram"),
        )
        quota.refund("user:a@example.com", "user", "url")
    finally:
        _release(handler)
        telemetry._request_id.set(None)
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value
    events = handler.events
    assert [e["event"] for e in events] == ["quota", "analysis", "quota"], events
    assert {e["request_id"] for e in events} == {request_id}, events
    assert [e.get("action") for e in events if e["event"] == "quota"] == ["allowed", "refund"]
    assert "a@example.com" not in "\n".join(handler.lines)
    print("test_one_request_id_from_quota_to_engine PASSED")


def test_engine_errors_are_logged_and_still_raised() -> None:
    handler = _capture()
    try:
        try:
            TrustEngine().analyze(
                TrustSubject(content="not an email", declared_kind="email"),
                AnalysisContext(channel="api"),
            )
        except Exception as exc:  # the engine's error must still reach the caller
            code = getattr(exc, "code", None)
        else:
            raise AssertionError("invalid e-mail did not raise")
    finally:
        _release(handler)
    [event] = handler.events
    assert event["outcome"] == "error" and event["error_code"] == code, (event, code)
    print("test_engine_errors_are_logged_and_still_raised PASSED")


class _Answer(BaseModel):
    verdict: str = "safe"


class _FakeModels:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)

    def generate_content(self, model, contents, config):
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _fake_client(outcomes):
    models = _FakeModels(outcomes)
    return lambda **_kwargs: SimpleNamespace(models=models)


def test_gemini_attempts_logged_with_tokens_and_cost() -> None:
    answer = SimpleNamespace(
        parsed=_Answer(),
        text="",
        usage_metadata=SimpleNamespace(prompt_token_count=1200, candidates_token_count=300),
    )
    overloaded = genai_errors.APIError(429, {"error": {"message": "quota", "status": "RESOURCE_EXHAUSTED"}})
    original = gemini_client.genai.Client
    gemini_client.genai.Client = _fake_client([overloaded, answer])
    os.environ["TUMAR_MODEL_PRICES"] = json.dumps(
        {gemini_client.MODEL_CANDIDATES[1]: {"input": 0.1, "output": 0.4}}
    )
    handler = _capture()
    try:
        result = gemini_client.generate_structured("fake-key", "system", "SECRET-PROMPT-TEXT", _Answer)
    finally:
        _release(handler)
        gemini_client.genai.Client = original
        os.environ.pop("TUMAR_MODEL_PRICES", None)
    assert result.verdict == "safe"
    first, second = handler.events
    assert first["model"] == gemini_client.MODEL_CANDIDATES[0] and first["attempt"] == 1
    assert first["outcome"] == "error" and first["error_code"] == "rate_limited"
    assert first["http_status"] == 429 and first["input_tokens"] is None
    assert second["model"] == gemini_client.MODEL_CANDIDATES[1] and second["attempt"] == 2
    assert second["outcome"] == "ok"
    assert (second["input_tokens"], second["output_tokens"]) == (1200, 300)
    # (1200 * 0.1 + 300 * 0.4) / 1e6
    assert abs(second["cost_usd"] - 0.00024) < 1e-12, second
    assert "SECRET-PROMPT-TEXT" not in "\n".join(handler.lines)
    assert "fake-key" not in "\n".join(handler.lines)
    print("test_gemini_attempts_logged_with_tokens_and_cost PASSED")


def test_network_failure_is_logged_as_unreachable() -> None:
    original = gemini_client.genai.Client
    gemini_client.genai.Client = _fake_client([TimeoutError("read timed out")])
    handler = _capture()
    try:
        try:
            gemini_client.generate_structured("fake-key", "system", "text", _Answer)
        except gemini_client.GeminiError as exc:
            assert exc.code == "unreachable"
        else:
            raise AssertionError("expected GeminiError")
    finally:
        _release(handler)
        gemini_client.genai.Client = original
    [event] = handler.events
    assert event["outcome"] == "error" and event["error_code"] == "unreachable", event
    print("test_network_failure_is_logged_as_unreachable PASSED")


def test_cost_needs_configured_prices() -> None:
    os.environ.pop("TUMAR_MODEL_PRICES", None)
    assert telemetry.approximate_cost("gemini-3.5-flash", 1000, 100) is None
    os.environ["TUMAR_MODEL_PRICES"] = "not json"
    assert telemetry.approximate_cost("gemini-3.5-flash", 1000, 100) is None
    os.environ.pop("TUMAR_MODEL_PRICES")
    print("test_cost_needs_configured_prices PASSED")


def test_metrics_summary_percentiles() -> None:
    metrics = telemetry.Metrics(window=500)
    for ms in range(1, 101):
        metrics.observe({"event": "analysis", "kind": "message", "outcome": "ok", "duration_ms": ms})
    metrics.observe({"event": "analysis", "kind": "message", "outcome": "error"})
    summary = metrics.summary()
    assert summary["latency"]["analysis:message"] == {"count": 100, "p50_ms": 50, "p95_ms": 95}
    assert summary["counts"] == {"analysis:message:ok": 100, "analysis:message:error": 1}
    assert telemetry._percentile([], 95) is None  # no data is not "0 ms"
    print("test_metrics_summary_percentiles PASSED")


def test_switch_off_silences_logs_only() -> None:
    os.environ["TUMAR_TELEMETRY"] = "off"
    handler = _capture()
    telemetry.metrics.reset()
    try:
        telemetry.emit("quota", tier="bot", kind="message", action="allowed")
    finally:
        _release(handler)
        os.environ.pop("TUMAR_TELEMETRY")
    assert handler.lines == []
    assert telemetry.metrics.summary()["counts"] == {"quota:message:allowed": 1}
    print("test_switch_off_silences_logs_only PASSED")


if __name__ == "__main__":
    test_only_allow_listed_identifier_values_pass()
    test_engine_logs_no_user_content()
    test_one_request_id_from_quota_to_engine()
    test_engine_errors_are_logged_and_still_raised()
    test_gemini_attempts_logged_with_tokens_and_cost()
    test_network_failure_is_logged_as_unreachable()
    test_cost_needs_configured_prices()
    test_metrics_summary_percentiles()
    test_switch_off_silences_logs_only()
    print("All telemetry tests passed.")
