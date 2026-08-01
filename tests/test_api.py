"""Tests for the REST API (no network, no AI calls).

The AI layer is replaced with a stub, so these run offline and free in
CI. What is tested here is the network boundary: who gets in, what
gets rejected, and what a failure reveals — the parts where a mistake
is a security incident rather than a wrong answer.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_api.py
"""

import os
import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Configure before importing the app: settings are read at import time,
# which is what makes an unconfigured deployment fail closed.
os.environ["TUMAR_API_KEYS"] = "test-key-one,test-key-two"
os.environ["GEMINI_API_KEY"] = "stub-key"
os.environ["TUMAR_RATE_LIMIT"] = "5"

from fastapi.testclient import TestClient  # noqa: E402

from api import main  # noqa: E402
from api.security import RateLimiter, key_fingerprint, verify_key  # noqa: E402
from services.common import ServiceError  # noqa: E402
from services.trust_engine import AnalysisContext, TrustSubject  # noqa: E402
from services.trust_report import TrustReport  # noqa: E402

AUTH = {"Authorization": "Bearer test-key-one"}


class _StubAnalyzer:
    """Stands in for a real analyzer: no AI, no network, no cost."""

    kind = "message"

    def __init__(self, error: ServiceError | None = None):
        self.error = error

    def can_handle(self, subject: TrustSubject) -> bool:
        return isinstance(subject.content, str) and bool(subject.content.strip())

    def analyze(
        self, subject: TrustSubject, context: AnalysisContext
    ) -> TrustReport:
        if self.error:
            raise self.error
        return TrustReport(
            source="scam_analyzer",
            subject_type="message",
            subject_preview="stubbed",
            verdict="danger",
            trust_score=10,
            confidence=80,
        )


def _client(error: ServiceError | None = None) -> TestClient:
    """A client whose engine is stubbed, and a fresh rate limiter."""
    main.engine = main.TrustEngine([_StubAnalyzer(error)])
    main.limiter = RateLimiter(main.settings.rate_limit, 60)
    return TestClient(main.app)


# --- Authentication ---


def test_analysis_requires_a_key() -> None:
    response = _client().post("/v1/analyze", json={"content": "hello there"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    print("test_analysis_requires_a_key PASSED")


def test_wrong_key_is_rejected() -> None:
    response = _client().post(
        "/v1/analyze",
        json={"content": "hello there"},
        headers={"Authorization": "Bearer not-a-real-key"},
    )
    assert response.status_code == 401
    print("test_wrong_key_is_rejected PASSED")


def test_both_header_styles_work() -> None:
    client = _client()
    for headers in (
        {"Authorization": "Bearer test-key-one"},
        {"X-API-Key": "test-key-two"},
    ):
        response = client.post(
            "/v1/analyze", json={"content": "hello there"}, headers=headers
        )
        assert response.status_code == 200, headers
    print("test_both_header_styles_work PASSED")


def test_key_comparison_is_constant_time_and_fails_closed() -> None:
    assert verify_key("abc", ("abc",))
    assert not verify_key("ab", ("abc",))
    assert not verify_key("", ("abc",))
    # An unconfigured deployment must reject everyone, not accept all.
    assert not verify_key("anything", ())
    print("test_key_comparison_is_constant_time_and_fails_closed PASSED")


def test_key_never_appears_in_its_fingerprint() -> None:
    secret = "super-secret-key"
    fingerprint = key_fingerprint(secret)
    assert secret not in fingerprint
    assert fingerprint == key_fingerprint(secret)  # stable for grouping
    assert fingerprint != key_fingerprint("another-key")
    print("test_key_never_appears_in_its_fingerprint PASSED")


# --- Rate limiting ---


def test_rate_limit_blocks_the_caller_after_the_quota() -> None:
    client = _client()
    for _ in range(main.settings.rate_limit):
        assert (
            client.post("/v1/analyze", json={"content": "hi there"}, headers=AUTH).status_code
            == 200
        )
    blocked = client.post("/v1/analyze", json={"content": "hi there"}, headers=AUTH)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    print("test_rate_limit_blocks_the_caller_after_the_quota PASSED")


def test_rate_limit_window_resets() -> None:
    limiter = RateLimiter(limit=2, window_seconds=60)
    assert limiter.check("caller", now=0.0)[0]
    assert limiter.check("caller", now=1.0)[0]
    assert not limiter.check("caller", now=2.0)[0]
    # A later window is a clean slate.
    assert limiter.check("caller", now=61.0)[0]
    print("test_rate_limit_window_resets PASSED")


def test_rate_limit_is_per_caller() -> None:
    limiter = RateLimiter(limit=1, window_seconds=60)
    assert limiter.check("first", now=0.0)[0]
    assert not limiter.check("first", now=0.0)[0]
    # One noisy customer must not spend another customer's quota.
    assert limiter.check("second", now=0.0)[0]
    print("test_rate_limit_is_per_caller PASSED")


# --- Input handling ---


def test_oversized_content_is_rejected_before_any_analysis() -> None:
    response = _client().post(
        "/v1/analyze",
        json={"content": "x" * (main.settings.max_content_length + 1)},
        headers=AUTH,
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "content_too_large"
    print("test_oversized_content_is_rejected_before_any_analysis PASSED")


def test_empty_content_is_rejected_by_the_schema() -> None:
    response = _client().post("/v1/analyze", json={"content": ""}, headers=AUTH)
    assert response.status_code == 422
    print("test_empty_content_is_rejected_by_the_schema PASSED")


def test_passwords_cannot_be_requested_over_http() -> None:
    # The guarantee is that a password never travels. An endpoint that
    # accepted one would break it however carefully we behaved after.
    response = _client().post(
        "/v1/analyze",
        json={"content": "hunter2", "kind": "password"},
        headers=AUTH,
    )
    assert response.status_code == 422
    assert not any(a.kind == "password" for a in main._API_ANALYZERS)
    print("test_passwords_cannot_be_requested_over_http PASSED")


# --- Responses ---


def test_successful_analysis_returns_a_trust_report() -> None:
    response = _client().post(
        "/v1/analyze", json={"content": "URGENT! send the code"}, headers=AUTH
    )
    assert response.status_code == 200
    body = response.json()
    assert body["detected_kind"] == "message"
    assert body["report"]["verdict"] == "danger"
    assert body["report"]["trust_score"] == 10
    # The report validates as the same schema the rest of the platform
    # uses — the API invented no result type of its own.
    TrustReport.model_validate(body["report"])
    print("test_successful_analysis_returns_a_trust_report PASSED")


def test_every_response_carries_a_request_id() -> None:
    response = _client().post(
        "/v1/analyze", json={"content": "hello there"}, headers=AUTH
    )
    assert response.headers.get("X-Request-ID")
    assert response.json()["request_id"]
    print("test_every_response_carries_a_request_id PASSED")


def test_service_failures_map_to_useful_statuses() -> None:
    for code, expected in (
        ("timeout", 504),
        ("rate_limited", 429),
        ("credentials", 503),
        ("something_unheard_of", 502),
    ):
        response = _client(ServiceError(code)).post(
            "/v1/analyze", json={"content": "hello there"}, headers=AUTH
        )
        assert response.status_code == expected, code
    print("test_service_failures_map_to_useful_statuses PASSED")


def test_failures_never_leak_internals() -> None:
    response = _client(ServiceError("credentials")).post(
        "/v1/analyze", json={"content": "hello there"}, headers=AUTH
    )
    body = response.text.lower()
    for leak in ("traceback", "gemini", "stub-key", "api_key", "file \""):
        assert leak not in body, leak
    print("test_failures_never_leak_internals PASSED")


def test_health_is_open_and_says_nothing_secret() -> None:
    response = _client().get("/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "stub-key" not in response.text
    assert "test-key-one" not in response.text
    print("test_health_is_open_and_says_nothing_secret PASSED")


def test_analyzers_are_listed_from_the_live_registry() -> None:
    response = _client().get("/v1/analyzers")
    kinds = {item["kind"] for item in response.json()["analyzers"]}
    assert {"message", "url", "email"} <= kinds
    assert "password" not in kinds
    print("test_analyzers_are_listed_from_the_live_registry PASSED")


if __name__ == "__main__":
    test_analysis_requires_a_key()
    test_wrong_key_is_rejected()
    test_both_header_styles_work()
    test_key_comparison_is_constant_time_and_fails_closed()
    test_key_never_appears_in_its_fingerprint()
    test_rate_limit_blocks_the_caller_after_the_quota()
    test_rate_limit_window_resets()
    test_rate_limit_is_per_caller()
    test_oversized_content_is_rejected_before_any_analysis()
    test_empty_content_is_rejected_by_the_schema()
    test_passwords_cannot_be_requested_over_http()
    test_successful_analysis_returns_a_trust_report()
    test_every_response_carries_a_request_id()
    test_service_failures_map_to_useful_statuses()
    test_failures_never_leak_internals()
    test_health_is_open_and_says_nothing_secret()
    test_analyzers_are_listed_from_the_live_registry()
    print("ALL API TESTS PASSED")
