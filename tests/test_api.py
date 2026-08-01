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

# A throwaway database, so these tests never touch a real one.
import tempfile  # noqa: E402

_DB_HANDLE = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_DB_HANDLE.close()
os.environ["TUMAR_DB_PATH"] = _DB_HANDLE.name

from fastapi.testclient import TestClient  # noqa: E402

from api import corpus_store, keystore, main  # noqa: E402
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


# --- Issued keys, quota and metering, over HTTP ---


def test_an_issued_key_authenticates() -> None:
    issued = keystore.issue("Acme Bank", "production", path=main.settings.database_path)
    response = _client().post(
        "/v1/analyze",
        json={"content": "hello there"},
        headers={"Authorization": f"Bearer {issued.secret}"},
    )
    assert response.status_code == 200
    print("test_an_issued_key_authenticates PASSED")


def test_a_revoked_key_stops_working_over_http() -> None:
    issued = keystore.issue("Acme Bank", path=main.settings.database_path)
    headers = {"Authorization": f"Bearer {issued.secret}"}
    client = _client()
    assert client.post("/v1/analyze", json={"content": "hi"}, headers=headers).status_code == 200
    keystore.revoke(issued.record.id, main.settings.database_path)
    assert client.post("/v1/analyze", json={"content": "hi"}, headers=headers).status_code == 401
    print("test_a_revoked_key_stops_working_over_http PASSED")


def test_calls_are_metered_against_the_issued_key() -> None:
    issued = keystore.issue("Metered Co", path=main.settings.database_path)
    client = _client()
    for _ in range(3):
        client.post(
            "/v1/analyze",
            json={"content": "hello there"},
            headers={"Authorization": f"Bearer {issued.secret}"},
        )
    used = keystore.usage_this_month(
        issued.record.id, path=main.settings.database_path
    )
    assert used == 3
    print("test_calls_are_metered_against_the_issued_key PASSED")


def test_spent_quota_is_refused_before_the_ai_is_called() -> None:
    issued = keystore.issue(
        "Small Plan", monthly_quota=2, path=main.settings.database_path
    )
    headers = {"Authorization": f"Bearer {issued.secret}"}
    client = _client()
    for _ in range(2):
        assert client.post("/v1/analyze", json={"content": "hi"}, headers=headers).status_code == 200
    blocked = client.post("/v1/analyze", json={"content": "hi"}, headers=headers)
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "quota_exceeded"
    # A refused call is not billable, so the count must not move.
    assert keystore.usage_this_month(issued.record.id, path=main.settings.database_path) == 2
    print("test_spent_quota_is_refused_before_the_ai_is_called PASSED")


def test_failed_calls_are_recorded_but_not_billed() -> None:
    issued = keystore.issue("Acme", path=main.settings.database_path)
    client = _client(ServiceError("timeout"))
    response = client.post(
        "/v1/analyze",
        json={"content": "hello there"},
        headers={"Authorization": f"Bearer {issued.secret}"},
    )
    assert response.status_code == 504
    # Visible to support…
    summary = keystore.usage_summary(
        issued.record.id, path=main.settings.database_path
    )[0]
    assert summary["calls"] == 1
    # …but never charged to the customer.
    assert keystore.usage_this_month(issued.record.id, path=main.settings.database_path) == 0
    print("test_failed_calls_are_recorded_but_not_billed PASSED")


def test_analyze_runs_off_the_event_loop() -> None:
    # The endpoint does blocking work: an HTTP call to the AI provider
    # and a database write. Declared async, that would stall every
    # other request on the process while one provider call hangs.
    import inspect

    assert not inspect.iscoroutinefunction(main.analyze)
    print("test_analyze_runs_off_the_event_loop PASSED")


# --- Corpus contribution: opt-in, redacted, withdrawable ---


def test_nothing_is_contributed_unless_asked() -> None:
    """The default must be that we keep nothing."""
    issued = keystore.issue("Quiet Co", path=main.settings.database_path)
    response = _client().post(
        "/v1/analyze",
        json={"content": "URGENT! confirm your card at http://bad.xyz"},
        headers={"Authorization": f"Bearer {issued.secret}"},
    )
    assert response.status_code == 200
    assert response.json()["contributed"] is False
    assert corpus_store.for_key(issued.record.id, main.settings.database_path) == []
    print("test_nothing_is_contributed_unless_asked PASSED")


def test_opting_in_stores_a_redacted_sample() -> None:
    issued = keystore.issue("Sharing Co", path=main.settings.database_path)
    response = _client().post(
        "/v1/analyze",
        json={
            "content": "Card 4539578763621486 blocked, code 481920, "
            "go to http://kaspi-verify.xyz",
            "contribute": True,
        },
        headers={"Authorization": f"Bearer {issued.secret}"},
    )
    assert response.json()["contributed"] is True

    stored = corpus_store.for_key(
        issued.record.id, main.settings.database_path
    )[0].redacted_content
    assert "4539578763621486" not in stored
    assert "481920" not in stored
    assert "http://kaspi-verify.xyz" in stored  # the attack survives
    print("test_opting_in_stores_a_redacted_sample PASSED")


def test_a_contributor_can_read_back_exactly_what_we_hold() -> None:
    issued = keystore.issue("Transparent Co", path=main.settings.database_path)
    headers = {"Authorization": f"Bearer {issued.secret}"}
    client = _client()
    client.post(
        "/v1/analyze",
        json={"content": "URGENT! send the code now", "contribute": True},
        headers=headers,
    )
    body = client.get("/v1/contributions", headers=headers).json()
    assert body["count"] == 1
    assert body["consent_version"] == corpus_store.CONSENT_VERSION
    assert "redacted_content" in body["contributions"][0]
    print("test_a_contributor_can_read_back_exactly_what_we_hold PASSED")


def test_withdrawal_is_self_service_and_immediate() -> None:
    issued = keystore.issue("Leaving Co", path=main.settings.database_path)
    headers = {"Authorization": f"Bearer {issued.secret}"}
    client = _client()
    for _ in range(2):
        client.post(
            "/v1/analyze",
            json={"content": "URGENT! send the code now", "contribute": True},
            headers=headers,
        )
    deleted = client.delete("/v1/contributions", headers=headers).json()
    assert deleted["deleted"] == 2
    assert client.get("/v1/contributions", headers=headers).json()["count"] == 0
    print("test_withdrawal_is_self_service_and_immediate PASSED")


def test_contribution_endpoints_require_an_issued_key() -> None:
    client = _client()
    # A bootstrap key has no record, so there is nobody to attribute
    # samples to and nobody who could withdraw them.
    for method in (client.get, client.delete):
        assert method("/v1/contributions", headers=AUTH).status_code == 401
        assert method("/v1/contributions").status_code == 401
    print("test_contribution_endpoints_require_an_issued_key PASSED")


def test_bootstrap_keys_cannot_contribute() -> None:
    response = _client().post(
        "/v1/analyze",
        json={"content": "URGENT! send the code", "contribute": True},
        headers=AUTH,
    )
    assert response.status_code == 200
    assert response.json()["contributed"] is False
    print("test_bootstrap_keys_cannot_contribute PASSED")


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
    test_an_issued_key_authenticates()
    test_a_revoked_key_stops_working_over_http()
    test_calls_are_metered_against_the_issued_key()
    test_spent_quota_is_refused_before_the_ai_is_called()
    test_failed_calls_are_recorded_but_not_billed()
    test_analyze_runs_off_the_event_loop()
    test_nothing_is_contributed_unless_asked()
    test_opting_in_stores_a_redacted_sample()
    test_a_contributor_can_read_back_exactly_what_we_hold()
    test_withdrawal_is_self_service_and_immediate()
    test_contribution_endpoints_require_an_issued_key()
    test_bootstrap_keys_cannot_contribute()
    test_analyzers_are_listed_from_the_live_registry()
    print("ALL API TESTS PASSED")
