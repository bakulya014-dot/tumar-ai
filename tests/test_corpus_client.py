"""Tests for sending contributions to a remote Tumar.AI API.

No network: `requests` is replaced with a stub, so these run offline
and assert on what would have been sent.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_corpus_client.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import corpus_client
from services.corpus_client import RemoteCorpus


class _Response:
    def __init__(self, status_code: int, payload=None, bad_json: bool = False):
        self.status_code = status_code
        self._payload = payload or {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class _Recorder:
    """Stands in for requests, remembering the last call."""

    def __init__(self, response=None, raises: Exception | None = None):
        self.response = response or _Response(200, {"stored": True})
        self.raises = raises
        self.last: dict = {}

    def post(self, url, headers=None, json=None, timeout=None):
        self.last = {"url": url, "headers": headers, "json": json, "timeout": timeout}
        if self.raises:
            raise self.raises
        return self.response

    def delete(self, url, headers=None, params=None, timeout=None):
        self.last = {"url": url, "headers": headers, "params": params, "timeout": timeout}
        if self.raises:
            raise self.raises
        return self.response


def _with_stub(recorder: _Recorder):
    """Swap the module's requests for a recorder, keeping exceptions."""
    recorder.exceptions = corpus_client.requests.exceptions
    corpus_client.requests = recorder
    return recorder


def _restore() -> None:
    import requests

    corpus_client.requests = requests


def test_client_is_unconfigured_without_both_url_and_key() -> None:
    assert not RemoteCorpus("", "").configured
    assert not RemoteCorpus("https://api.example.com", "").configured
    assert not RemoteCorpus("", "tmr_live_x").configured
    assert RemoteCorpus("https://api.example.com", "tmr_live_x").configured
    print("test_client_is_unconfigured_without_both_url_and_key PASSED")


def test_submit_sends_the_sample_and_authenticates() -> None:
    recorder = _with_stub(_Recorder())
    try:
        stored = RemoteCorpus("https://api.example.com/", "tmr_live_secret").submit(
            content="URGENT! send the code",
            kind="message",
            language="ru",
            verdict="danger",
            confidence=95,
            session_id="sess-1",
        )
        assert stored is True
        assert recorder.last["url"] == "https://api.example.com/v1/contributions"
        assert recorder.last["headers"]["Authorization"] == "Bearer tmr_live_secret"
        assert recorder.last["json"]["session_id"] == "sess-1"
        assert recorder.last["json"]["language"] == "ru"
        # A hung request must not hang the page.
        assert recorder.last["timeout"] == corpus_client.REQUEST_TIMEOUT_S
    finally:
        _restore()
    print("test_submit_sends_the_sample_and_authenticates PASSED")


def test_a_refused_sample_reports_false() -> None:
    recorder = _with_stub(_Recorder(_Response(200, {"stored": False})))
    try:
        assert (
            RemoteCorpus("https://api.example.com", "k").submit(
                "x", "message", "en", "safe", 50, "s"
            )
            is False
        )
    finally:
        _restore()
    print("test_a_refused_sample_reports_false PASSED")


def test_network_failure_fails_soft() -> None:
    """A contribution is a favour; our outage must not break the page."""
    import requests as real_requests

    recorder = _with_stub(
        _Recorder(raises=real_requests.exceptions.ConnectionError("down"))
    )
    try:
        assert (
            RemoteCorpus("https://api.example.com", "k").submit(
                "x", "message", "en", "safe", 50, "s"
            )
            is False
        )
        assert RemoteCorpus("https://api.example.com", "k").withdraw("s") == 0
    finally:
        _restore()
    print("test_network_failure_fails_soft PASSED")


def test_error_status_and_bad_json_fail_soft() -> None:
    for response in (_Response(500), _Response(401), _Response(200, bad_json=True)):
        _with_stub(_Recorder(response))
        try:
            assert (
                RemoteCorpus("https://api.example.com", "k").submit(
                    "x", "message", "en", "safe", 50, "s"
                )
                is False
            )
        finally:
            _restore()
    print("test_error_status_and_bad_json_fail_soft PASSED")


def test_withdraw_passes_the_session_and_returns_the_count() -> None:
    recorder = _with_stub(_Recorder(_Response(200, {"deleted": 3})))
    try:
        assert RemoteCorpus("https://api.example.com", "k").withdraw("sess-9") == 3
        assert recorder.last["params"] == {"session_id": "sess-9"}
    finally:
        _restore()
    print("test_withdraw_passes_the_session_and_returns_the_count PASSED")


if __name__ == "__main__":
    test_client_is_unconfigured_without_both_url_and_key()
    test_submit_sends_the_sample_and_authenticates()
    test_a_refused_sample_reports_false()
    test_network_failure_fails_soft()
    test_error_status_and_bad_json_fail_soft()
    test_withdraw_passes_the_session_and_returns_the_count()
    print("ALL CORPUS CLIENT TESTS PASSED")
