"""Offline tests for report_store.py (no Streamlit needed).

The store takes its state container as an argument, so a plain dict
stands in for st.session_state here — which is exactly why the store
was designed that way.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_report_store.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import report_store
from services.trust_report import TrustReport


def _report(source: str, score: int = 50) -> TrustReport:
    return TrustReport(
        source=source,
        subject_type="message",
        subject_preview=f"{source}-{score}",
        verdict="caution",
        trust_score=score,
        confidence=60,
    )


def test_latest_returns_newest_first() -> None:
    state: dict = {}
    report_store.remember(state, _report("scam_analyzer", 10))
    report_store.remember(state, _report("url_scanner", 20))
    newest = report_store.latest(state)
    assert newest is not None and newest.source == "url_scanner"
    print("test_latest_returns_newest_first PASSED")


def test_latest_filters_by_source() -> None:
    # This is what fixes the "result vanishes on re-run" defect: each
    # page re-reads ITS own last report on every script re-run.
    state: dict = {}
    report_store.remember(state, _report("scam_analyzer", 10))
    report_store.remember(state, _report("url_scanner", 20))
    scam = report_store.latest(state, "scam_analyzer")
    assert scam is not None and scam.trust_score == 10
    assert report_store.latest(state, "breach_checker") is None
    print("test_latest_filters_by_source PASSED")


def test_empty_state_has_no_latest() -> None:
    assert report_store.latest({}) is None
    assert report_store.history({}) == []
    print("test_empty_state_has_no_latest PASSED")


def test_history_is_bounded() -> None:
    # Unbounded growth would be a slow memory leak per session.
    state: dict = {}
    for index in range(report_store.MAX_HISTORY + 7):
        report_store.remember(state, _report("scam_analyzer", index % 101))
    assert len(report_store.history(state)) == report_store.MAX_HISTORY
    print("test_history_is_bounded PASSED")


def test_clear_forgets_everything() -> None:
    state: dict = {}
    report_store.remember(state, _report("scam_analyzer"))
    report_store.clear(state)
    assert report_store.history(state) == []
    assert report_store.latest(state) is None
    print("test_clear_forgets_everything PASSED")


def test_no_shared_state_between_sessions() -> None:
    # Two dicts stand in for two visitors: one user's analysis must
    # never be visible in another user's session.
    first: dict = {}
    second: dict = {}
    report_store.remember(first, _report("scam_analyzer"))
    assert report_store.history(second) == []
    print("test_no_shared_state_between_sessions PASSED")


if __name__ == "__main__":
    test_latest_returns_newest_first()
    test_latest_filters_by_source()
    test_empty_state_has_no_latest()
    test_history_is_bounded()
    test_clear_forgets_everything()
    test_no_shared_state_between_sessions()
    print("ALL REPORT STORE TESTS PASSED")
