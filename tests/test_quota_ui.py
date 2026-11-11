"""The web app's quota gate (quota_ui.py), run in Streamlit's AppTest.

Guests are counted per browser session by default (each AppTest run is
a new session), and all guests together draw from a shared daily pool
that caps total cost. Password checks are never counted.

    venv\\Scripts\\python.exe tests\\test_quota_ui.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import services.quota as quota_module  # noqa: E402
from i18n import translate  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402


def _app() -> None:
    import sys as _sys

    import streamlit as st

    _sys.path.insert(0, st.session_state["root"])  # AppTest runs the function standalone
    import quota_ui

    st.session_state["results"] = [quota_ui.allow_check(kind) for kind in st.session_state["kinds"]]


def _session(kinds: list[str]) -> AppTest:
    """One fresh browser session that runs the given checks in order."""
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["root"] = str(ROOT)
    at.session_state["kinds"] = kinds
    at.run()
    assert not at.exception, at.exception
    return at


class _Env:
    def __init__(self, **values: str):
        self.values, self.saved = values, {}

    def __enter__(self):
        for name, value in self.values.items():
            self.saved[name] = os.environ.get(name)
            os.environ[name] = value
        quota_module._default = None  # fresh counters for each scenario
        return self

    def __exit__(self, *exc):
        for name, old in self.saved.items():
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old
        quota_module._default = None


def test_guest_gets_a_warning_after_the_limit() -> None:
    with _Env(TUMAR_DAILY_LIMIT_GUEST="1"):
        at = _session(["message", "url", "password"])
        assert at.session_state["results"] == [True, False, True], at.session_state["results"]
        warnings = [w.value for w in at.warning]
        assert warnings == [translate("quota.exceeded_guest", "en", limit=1)], warnings
    print("test_guest_gets_a_warning_after_the_limit PASSED")


def test_each_guest_session_has_its_own_allowance() -> None:
    # Behind a hosting proxy every guest can share one IP; per-session
    # counting keeps one guest from using up everyone's allowance.
    with _Env(TUMAR_DAILY_LIMIT_GUEST="1"):
        first, second = _session(["message"]), _session(["message"])
        assert first.session_state["results"] == [True]
        assert second.session_state["results"] == [True]
    print("test_each_guest_session_has_its_own_allowance PASSED")


def test_shared_guest_pool_caps_total_use() -> None:
    with _Env(TUMAR_DAILY_LIMIT_GUEST="5", TUMAR_DAILY_LIMIT_GUEST_POOL="2"):
        first = _session(["message", "url"])
        second = _session(["message"])
        assert first.session_state["results"] == [True, True]
        assert second.session_state["results"] == [False]
        assert [w.value for w in second.warning] == [translate("quota.exceeded_pool", "en")]
    print("test_shared_guest_pool_caps_total_use PASSED")


def test_ip_mode_falls_back_to_session_without_an_ip() -> None:
    with _Env(TUMAR_GUEST_QUOTA_KEY="ip", TUMAR_DAILY_LIMIT_GUEST="1"):
        at = _session(["message", "message"])  # AppTest has no client IP
        assert at.session_state["results"] == [True, False]
    print("test_ip_mode_falls_back_to_session_without_an_ip PASSED")


def _settle_app() -> None:
    import sys as _sys

    import streamlit as st

    _sys.path.insert(0, st.session_state["root"])
    import quota_ui
    from services.offline_report import offline_message_report

    offline = offline_message_report("Send me the SMS code", "timeout")
    results = []
    for _ in range(3):  # limit 1: each check is refunded, so all three run
        results.append(quota_ui.allow_check("message"))
        quota_ui.settle("message", offline)
    results.append(quota_ui.allow_check("message"))
    quota_ui.settle("message", failed=True)
    results.append(quota_ui.allow_check("message"))  # refunded again
    results.append(quota_ui.allow_check("message"))  # a real, counted check → over
    st.session_state["results"] = results


def test_failed_and_offline_checks_are_refunded() -> None:
    with _Env(TUMAR_DAILY_LIMIT_GUEST="1", TUMAR_DAILY_LIMIT_GUEST_POOL="1"):
        at = AppTest.from_function(_settle_app, default_timeout=60)
        at.session_state["root"] = str(ROOT)
        at.run()
        assert not at.exception, at.exception
        assert at.session_state["results"] == [True, True, True, True, True, False], at.session_state["results"]
    print("test_failed_and_offline_checks_are_refunded PASSED")


if __name__ == "__main__":
    test_failed_and_offline_checks_are_refunded()
    test_guest_gets_a_warning_after_the_limit()
    test_each_guest_session_has_its_own_allowance()
    test_shared_guest_pool_caps_total_use()
    test_ip_mode_falls_back_to_session_without_an_ip()
    print("All quota UI tests passed.")
