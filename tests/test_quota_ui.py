"""The web app's quota gate (quota_ui.py), run in Streamlit's AppTest.

A guest with a daily limit of 1 gets the first check and a translated
warning on the second; password checks are never counted.

    venv\\Scripts\\python.exe tests\\test_quota_ui.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from streamlit.testing.v1 import AppTest  # noqa: E402


def _app() -> None:
    import sys as _sys

    import streamlit as st

    _sys.path.insert(0, st.session_state["root"])  # AppTest runs the function standalone
    import quota_ui

    results = [quota_ui.allow_check(kind) for kind in st.session_state["kinds"]]
    st.session_state["results"] = results


def _run(kinds: list[str]) -> AppTest:
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["root"] = str(ROOT)
    at.session_state["kinds"] = kinds
    return at.run()


def test_guest_gets_a_warning_after_the_limit() -> None:
    os.environ["TUMAR_DAILY_LIMIT_GUEST"] = "1"
    import services.quota as quota_module

    quota_module._default = None
    try:
        at = _run(["message", "url", "password"])
        assert not at.exception, at.exception
        assert at.session_state["results"] == [True, False, True], at.session_state["results"]
        warnings = [w.value for w in at.warning]
        assert len(warnings) == 1 and "1" in warnings[0] and "00:00 UTC" in warnings[0], warnings
    finally:
        os.environ.pop("TUMAR_DAILY_LIMIT_GUEST", None)
        quota_module._default = None
    print("test_guest_gets_a_warning_after_the_limit PASSED")


if __name__ == "__main__":
    test_guest_gets_a_warning_after_the_limit()
    print("All quota UI tests passed.")
