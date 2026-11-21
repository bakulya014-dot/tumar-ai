"""Who sees what: landing for visitors, workspace for signed-in users and guests.

Runs the real app.py in Streamlit's AppTest. Google login is simulated
by patching auth.is_signed_in / auth.user_display (st.user cannot be set
from a test); everything else is the production code path.

    venv\\Scripts\\python.exe tests\\test_routing.py
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import auth  # noqa: E402
import routing  # noqa: E402
from i18n import translate  # noqa: E402
from services import telemetry  # noqa: E402
from streamlit.runtime.scriptrunner_utils.exceptions import StopException  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(ROOT / "app.py")


def _run(signed_in: bool = False, guest: bool = False, email: str = "") -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    if guest:
        at.session_state["tumar_guest"] = True
    with patch.object(auth, "is_signed_in", return_value=signed_in), \
            patch.object(auth, "user_display", return_value=("Aru", email)), \
            patch.object(auth, "record_registration", return_value=None):
        at.run()
    assert not at.exception, at.exception
    return at


def _markdown(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def _buttons(at: AppTest) -> list[str]:
    return [b.label for b in at.button]


def test_visitor_sees_only_the_landing_page() -> None:
    at = _run()
    assert 'class="l-hero"' in _markdown(at)
    labels = _buttons(at)
    assert translate("landing.cta_google", "en") in labels
    assert translate("account.sign_out", "en") not in labels  # no workspace chrome
    print("test_visitor_sees_only_the_landing_page PASSED")


def test_signed_in_user_reaches_the_workspace() -> None:
    at = _run(signed_in=True, email="aru@example.com")
    assert 'class="l-hero"' not in _markdown(at)
    labels = _buttons(at)
    assert translate("account.sign_out", "en") in labels
    assert translate("landing.cta_google", "en") not in labels
    assert translate("account.delete_confirm", "en") in labels  # signed-in only
    print("test_signed_in_user_reaches_the_workspace PASSED")


def test_guest_reaches_the_workspace_without_account_actions() -> None:
    at = _run(guest=True)
    assert 'class="l-hero"' not in _markdown(at)
    labels = _buttons(at)
    assert translate("account.sign_out", "en") in labels
    assert translate("account.delete_confirm", "en") not in labels  # nothing to delete
    print("test_guest_reaches_the_workspace_without_account_actions PASSED")


def test_login_state_survives_a_rerun() -> None:
    # A rerun (any click, or a refresh restoring the login cookie) must
    # not drop a signed-in user back to the landing page.
    at = AppTest.from_file(APP, default_timeout=60)
    with patch.object(auth, "is_signed_in", return_value=True), \
            patch.object(auth, "user_display", return_value=("Aru", "aru@example.com")), \
            patch.object(auth, "record_registration", return_value=None):
        at.run()
        at.run()
    assert not at.exception and 'class="l-hero"' not in _markdown(at)
    print("test_login_state_survives_a_rerun PASSED")


def test_sign_out_logs_out_only_when_signed_in() -> None:
    calls = []
    state = {"tumar_guest": True}
    with patch.object(auth.st, "session_state", state), \
            patch.object(auth.st, "logout", side_effect=lambda: calls.append("logout")):
        with patch.object(auth, "is_signed_in", return_value=True):
            auth.sign_out()
        with patch.object(auth, "is_signed_in", return_value=False):
            auth.sign_out()
    assert calls == ["logout"], calls  # never called for a guest
    assert "tumar_guest" not in state
    print("test_sign_out_logs_out_only_when_signed_in PASSED")


def test_crash_guard_shows_a_message_and_lets_control_flow_pass() -> None:
    shown = []
    with patch.object(routing, "error_view", side_effect=lambda m: shown.append(m)):
        routing.run_page(SimpleNamespace(url_path="scam_analyzer", run=lambda: 1 / 0))
    assert shown == [translate("errors.unexpected", "en")], shown

    def stop():
        raise StopException()

    try:
        routing.run_page(SimpleNamespace(url_path="x", run=stop))
    except StopException:
        pass  # st.stop() must still stop the script
    else:
        raise AssertionError("StopException was swallowed")
    print("test_crash_guard_shows_a_message_and_lets_control_flow_pass PASSED")


def test_route_events_are_content_free_and_deduplicated() -> None:
    telemetry.metrics.reset()
    state: dict = {}
    with patch.object(routing.st, "session_state", state):
        routing.log_route("home", True, False)
        routing.log_route("home", True, False)  # a rerun: not logged again
        routing.log_route("scam_analyzer", True, False)
    counts = telemetry.metrics.summary()["counts"]
    assert counts.get("route:seen") == 2, counts
    record = telemetry.sanitize({"route": "home", "signed_in": True, "guest": False})
    assert record == {"route": "home", "signed_in": True, "guest": False}
    print("test_route_events_are_content_free_and_deduplicated PASSED")


if __name__ == "__main__":
    test_visitor_sees_only_the_landing_page()
    test_signed_in_user_reaches_the_workspace()
    test_guest_reaches_the_workspace_without_account_actions()
    test_login_state_survives_a_rerun()
    test_sign_out_logs_out_only_when_signed_in()
    test_crash_guard_shows_a_message_and_lets_control_flow_pass()
    test_route_events_are_content_free_and_deduplicated()
    print("All routing tests passed.")
