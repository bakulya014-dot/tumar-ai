"""My Safety Center: snapshot figures, actions, and the page itself.

    venv\\Scripts\\python.exe tests\\test_safety_center.py
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import auth  # noqa: E402
from i18n import translate  # noqa: E402
from services import safety_center  # noqa: E402
from services.trust_report import TrustReport  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

en = lambda key: translate(key, "en")  # noqa: E731


def _report(verdict: str, trust: int, actions=None, keys=None) -> TrustReport:
    return TrustReport(
        source="scam_analyzer", subject_type="message", subject_preview="test message",
        verdict=verdict, trust_score=trust, confidence=70,
        recommended_actions=actions or [], recommended_action_keys=keys or [],
    )


def test_empty_session_has_no_made_up_score() -> None:
    snap = safety_center.snapshot([])
    assert snap.status == "empty" and snap.safety_score is None and snap.checks == 0
    print("test_empty_session_has_no_made_up_score PASSED")


def test_snapshot_figures() -> None:
    reports = [_report("danger", 10), _report("caution", 50), _report("safe", 90)]  # newest first
    snap = safety_center.snapshot(reports)
    assert (snap.checks, snap.dangerous, snap.cautious) == (3, 1, 1)
    assert snap.safety_score == 50 and snap.status == "act"
    assert snap.trend == [90, 50, 10]  # oldest first for the chart
    assert safety_center.snapshot([_report("caution", 40)]).status == "watch"
    assert safety_center.snapshot([_report("safe", 95)]).status == "calm"
    print("test_snapshot_figures PASSED")


def test_top_actions_prefer_dangerous_then_fill_with_defaults() -> None:
    reports = [
        _report("caution", 50, actions=["Verify with the bank"]),
        _report("danger", 5, actions=["Do not open the link", "Block the sender"]),
        _report("safe", 95, actions=["Ignore this"]),
    ]
    assert safety_center.top_actions(reports, en) == [
        "Do not open the link", "Block the sender", "Verify with the bank",
    ]
    only_safe = safety_center.top_actions([_report("safe", 95, actions=["x"])], en)
    assert only_safe == [en(k) for k in safety_center.DEFAULT_ACTION_KEYS]
    keyed = safety_center.top_actions([_report("danger", 5, keys=["center.default_action_3"])], en)
    assert keyed[0] == en("center.default_action_3") and len(set(keyed)) == 3  # no repeats
    print("test_top_actions_prefer_dangerous_then_fill_with_defaults PASSED")


def _page(history=None, signed_in: bool = True) -> AppTest:
    """Open My Safety Center through app.py, as a signed-in user reaches it."""
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    if history is not None:
        at.session_state["trust_history"] = history
    with patch.object(auth, "is_signed_in", return_value=signed_in),             patch.object(auth, "user_display", return_value=("Aru", "aru@example.com")),             patch.object(auth, "record_registration", return_value=None):
        at.run()
        at.switch_page("views/safety_center.py")
        at.run()
    assert not at.exception, at.exception
    return at


def test_page_empty_state() -> None:
    at = _page()
    text = "\n".join(m.value for m in at.markdown)
    assert en("center.empty_title") in text
    print("test_page_empty_state PASSED")


def test_page_with_a_dangerous_check() -> None:
    import report_store

    state: dict = {}
    report_store.remember(state, _report("safe", 90))
    report_store.remember(state, _report("danger", 8, actions=["Do not open the link"]))
    at = _page(state["trust_history"])
    text = "\n".join(m.value for m in at.markdown)
    assert en("center.status_act") in text and "Do not open the link" in text
    assert en("center.danger_title") in "\n".join(s.value for s in at.subheader)
    print("test_page_with_a_dangerous_check PASSED")


def test_menu_entry_only_for_signed_in_users() -> None:
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "views/safety_center.py" in source and "if _signed_in" in source
    # A guest asking for the page by URL is not given it: st.navigation
    # only knows the pages registered for this visitor.
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.session_state["tumar_guest"] = True
    with patch.object(auth, "is_signed_in", return_value=False),             patch.object(auth, "user_display", return_value=("", "")),             patch.object(auth, "record_registration", return_value=None):
        at.run()
        try:
            at.switch_page("views/safety_center.py")
            at.run()
        except Exception:
            pass  # refused outright is also acceptable
    text = "\n".join(m.value for m in at.markdown)
    assert en("center.scope") not in text, "guest reached My Safety Center"
    print("test_menu_entry_only_for_signed_in_users PASSED")

if __name__ == "__main__":
    test_empty_session_has_no_made_up_score()
    test_snapshot_figures()
    test_top_actions_prefer_dangerous_then_fill_with_defaults()
    test_page_empty_state()
    test_page_with_a_dangerous_check()
    test_menu_entry_only_for_signed_in_users()
    print("All Safety Center tests passed.")
