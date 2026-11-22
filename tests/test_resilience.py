"""Personal Cyber Resilience Score: transparent factors, honest limits, the page.

    venv\\Scripts\\python.exe tests\\test_resilience.py
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import auth  # noqa: E402
import report_store  # noqa: E402
from i18n import LANGUAGES, _load, translate  # noqa: E402
from services import resilience  # noqa: E402
from services.trust_report import TrustReport  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

NO_2FA = {item: False for item in resilience.TWO_FACTOR_ITEMS}
ALL_2FA = {item: True for item in resilience.TWO_FACTOR_ITEMS}


def _r(kind="message", verdict="danger") -> TrustReport:
    return TrustReport(source=kind, subject_type=kind, subject_preview="x", verdict=verdict,
                       trust_score=10 if verdict == "danger" else 90, confidence=70)


def _score(reports, two_factor=NO_2FA, handled=frozenset()):
    return resilience.score(resilience.factors(reports, two_factor, set(handled)))


def test_score_is_the_visible_sum_of_factors() -> None:
    assert _score([]) == resilience.BASE  # nothing checked yet: just the starting point
    factors = resilience.factors([_r()], NO_2FA, set())
    assert resilience.score(factors) == sum(f.points for f in factors if f.active) == 60 - 12 + 4
    print("test_score_is_the_visible_sum_of_factors PASSED")


def test_score_never_reaches_100() -> None:
    best = [_r("message", "safe"), _r("email", "safe"), _r("password", "safe")]
    assert _score(best, ALL_2FA) == 90  # the ceiling: no score promises full safety
    worst = [_r(), _r(), _r(), _r("email", "danger"), _r("password", "danger")]
    assert 0 <= _score(worst) < resilience.BASE
    print("test_score_never_reaches_100 PASSED")


def test_dealing_with_a_finding_raises_the_score_and_explains_why() -> None:
    finding = _r()
    before = resilience.factors([finding], NO_2FA, set())
    after = resilience.factors([finding], NO_2FA, {resilience.report_id(finding)})
    assert resilience.score(after) - resilience.score(before) == 12
    assert resilience.changes(before, after) == [("dangerous_open", 12)]
    assert resilience.changes(None, after) == []  # first view: nothing "changed"
    print("test_dealing_with_a_finding_raises_the_score_and_explains_why PASSED")


def test_top_steps_biggest_gain_first() -> None:
    steps = resilience.top_steps([_r(), _r("email", "danger")], NO_2FA, set())
    assert [s.key for s in steps] == ["deal_dangerous", "change_breached", "two_factor"]
    assert steps[0].gain == 12
    done = resilience.top_steps([_r("email", "safe")], ALL_2FA, set())
    assert all(s.key != "two_factor" for s in done)
    print("test_top_steps_biggest_gain_first PASSED")


def test_every_resilience_string_exists() -> None:
    keys = {f"resilience.factor.{f.key}" for f in resilience.factors([], NO_2FA, set())}
    keys |= {f"resilience.step.{k}" for k in ("deal_dangerous", "change_breached", "replace_weak", "two_factor", "check_first", "check_email")}
    keys |= {f"resilience.checklist.{i}" for i in resilience.TWO_FACTOR_ITEMS} | {f"resilience.item.{i}" for i in resilience.TWO_FACTOR_ITEMS}
    keys |= {"resilience.no_guarantee", "resilience.dealt_with", "resilience.how_note"}
    for language in LANGUAGES:
        missing = sorted(keys - set(_load(language)))
        assert not missing, (language, missing)
    print("test_every_resilience_string_exists PASSED")


def _open_center(at: AppTest) -> None:
    with patch.object(auth, "is_signed_in", return_value=True), \
            patch.object(auth, "user_display", return_value=("Aru", "aru@example.com")), \
            patch.object(auth, "record_registration", return_value=None):
        at.switch_page("views/safety_center.py")
        at.run()
    assert not at.exception, at.exception


def test_page_checklist_survives_leaving_the_page() -> None:
    state: dict = {}
    report_store.remember(state, _r())
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.session_state["trust_history"] = state["trust_history"]
    with patch.object(auth, "is_signed_in", return_value=True), \
            patch.object(auth, "user_display", return_value=("Aru", "aru@example.com")), \
            patch.object(auth, "record_registration", return_value=None):
        at.run()
    _open_center(at)
    score_text = lambda: "\n".join(m.value for m in at.markdown)  # noqa: E731
    assert "52" in score_text()  # 60 - 12 + 4
    email_box = next(c for c in at.checkbox if c.label == translate("resilience.checklist.email", "en"))
    with patch.object(auth, "is_signed_in", return_value=True), \
            patch.object(auth, "user_display", return_value=("Aru", "aru@example.com")), \
            patch.object(auth, "record_registration", return_value=None):
        email_box.check().run()
        at.switch_page("views/home.py")
        at.run()
    _open_center(at)  # back again: the tick must still count
    assert "58" in score_text(), score_text()[:400]
    print("test_page_checklist_survives_leaving_the_page PASSED")


if __name__ == "__main__":
    test_score_is_the_visible_sum_of_factors()
    test_score_never_reaches_100()
    test_dealing_with_a_finding_raises_the_score_and_explains_why()
    test_top_steps_biggest_gain_first()
    test_every_resilience_string_exists()
    test_page_checklist_survives_leaving_the_page()
    print("All resilience tests passed.")
