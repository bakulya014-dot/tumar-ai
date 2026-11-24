"""Home first run, training examples, session-only feedback, honest wording.

    venv\\Scripts\\python.exe tests\\test_home_feedback.py
"""

import json
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import auth  # noqa: E402
import feedback_ui  # noqa: E402
from i18n import LANGUAGES, _load, translate  # noqa: E402
from services.offline_report import offline_message_report  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

EXAMPLES = ("bank", "delivery", "job")


def _app(state: dict | None = None) -> AppTest:
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.session_state["tumar_guest"] = True
    for key, value in (state or {}).items():
        at.session_state[key] = value
    return at


def _signed_out():
    return (
        patch.object(auth, "is_signed_in", return_value=False),
        patch.object(auth, "user_display", return_value=("", "")),
        patch.object(auth, "record_registration", return_value=None),
        patch("services.scam_analysis.text_provider", return_value=None),
        patch("components.get_gemini_api_key", return_value=""),
    )


def test_training_examples_exist_and_look_like_scams() -> None:
    for language in LANGUAGES:
        keys = _load(language)
        for name in EXAMPLES:
            assert keys.get(f"home.train.{name}") and keys.get(f"home.train_button.{name}"), (language, name)
        assert keys.get("home.train_label") and keys.get("home.main_action")
        # The bank example must be flagged by the rules alone, in every language.
        bank = offline_message_report(translate("home.train.bank", language), "test")
        assert bank.verdict == "danger", (language, bank.verdict)
        delivery = offline_message_report(translate("home.train.delivery", language), "test")
        assert {"url_no_https", "url_suspicious_tld"} <= {e.code for e in delivery.evidence}, language
    print("test_training_examples_exist_and_look_like_scams PASSED")


def test_home_leads_with_one_action_and_labels_examples() -> None:
    at = _app()
    a, b, c, d, e = _signed_out()
    with a, b, c, d, e:
        at.run()
        assert not at.exception, at.exception
        headers = " ".join(h.value for h in at.subheader)
        assert translate("home.main_action", "en") in headers
        assert not any(translate("home.train_label", "en") in i.value for i in at.info)  # nothing loaded yet
        next(btn for btn in at.button if btn.label == translate("home.train_button.delivery", "en")).click().run()
    assert at.text_area(key="quick_input").value == translate("home.train.delivery", "en")
    assert any(translate("home.train_label", "en") in i.value for i in at.info)  # labelled as fictional
    print("test_home_leads_with_one_action_and_labels_examples PASSED")


def _checked_example(at: AppTest, example: str, language: str = "en") -> None:
    next(btn for btn in at.button if btn.label == translate(f"home.train_button.{example}", language)).click().run()
    next(btn for btn in at.button if btn.label == translate("home.quick_button", language)).click().run()


def test_feedback_is_kept_in_the_session_without_message_content() -> None:
    at = _app()
    a, b, c, d, e = _signed_out()
    with a, b, c, d, e:
        at.run()
        _checked_example(at, "job")
        assert not at.exception, at.exception
        report_id = at.session_state["trust_history"][0].report_id
        helpful = at.get("button_group")
        assert helpful, "feedback questions are shown under the result"
        helpful[0].set_value("yes").run()
        at.get("button_group")[1].set_value("unsure").run()
        missed = next(btn for btn in at.button if btn.label == translate("feedback.missed_button", "en"))
        missed.click().run()
    assert not at.exception, at.exception
    saved = at.session_state[feedback_ui.STORE][report_id]
    assert saved == {"helpful": "yes", "was_scam": "unsure", "missed": "yes"}, saved
    text = translate("home.train.job", "en")
    assert text not in json.dumps(at.session_state[feedback_ui.STORE])  # no message content stored
    assert any(translate("feedback.missed_thanks", "en") in s.value for s in at.success)
    assert any(translate("feedback.privacy", "en") in cap.value for cap in at.caption)
    print("test_feedback_is_kept_in_the_session_without_message_content PASSED")


def test_missed_scam_is_not_offered_on_a_danger_result() -> None:
    at = _app()
    a, b, c, d, e = _signed_out()
    with a, b, c, d, e:
        at.run()
        _checked_example(at, "bank")
    assert at.session_state["trust_history"][0].verdict == "danger"
    assert not any(btn.label == translate("feedback.missed_button", "en") for btn in at.button)
    print("test_missed_scam_is_not_offered_on_a_danger_result PASSED")


def test_clearing_the_session_removes_feedback() -> None:
    at = _app({feedback_ui.STORE: {"abc": {"helpful": "no"}}})
    a, b, c, d, e = _signed_out()
    with a, b, c, d, e:
        at.run()
        at.switch_page("views/settings.py")
        at.run()
        next(btn for btn in at.button if btn.label == translate("settings.clear_button", "en")).click().run()
    assert feedback_ui.STORE not in at.session_state
    print("test_clearing_the_session_removes_feedback PASSED")


def test_every_result_carries_the_bank_note() -> None:
    at = _app()
    a, b, c, d, e = _signed_out()
    with a, b, c, d, e:
        at.run()
        _checked_example(at, "delivery")
    assert any(translate("trust.bank_note", "en") in cap.value for cap in at.caption)
    print("test_every_result_carries_the_bank_note PASSED")


_ABSOLUTE = re.compile(r"100\s?%\s*(?:safe|secure|guaranteed|безопас|надёжн|надежн|гарант|қауіпсіз|кепіл)", re.IGNORECASE)


def test_rules_only_result_with_no_findings_names_the_right_method() -> None:
    # Seen in the browser: the fictional job example matched no rule offline,
    # and the footer said "Method: Breach database".
    import report_view

    report = offline_message_report("Hello, see you tomorrow at the library.", "missing_key")
    assert not report.evidence
    assert report_view._method_keys(report) == ["trust.evidence_scanner"]
    print("test_rules_only_result_with_no_findings_names_the_right_method PASSED")


def test_nothing_claims_to_be_100_percent_safe() -> None:
    for language in LANGUAGES:
        bad = {key: value for key, value in _load(language).items() if _ABSOLUTE.search(value)}
        assert not bad, (language, bad)
    for path in [*ROOT.joinpath("services").rglob("*.py"), *ROOT.joinpath("views").glob("*.py"), *ROOT.joinpath("prompts").glob("*.md")]:
        assert not _ABSOLUTE.search(path.read_text(encoding="utf-8")), path
    print("test_nothing_claims_to_be_100_percent_safe PASSED")


def test_feedback_strings_exist_in_every_language() -> None:
    needed = {f"feedback.{q}" for q in ("helpful", "was_scam", "missed_button", "missed_thanks", "thanks", "privacy")}
    needed |= {f"feedback.option.{o}" for o in set(feedback_ui.HELPFUL) | set(feedback_ui.WAS_SCAM)}
    needed.add("trust.bank_note")
    for language in LANGUAGES:
        missing = [k for k in needed if not _load(language).get(k)]
        assert not missing, (language, missing)
    print("test_feedback_strings_exist_in_every_language PASSED")


if __name__ == "__main__":
    test_training_examples_exist_and_look_like_scams()
    test_home_leads_with_one_action_and_labels_examples()
    test_feedback_is_kept_in_the_session_without_message_content()
    test_missed_scam_is_not_offered_on_a_danger_result()
    test_clearing_the_session_removes_feedback()
    test_every_result_carries_the_bank_note()
    test_rules_only_result_with_no_findings_names_the_right_method()
    test_nothing_claims_to_be_100_percent_safe()
    test_feedback_strings_exist_in_every_language()
    print("All home and feedback tests passed.")
