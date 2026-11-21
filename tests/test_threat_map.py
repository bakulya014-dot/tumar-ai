"""Threat Map prototype and the Safety Report's new blocks.

    venv\\Scripts\\python.exe tests\\test_threat_map.py
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
import report_view  # noqa: E402
from i18n import LANGUAGES, _load, translate  # noqa: E402
from services import threat_map_demo as demo  # noqa: E402
from services.trust_report import Evidence, TrustReport  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402


def _report(verdict="danger", preview="Your card is blocked", kind="message", evidence=()) -> TrustReport:
    return TrustReport(
        source="scam_analyzer", subject_type=kind, subject_preview=preview,
        verdict=verdict, trust_score=10 if verdict == "danger" else 90, confidence=70,
        evidence=list(evidence),
    )


def test_demo_data_is_consistent_and_flagged() -> None:
    assert demo.IS_SIMULATED is True
    national, regions = demo.national_counts(), demo.region_counts()
    for category in demo.CATEGORIES:
        assert national[category] == sum(regions[r][category] for r in demo.REGIONS)
    print("test_demo_data_is_consistent_and_flagged PASSED")


def test_categorize_the_users_last_check() -> None:
    assert demo.categorize(_report(verdict="safe")) is None
    assert demo.categorize(_report(preview="Удалённая работа, ставить лайки")) == "fake_jobs"
    assert demo.categorize(_report(preview="Kazpost: сәлемдеме қоймада")) == "marketplace"
    assert demo.categorize(_report(preview="Telegram Premium gift for you")) == "telegram_fraud"
    qr = Evidence(kind="heuristic", code="qr_link", detail="")
    assert demo.categorize(_report(kind="image", evidence=[qr])) == "qr_fraud"
    assert demo.categorize(_report(preview="Send the SMS code to unlock")) == "phishing"
    print("test_categorize_the_users_last_check PASSED")


def test_every_map_and_report_string_exists() -> None:
    keys = {f"map.cat.{c}" for c in demo.CATEGORIES} | {f"map.region.{r}" for r in demo.REGIONS}
    keys |= {"map.title", "map.demo_notice", "map.your_check", "map.method_note", "nav.map"}
    keys |= {f"trust.summary.{v}" for v in ("safe", "caution", "danger")} | {"trust.in_short", "trust.dont_title"}
    for kind in ("message", "url", "image", "email", "password"):
        keys |= set(report_view.dont_keys(_report(kind=kind)))
    for language in LANGUAGES:
        missing = sorted(keys - set(_load(language)))
        assert not missing, (language, missing)
    print("test_every_map_and_report_string_exists PASSED")


def test_dont_block_only_for_risky_results() -> None:
    assert report_view.dont_keys(_report(verdict="safe")) == []
    assert report_view.dont_keys(_report(verdict="caution", kind="url")) == [
        "trust.dont.url_1", "trust.dont.url_2", "trust.dont.url_3",
    ]
    print("test_dont_block_only_for_risky_results PASSED")


def test_map_page_labels_demo_data_and_shows_the_users_category() -> None:
    state: dict = {}
    report_store.remember(state, _report(preview="Удалённая работа: внесите депозит"))
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.session_state["trust_history"] = state["trust_history"]
    at.session_state["tumar_guest"] = True  # the map is open to guests too
    with patch.object(auth, "is_signed_in", return_value=False), \
            patch.object(auth, "user_display", return_value=("", "")), \
            patch.object(auth, "record_registration", return_value=None):
        at.run()
        at.switch_page("views/threat_map.py")
        at.run()
    assert not at.exception, at.exception
    assert at.warning and at.warning[0].value == translate("map.demo_notice", "en")
    fake_jobs = translate("map.cat.fake_jobs", "en")
    assert any(fake_jobs in i.value for i in at.info), [i.value for i in at.info]
    assert len(at.dataframe) == 1
    print("test_map_page_labels_demo_data_and_shows_the_users_category PASSED")


if __name__ == "__main__":
    test_demo_data_is_consistent_and_flagged()
    test_categorize_the_users_last_check()
    test_every_map_and_report_string_exists()
    test_dont_block_only_for_risky_results()
    test_map_page_labels_demo_data_and_shows_the_users_category()
    print("All Threat Map tests passed.")
