"""Threat Map (official statistics) and the Safety Report's new blocks.

    venv\\Scripts\\python.exe tests\\test_threat_map.py
"""

import os
import re
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
from services import threat_map_data as demo  # noqa: E402
from services.trust_report import Evidence, TrustReport  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402


def _report(verdict="danger", preview="Your card is blocked", kind="message", evidence=()) -> TrustReport:
    return TrustReport(
        source="scam_analyzer", subject_type=kind, subject_preview=preview,
        verdict=verdict, trust_score=10 if verdict == "danger" else 90, confidence=70,
        evidence=list(evidence),
    )


def test_official_data_is_consistent_and_sourced() -> None:
    assert not hasattr(demo, "IS_SIMULATED")  # no simulated figures any more
    national = demo.national_counts()
    assert set(national) == set(demo.CATEGORIES)
    assert sum(national.values()) == demo.NATIONAL_TOTAL and national["other"] > 0
    counted = [r.cases for r in demo.REGIONS if r.cases is not None]
    assert sum(counted) < demo.NATIONAL_TOTAL  # regions are a subset of the national total
    assert abs(sum(counted) / demo.NATIONAL_TOTAL * 100 - demo.TOP5_SHARE_PCT) < 1.5
    for _title, _publisher, _date, url in demo.SOURCES.values():
        assert url.startswith("https://")
    print("test_official_data_is_consistent_and_sourced PASSED")


def test_categorize_the_users_last_check() -> None:
    assert demo.categorize(_report(verdict="safe")) is None
    assert demo.categorize(_report(preview="Удалённая работа, ставить лайки")) == "service_ads"
    assert demo.categorize(_report(preview="Kazpost: сәлемдеме қоймада")) == "online_purchases"
    assert demo.categorize(_report(preview="Telegram Premium gift for you")) == "phishing"
    qr = Evidence(kind="heuristic", code="qr_link", detail="")
    assert demo.categorize(_report(kind="image", evidence=[qr])) == "phishing"
    assert demo.categorize(_report(preview="Send the SMS code to unlock")) == "bank_calls"
    assert demo.categorize(_report(preview="Вам одобрен кредит, подтвердите")) == "online_loans"
    assert demo.categorize(_report(preview="Инвестиции с доходом 30% в месяц")) == "other"
    # A leaked email or weak password is exposure, not a scam type (seen in production).
    assert demo.categorize(_report(kind="email", preview="te**t@example.com")) is None
    assert demo.categorize(_report(kind="password", verdict="caution", preview="••••")) is None
    print("test_categorize_the_users_last_check PASSED")


def test_every_map_and_report_string_exists() -> None:
    keys = {f"map.cat.{c}" for c in demo.CATEGORIES} | {f"map.region.{r.key}" for r in demo.REGIONS}
    keys |= {f"map.af.{k}" for k, _ in demo.ANTIFRAUD_SCHEMES}
    source = (ROOT / "views" / "threat_map.py").read_text(encoding="utf-8")
    keys |= set(re.findall(r'"(map\.[a-z_]+[a-z])"', source))
    keys |= {"map.official_notice", "map.your_check", "map.method_note", "nav.map"}
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


def test_map_page_shows_official_figures_and_the_users_category() -> None:
    state: dict = {}
    report_store.remember(state, _report(preview="Удалённая работа: внесите депозит"))
    # A newer breach result must not replace the scam check on the map.
    report_store.remember(state, _report(kind="email", preview="te**t@example.com"))
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
    assert not at.warning  # the old "demo data" banner is gone
    assert at.info[0].value == translate("map.official_notice", "en", date=demo.AS_OF)
    service_ads = translate("map.cat.service_ads", "en")
    assert any(service_ads in i.value for i in at.info), [i.value for i in at.info]
    assert len(at.dataframe) == 1
    page = "\n".join(m.value for m in at.markdown)
    assert "28 851" in page and "finprom.kz" in page
    print("test_map_page_shows_official_figures_and_the_users_category PASSED")


if __name__ == "__main__":
    test_official_data_is_consistent_and_sourced()
    test_categorize_the_users_last_check()
    test_every_map_and_report_string_exists()
    test_dont_block_only_for_risky_results()
    test_map_page_shows_official_figures_and_the_users_category()
    print("All Threat Map tests passed.")
