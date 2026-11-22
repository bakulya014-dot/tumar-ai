"""Service status from real outcomes (no probing), the Security page, and the
Impersonation category on the demo map.

    venv\\Scripts\\python.exe tests\\test_service_status.py
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

import auth  # noqa: E402
from i18n import LANGUAGES, _load, translate  # noqa: E402
from services import service_status, telemetry  # noqa: E402
from services import threat_map_demo as demo  # noqa: E402
from services.trust_report import Evidence, TrustReport  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402


def _states(key_present=True) -> dict[str, str]:
    return {s.key: s.state for s in service_status.statuses(key_present)}


def test_states_follow_config_and_recent_outcomes() -> None:
    telemetry.metrics.reset()
    with patch("services.service_status.ocr_engine.available", return_value=True):
        assert _states() == {"ai": "ready", "breach": "ready", "password": "ready", "images": "ready"}
        assert _states(key_present=False)["ai"] == "not_configured"
        telemetry.emit("provider_call", provider="gemini", outcome="error", error_code="service_down")
        telemetry.emit("analysis", kind="email", outcome="error", error_code="unreachable")
        assert _states()["ai"] == "degraded" and _states()["breach"] == "degraded"
        telemetry.emit("provider_call", provider="gemini", outcome="ok")
        assert _states()["ai"] == "ready"  # recovered on the next good call
        # An input mistake is not an outage.
        telemetry.emit("analysis", kind="email", outcome="error", error_code="invalid_email")
        assert _states()["breach"] == "ready"
    with patch("services.service_status.ocr_engine.available", return_value=False):
        assert _states()["images"] == "limited"
    telemetry.metrics.reset()
    print("test_states_follow_config_and_recent_outcomes PASSED")


def test_kill_switch_shows_as_off() -> None:
    os.environ["TUMAR_DISABLE_FEATURES"] = "ai,breach,images"
    try:
        states = _states()
    finally:
        os.environ.pop("TUMAR_DISABLE_FEATURES")
    assert states["ai"] == states["breach"] == states["images"] == "off"
    print("test_kill_switch_shows_as_off PASSED")


def test_every_status_and_security_string_exists() -> None:
    keys = {f"status.service.{k}" for k in ("ai", "breach", "password", "images")}
    keys |= {f"status.state.{s}" for s in ("ready", "degraded", "off", "not_configured", "limited")}
    keys |= {"status.help.ai.ready", "status.help.ai.degraded", "status.help.ai.off", "status.help.ai.not_configured",
             "status.help.breach.ready", "status.help.breach.degraded", "status.help.breach.off",
             "status.help.password.ready", "status.help.password.degraded",
             "status.help.images.ready", "status.help.images.limited", "status.help.images.off"}
    import views  # noqa: F401  (namespace)
    sections = {
        "data": ("message", "link", "image", "email", "password", "account"),
        "ai": ("does", "never", "floor", "text"),
        "safeguards": ("limits", "errors", "secrets", "switches", "logs"),
        "limits": ("no_guarantee", "demo_map", "session", "third_parties"),
    }
    keys |= {f"security.{s}.{i}" for s, items in sections.items() for i in items}
    keys |= {f"security.{s}.title" for s in sections} | {"nav.security", "map.cat.impersonation"}
    for language in LANGUAGES:
        missing = sorted(keys - set(_load(language)))
        assert not missing, (language, missing)
    print("test_every_status_and_security_string_exists PASSED")


def test_security_page_and_home_status_render() -> None:
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    at.session_state["tumar_guest"] = True
    with patch.object(auth, "is_signed_in", return_value=False), \
            patch.object(auth, "user_display", return_value=("", "")), \
            patch.object(auth, "record_registration", return_value=None):
        at.run()
        home = "\n".join(m.value for m in at.markdown)
        at.switch_page("views/security.py")
        at.run()
    assert not at.exception, at.exception
    assert translate("status.service.breach", "en") in home
    page = "\n".join(m.value for m in at.markdown)
    assert "XposedOrNot" in page and "Pwned Passwords" in page
    assert translate("security.limits.no_guarantee", "en") in page
    print("test_security_page_and_home_status_render PASSED")


def test_impersonation_on_the_demo_map() -> None:
    assert "impersonation" in demo.CATEGORIES and demo.IS_SIMULATED
    lookalike = TrustReport(source="url_scanner", subject_type="url", subject_preview="halyk-bank-kz.net",
                            verdict="caution", trust_score=50, confidence=60,
                            evidence=[Evidence(kind="heuristic", code="url_brand_lookalike", detail="")])
    assert demo.categorize(lookalike) == "impersonation"
    assert translate("map.your_check", "en", category="x").endswith("was not added to these figures.")
    print("test_impersonation_on_the_demo_map PASSED")


if __name__ == "__main__":
    test_states_follow_config_and_recent_outcomes()
    test_kill_switch_shows_as_off()
    test_every_status_and_security_string_exists()
    test_security_page_and_home_status_render()
    test_impersonation_on_the_demo_map()
    print("All service status tests passed.")
