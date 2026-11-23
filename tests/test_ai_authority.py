"""The AI may analyse and recommend; it can never act. Plus the kill switches.

    venv\\Scripts\\python.exe tests\\test_ai_authority.py
"""

import os
import re
import sys
import typing
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["TUMAR_TELEMETRY"] = "off"

from services import ai_authority  # noqa: E402
from services.scam_analysis import ScamAnalysis  # noqa: E402
from services.trust_engine import AnalysisContext, EngineError, TrustEngine, TrustSubject  # noqa: E402
from services.url_scanner import UrlAnalysis  # noqa: E402
from services.vision_analysis import VisionFinding  # noqa: E402

AI_SOURCES = [
    *sorted((ROOT / "services" / "providers").glob("*.py")),
    ROOT / "services" / "gemini_client.py",
    ROOT / "services" / "vision_analysis.py",
    ROOT / "app" / "news" / "summarizer.py",
]
TOOL_PARAMETERS = re.compile(
    r"\b(tools|tool_choice|tool_config|function_call|functions|function_declarations|automatic_function_calling)\s*[=:]",
)


def test_no_ai_call_can_use_tools() -> None:
    offenders = []
    for path in AI_SOURCES:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if TOOL_PARAMETERS.search(line) and not line.strip().startswith("#"):
                offenders.append(f"{path.name}:{number}")
    assert not offenders, f"tool/function calling configured: {offenders}"
    print("test_no_ai_call_can_use_tools PASSED")


def test_ai_answers_are_data_only() -> None:
    allowed = {str, int, float, bool}
    for schema in (ScamAnalysis, UrlAnalysis, VisionFinding):
        for name, field in schema.model_fields.items():
            annotation = field.annotation
            origin = typing.get_origin(annotation)
            args = typing.get_args(annotation)
            ok = (
                annotation in allowed
                or origin is typing.Literal
                or (origin is list and args and args[0] is str)
            )
            assert ok, (schema.__name__, name, annotation)
    print("test_ai_answers_are_data_only PASSED")


def test_every_ai_call_site_is_gated() -> None:
    call = re.compile(r"(generate_structured\(|generate_content\(|provider\.analyze_image\()")
    gated = {
        "services/scam_analysis.py", "services/url_scanner.py",
        "services/vision_analysis.py", "app/news/summarizer.py",
        "services/ai_security/analysis.py",
    }
    callers = set()
    for path in [*ROOT.joinpath("services").rglob("*.py"), *ROOT.joinpath("app").rglob("*.py"), *ROOT.joinpath("api").rglob("*.py"), *ROOT.joinpath("telegram_bot").rglob("*.py")]:
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("services/providers/") or rel == "services/gemini_client.py":
            continue  # the transports themselves
        text = path.read_text(encoding="utf-8")
        if any(not ln.lstrip().startswith(("def ", "#")) and call.search(ln) for ln in text.splitlines()):
            callers.add(rel)
            assert "ai_authority.require(" in text, f"{rel} calls a model without ai_authority.require()"
    assert callers == gated, callers
    print("test_every_ai_call_site_is_gated PASSED")


def test_capabilities_and_forbidden_actions() -> None:
    assert set(ai_authority.ALLOWED) == {"analyze_text", "read_image", "summarize_public_news"}
    for forbidden in ai_authority.FORBIDDEN:
        try:
            ai_authority.require(forbidden)
        except PermissionError:
            continue
        raise AssertionError(f"{forbidden} was allowed")
    assert ai_authority.USER_ACTIONS == {"delete_my_data": 2}
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "st.popover(t(\"account.delete_data\")" in app and "account.delete_confirm" in app
    print("test_capabilities_and_forbidden_actions PASSED")


class _Env:
    def __init__(self, value: str):
        self.value, self.saved = value, None

    def __enter__(self):
        self.saved = os.environ.get("TUMAR_DISABLE_FEATURES")
        os.environ["TUMAR_DISABLE_FEATURES"] = self.value

    def __exit__(self, *exc):
        if self.saved is None:
            os.environ.pop("TUMAR_DISABLE_FEATURES", None)
        else:
            os.environ["TUMAR_DISABLE_FEATURES"] = self.saved


def test_kill_switch_ai_falls_back_to_rules() -> None:
    with _Env("ai"):
        report = TrustEngine().analyze(
            TrustSubject(content="Send me your SMS code now", declared_kind="message"),
            AnalysisContext(api_key="placeholder", offline_fallback=True),
        )
    assert report.analysis_metadata.get("mode") == "offline"
    assert report.analysis_metadata.get("offline_reason") == "ai_disabled"
    print("test_kill_switch_ai_falls_back_to_rules PASSED")


def test_kill_switches_breach_images_vision() -> None:
    with _Env("breach, images"):
        for content, kind in (("someone@example.com", "email"), (b"\x89PNG", "image")):
            try:
                TrustEngine().analyze(
                    TrustSubject(content=content, declared_kind=kind, mime_type="image/png" if kind == "image" else "text/plain"),
                    AnalysisContext(),
                )
            except EngineError as exc:
                assert exc.code == "feature_disabled", (kind, exc.code)
            else:
                raise AssertionError(f"{kind} ran while switched off")
    with _Env("vision"):
        ai_authority.require("analyze_text")  # text AI still on
        try:
            ai_authority.require("read_image")
        except ai_authority.FeatureDisabled:
            pass
        else:
            raise AssertionError("vision ran while switched off")
    with _Env("nonsense, AI"):
        assert ai_authority.disabled_features() == {"ai"}  # case-insensitive; unknown names ignored
    print("test_kill_switches_breach_images_vision PASSED")


if __name__ == "__main__":
    test_no_ai_call_can_use_tools()
    test_ai_answers_are_data_only()
    test_every_ai_call_site_is_gated()
    test_capabilities_and_forbidden_actions()
    test_kill_switch_ai_falls_back_to_rules()
    test_kill_switches_breach_images_vision()
    print("All AI authority tests passed.")
