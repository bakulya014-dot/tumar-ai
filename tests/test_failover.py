"""Second-provider failover (no network).

    venv\\Scripts\\python.exe tests\\test_failover.py
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["TUMAR_TELEMETRY"] = "off"

from pydantic import BaseModel  # noqa: E402

from services import gemini_client, scam_analysis  # noqa: E402
from services.providers import (  # noqa: E402
    FailoverProvider,
    GeminiProvider,
    ProviderError,
    ProviderUnsupported,
    fallback_provider,
    with_fallback,
)
from services.providers.base import AIProvider  # noqa: E402


class _Answer(BaseModel):
    verdict: str


class _Fake(AIProvider):
    def __init__(self, name: str, answer: str = "", error: str = "", available: bool = True):
        self.name, self._answer, self._error, self._available = name, answer, error, available
        self.calls = 0

    def available(self) -> bool:
        return self._available

    def generate_structured(self, system_prompt, contents, schema):
        self.calls += 1
        if self._error == "unsupported":
            raise ProviderUnsupported()
        if self._error:
            raise ProviderError(self._error)
        return schema(verdict=self._answer)


def test_primary_answer_never_touches_the_backup() -> None:
    primary, backup = _Fake("gemini", "danger"), _Fake("deepseek", "safe")
    assert FailoverProvider(primary, backup).generate_structured("s", "c", _Answer).verdict == "danger"
    assert backup.calls == 0
    print("test_primary_answer_never_touches_the_backup PASSED")


def test_a_failing_primary_is_answered_by_the_backup() -> None:
    for code in ("service_down", "rate_limited", "timeout", "credentials", "model_unavailable"):
        primary, backup = _Fake("gemini", error=code), _Fake("deepseek", "danger")
        assert FailoverProvider(primary, backup).generate_structured("s", "c", _Answer).verdict == "danger"
        assert primary.calls == 1 and backup.calls == 1
    print("test_a_failing_primary_is_answered_by_the_backup PASSED")


def test_when_both_fail_the_primary_error_is_reported() -> None:
    failover = FailoverProvider(_Fake("gemini", error="service_down"), _Fake("deepseek", error="credentials"))
    try:
        failover.generate_structured("s", "c", _Answer)
    except ProviderError as exc:
        assert exc.code == "service_down"
    else:
        raise AssertionError("expected ProviderError")
    print("test_when_both_fail_the_primary_error_is_reported PASSED")


def test_no_failover_for_unsupported_or_unavailable_backup() -> None:
    backup = _Fake("deepseek", "danger")
    try:
        FailoverProvider(_Fake("gemini", error="unsupported"), backup).generate_structured("s", "c", _Answer)
    except ProviderUnsupported:
        pass
    assert backup.calls == 0
    offline = _Fake("deepseek", "danger", available=False)
    try:
        FailoverProvider(_Fake("gemini", error="service_down"), offline).generate_structured("s", "c", _Answer)
    except ProviderError as exc:
        assert exc.code == "service_down"
    assert offline.calls == 0
    print("test_no_failover_for_unsupported_or_unavailable_backup PASSED")


def test_failover_is_opt_in() -> None:
    gemini = GeminiProvider("key")
    with patch.dict(os.environ, {"TUMAR_FALLBACK_PROVIDER": "", "DEEPSEEK_API_KEY": "k"}):
        assert fallback_provider() is None and with_fallback(gemini) is gemini
    with patch.dict(os.environ, {"TUMAR_FALLBACK_PROVIDER": "deepseek", "DEEPSEEK_API_KEY": ""}):
        assert with_fallback(gemini) is gemini  # named but not configured: unchanged
    with patch.dict(os.environ, {"TUMAR_FALLBACK_PROVIDER": "deepseek", "DEEPSEEK_API_KEY": "k"}):
        wrapped = with_fallback(gemini)
        assert isinstance(wrapped, FailoverProvider) and wrapped.backup.name == "deepseek"
    with patch.dict(os.environ, {"TUMAR_FALLBACK_PROVIDER": "gemini", "GEMINI_API_KEY": "k"}):
        assert with_fallback(gemini) is gemini  # failing over to itself cannot help
    print("test_failover_is_opt_in PASSED")


def test_scam_analysis_uses_the_backup_when_gemini_is_down() -> None:
    backup = _Fake("deepseek")

    def answer(system_prompt, contents, schema):
        backup.calls += 1
        return schema.model_validate({
            "verdict": "Dangerous", "risk_score": 90, "confidence": 80, "credential_theft_risk": 90,
            "financial_scam_risk": 80, "red_flags": ["asks for SMS code"], "explanation": "x",
            "recommended_actions": ["do not reply"],
        })

    backup.generate_structured = answer
    with patch.object(gemini_client, "generate_structured", side_effect=gemini_client.GeminiError("service_down")), \
            patch("services.providers.fallback_provider", return_value=backup), \
            patch("services.scam_analysis.text_provider", return_value=None):
        try:
            report = scam_analysis.analyze_message("Kaspi: send the SMS code now", api_key="k")
        except scam_analysis.ScamAnalysisError as exc:
            raise AssertionError(f"failover did not happen: {exc.code}") from exc
    assert backup.calls == 1 and report.ai.verdict == "Dangerous"
    print("test_scam_analysis_uses_the_backup_when_gemini_is_down PASSED")


def test_gemini_chain_has_lighter_fallbacks() -> None:
    models = gemini_client.MODEL_CANDIDATES
    assert models[0] == "gemini-3.5-flash" and len(models) >= 3 and len(set(models)) == len(models)
    print("test_gemini_chain_has_lighter_fallbacks PASSED")


if __name__ == "__main__":
    test_primary_answer_never_touches_the_backup()
    test_a_failing_primary_is_answered_by_the_backup()
    test_when_both_fail_the_primary_error_is_reported()
    test_no_failover_for_unsupported_or_unavailable_backup()
    test_failover_is_opt_in()
    test_scam_analysis_uses_the_backup_when_gemini_is_down()
    test_gemini_chain_has_lighter_fallbacks()
    print("All failover tests passed.")
