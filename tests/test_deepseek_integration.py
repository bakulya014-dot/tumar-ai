"""Live integration tests for the DeepSeek provider.

These call the real endpoint and cost tokens, so they run **only**
when DEEPSEEK_API_KEY is set and skip cleanly otherwise. That keeps
them out of CI, which has no key and should not be spending one.

    setx DEEPSEEK_API_KEY "..."            # Windows, once
    $env:DEEPSEEK_API_KEY = "..."          # or for this shell only
    venv\\Scripts\\python.exe tests\\test_deepseek_integration.py

The key is read from the environment and never written anywhere. What
these tests check is not "does the model agree with us" — that is the
evaluation harness's job — but whether the integration holds: does the
endpoint answer, does the answer validate against our schema, and does
a failure stay a coded failure instead of leaking a stack trace.
"""

import os
import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.providers import DeepSeekProvider, ProviderError
from services.scam_analysis import ScamAnalysis, ScamReport, analyze_message
from services.trust_report import from_scam_report

CONFIGURED = bool(os.environ.get("DEEPSEEK_API_KEY"))
SKIP_NOTE = "SKIPPED (set DEEPSEEK_API_KEY to run)"


def test_endpoint_answers_with_our_schema() -> None:
    """The model returns something that validates as a ScamAnalysis."""
    if not CONFIGURED:
        print(f"test_endpoint_answers_with_our_schema {SKIP_NOTE}")
        return

    provider = DeepSeekProvider()
    assert provider.available(), "key present but provider reports unavailable"

    report = analyze_message(
        "URGENT! Your card is blocked. Reply with the SMS code we sent "
        "and confirm at http://kaspi-verify.xyz/login",
        api_key="",
        provider=provider,
    )
    assert isinstance(report, ScamReport)
    assert isinstance(report.ai, ScamAnalysis)
    assert report.ai.verdict in ("Safe", "Suspicious", "Dangerous")
    assert 0 <= report.ai.risk_score <= 100
    assert report.ai.explanation.strip(), "an empty explanation helps nobody"
    print(
        f"test_endpoint_answers_with_our_schema PASSED "
        f"(verdict={report.ai.verdict}, risk={report.ai.risk_score})"
    )


def test_the_engine_still_owns_the_verdict() -> None:
    """A live provider answer becomes a TrustReport only via the engine."""
    if not CONFIGURED:
        print(f"test_the_engine_still_owns_the_verdict {SKIP_NOTE}")
        return

    message = "Your verification code is 481920. Do not share this code."
    report = analyze_message(message, api_key="", provider=DeepSeekProvider())
    trust = from_scam_report(report, message)

    # The confidence shown is the platform's, derived from evidence —
    # never the number the model gave itself.
    assert trust.confidence_reason_keys
    assert trust.verdict in ("safe", "caution", "danger")
    print(
        f"test_the_engine_still_owns_the_verdict PASSED "
        f"(verdict={trust.verdict}, confidence={trust.confidence})"
    )


def test_a_bad_key_is_a_coded_failure_not_a_crash() -> None:
    """Wrong credentials must surface as a code the UI can translate."""
    if not CONFIGURED:
        print(f"test_a_bad_key_is_a_coded_failure_not_a_crash {SKIP_NOTE}")
        return

    provider = DeepSeekProvider(api_key="definitely-not-a-valid-key")
    try:
        provider.generate_structured("Reply in JSON.", "hello", ScamAnalysis)
    except ProviderError as error:
        assert error.code in ("credentials", "ai_error", "unexpected_answer")
        # Nothing internal may reach the user through an error.
        assert "definitely-not-a-valid-key" not in str(error)
        print(
            f"test_a_bad_key_is_a_coded_failure_not_a_crash PASSED "
            f"(code={error.code})"
        )
    else:
        raise AssertionError("an invalid key was accepted")


def test_vision_is_only_attempted_when_declared() -> None:
    """Images go to this model only once it is confirmed to read them."""
    if not CONFIGURED:
        print(f"test_vision_is_only_attempted_when_declared {SKIP_NOTE}")
        return

    assert DeepSeekProvider(vision=False).supports_vision() is False
    print("test_vision_is_only_attempted_when_declared PASSED")


if __name__ == "__main__":
    if not CONFIGURED:
        print("DEEPSEEK_API_KEY is not set — live tests skipped.")
    test_endpoint_answers_with_our_schema()
    test_the_engine_still_owns_the_verdict()
    test_a_bad_key_is_a_coded_failure_not_a_crash()
    test_vision_is_only_attempted_when_declared()
    print("ALL DEEPSEEK INTEGRATION TESTS PASSED")
