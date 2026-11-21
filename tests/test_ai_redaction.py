"""Personal data is masked before a message reaches an AI provider.

The landing page promises it ("card numbers, phones and IDs are
redacted before anything reaches an AI model"); this test holds the
code to that promise by capturing exactly what a provider receives.
Placeholder data only.

    venv\\Scripts\\python.exe tests\\test_ai_redaction.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.providers.base import AIProvider  # noqa: E402
from services.scam_analysis import ScamAnalysis, analyze_message  # noqa: E402

CARD = "4111 1111 1111 1111"  # the standard Luhn-valid test card number
PHONE = "+7 701 234 56 78"
EMAIL = "aigerim.test@example.com"
IIN = "990101300123"
CODE = "739154"
LINK = "http://kaspi-secure-verify.xyz/unlock?id=12345678"

MESSAGE = (
    f"URGENT: your card {CARD} is blocked. Call {PHONE} or write to {EMAIL}. "
    f"Confirm your IIN {IIN} and the SMS code {CODE} at {LINK} now."
)


class _Recorder(AIProvider):
    name = "recorder"

    def __init__(self) -> None:
        self.contents: list[str] = []

    def available(self) -> bool:
        return True

    def generate_structured(self, system_prompt, contents, schema):
        self.contents.append(contents)
        return ScamAnalysis(
            verdict="Dangerous", risk_score=90, confidence=80,
            credential_theft_risk=80, financial_scam_risk=80,
            red_flags=["test"], explanation="test", recommended_actions=["test"],
        )


def _sent() -> str:
    provider = _Recorder()
    analyze_message(MESSAGE, api_key="", provider=provider)
    assert len(provider.contents) == 1
    return provider.contents[0]


def test_identifiers_never_reach_the_provider() -> None:
    sent = _sent()
    for secret in (CARD, PHONE, EMAIL, IIN, CODE):
        assert secret not in sent, (secret, sent)
    for token in ("[card]", "[email]"):
        assert token in sent, (token, sent)
    print("test_identifiers_never_reach_the_provider PASSED")


def test_links_and_wording_survive() -> None:
    sent = _sent()
    assert LINK in sent, sent  # the link is the evidence; it is kept whole
    assert "URGENT" in sent and "SMS code" in sent
    print("test_links_and_wording_survive PASSED")


def test_rules_still_see_the_original_text() -> None:
    # Masking happens only on the way out: the scanner's findings, built
    # from the original message, are still summarised for the model.
    sent = _sent()
    assert "AUTOMATED SCANNER FINDINGS" in sent
    assert "One-time code:" in sent and "Suspicious URL" in sent, sent
    print("test_rules_still_see_the_original_text PASSED")


if __name__ == "__main__":
    test_identifiers_never_reach_the_provider()
    test_links_and_wording_survive()
    test_rules_still_see_the_original_text()
    print("All AI redaction tests passed.")
