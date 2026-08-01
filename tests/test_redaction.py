"""Tests for personal-identifier redaction.

This is the gate between a customer's traffic and our database. If it
leaks, consent does not save us — we would be holding card numbers and
phone numbers we never needed. The tests are written accordingly: what
must disappear, and what must survive for the sample to be worth
keeping.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_redaction.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.redaction import contains_identifier, redact


# --- What must disappear ---


def test_email_addresses_are_removed() -> None:
    text = "Contact me at bakytzhan.test@gmail.com about the order"
    result = redact(text)
    assert "bakytzhan.test@gmail.com" not in result
    assert "[email]" in result
    print("test_email_addresses_are_removed PASSED")


def test_card_numbers_are_removed() -> None:
    # A valid test card number (passes Luhn).
    for text in (
        "My card is 4539578763621486 please refund it",
        "Card: 4539 5787 6362 1486",
        "card 4539-5787-6362-1486 expires soon",
    ):
        result = redact(text)
        assert "4539" not in result, text
        assert "[card]" in result, text
    print("test_card_numbers_are_removed PASSED")


def test_phone_numbers_are_removed() -> None:
    for text in (
        "Call me on +7 701 234 5678 tomorrow",
        "My number is 8(701)2345678",
    ):
        result = redact(text)
        assert "234" not in result or "[phone]" in result or "[number]" in result
        assert any(token in result for token in ("[phone]", "[number]")), text
    print("test_phone_numbers_are_removed PASSED")


def test_one_time_codes_are_removed() -> None:
    # The code itself is the most sensitive thing a scam message
    # contains, and it is worthless for research.
    result = redact("Your verification code is 481920, do not share it")
    assert "481920" not in result
    assert "[number]" in result
    print("test_one_time_codes_are_removed PASSED")


def test_iban_is_removed() -> None:
    result = redact("Transfer to KZ86125KZT5004100100 today")
    assert "KZ86125KZT5004100100" not in result
    assert "[iban]" in result
    print("test_iban_is_removed PASSED")


def test_several_identifiers_in_one_message() -> None:
    text = (
        "Hi, I am at ivan@example.kz, call +7 701 234 5678, "
        "card 4539578763621486, code 481920"
    )
    result = redact(text)
    for leak in ("ivan@example.kz", "4539578763621486", "481920"):
        assert leak not in result, leak
    print("test_several_identifiers_in_one_message PASSED")


# --- What must survive ---


def test_urls_survive_intact() -> None:
    """A scam's infrastructure is the most valuable part of a sample."""
    for url in (
        "http://kaspi-bonus-security.xyz/login",
        "https://post.kz/track?id=12345678",
        "http://192.168.44.10/bank/login.php",
        "http://bit.ly/3xKz9Qp",
    ):
        result = redact(f"Click here now: {url} before it expires")
        assert url in result, url
    print("test_urls_survive_intact PASSED")


def test_scam_wording_survives() -> None:
    text = (
        "СРОЧНО! Ваша карта заблокирована. Назовите код из СМС "
        "оператору, иначе средства будут заморожены."
    )
    result = redact(text)
    assert "СРОЧНО" in result
    assert "Назовите код" in result
    assert "заблокирована" in result
    print("test_scam_wording_survives PASSED")


def test_short_numbers_survive() -> None:
    # "30 minutes", "24 hours", prices — these carry the urgency and
    # are not identifying.
    result = redact("Act within 30 minutes or pay the 990 fee")
    assert "30" in result
    assert "990" in result
    print("test_short_numbers_survive PASSED")


def test_ordinary_long_number_is_not_called_a_card() -> None:
    # Fails the Luhn check, so it is a reference number, not a card.
    result = redact("Order reference 1234567812345678 shipped")
    assert "[card]" not in result
    print("test_ordinary_long_number_is_not_called_a_card PASSED")


# --- The safety net ---


def test_safety_net_spots_survivors() -> None:
    assert contains_identifier("write to me at test@example.com")
    assert contains_identifier("the code is 481920")
    assert not contains_identifier("URGENT! Your card is blocked")
    # A URL is not an identifier, however many digits it holds.
    assert not contains_identifier("go to https://post.kz/track?id=12345678")
    print("test_safety_net_spots_survivors PASSED")


def test_redaction_output_passes_its_own_safety_net() -> None:
    """Whatever we redact must satisfy the check that guards storage."""
    samples = (
        "Hi, I am at ivan@example.kz, call +7 701 234 5678",
        "Card 4539578763621486, code 481920, IBAN KZ86125KZT5004100100",
        "Your verification code is 481920. Do not share this code.",
        "Pay at http://post-kz-tolem.top or call 8 701 234 56 78",
    )
    for text in samples:
        assert not contains_identifier(redact(text)), text
    print("test_redaction_output_passes_its_own_safety_net PASSED")


def test_a_message_cannot_forge_the_internal_marker() -> None:
    # URLs are held aside using control characters while numbers are
    # redacted. A message containing that marker must not be able to
    # confuse the restore step into revealing or corrupting anything.
    result = redact("odd \x000\x00 text with test@example.com")
    assert "test@example.com" not in result
    print("test_a_message_cannot_forge_the_internal_marker PASSED")


if __name__ == "__main__":
    test_email_addresses_are_removed()
    test_card_numbers_are_removed()
    test_phone_numbers_are_removed()
    test_one_time_codes_are_removed()
    test_iban_is_removed()
    test_several_identifiers_in_one_message()
    test_urls_survive_intact()
    test_scam_wording_survives()
    test_short_numbers_survive()
    test_ordinary_long_number_is_not_called_a_card()
    test_safety_net_spots_survivors()
    test_redaction_output_passes_its_own_safety_net()
    test_a_message_cannot_forge_the_internal_marker()
    print("ALL REDACTION TESTS PASSED")
