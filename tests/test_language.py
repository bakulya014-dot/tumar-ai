"""Tests for sample-language detection.

The corpus records which language a sample is in, and the evaluation
harness reports accuracy per language. Mislabelling here would make
those figures describe something other than what they claim.

Run with the project virtual environment:
    venv\\Scripts\\python.exe tests\\test_language.py
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.language import detect


def test_kazakh_is_distinguished_from_russian() -> None:
    """Kazakh is mostly shared Cyrillic; its own letters give it away."""
    assert detect("ШҰҒЫЛ! Картаңыз бұғатталды, кодты жіберіңіз") == "kk"
    assert detect("Растау коды: 593014. Оны ешкімге айтпаңыз.") == "kk"
    print("test_kazakh_is_distinguished_from_russian PASSED")


def test_russian_is_detected() -> None:
    assert detect("СРОЧНО! Карта заблокирована, назовите код") == "ru"
    assert detect("Код подтверждения: 274815") == "ru"
    print("test_russian_is_detected PASSED")


def test_english_is_detected() -> None:
    assert detect("URGENT! Your card is blocked, send the code") == "en"
    print("test_english_is_detected PASSED")


def test_the_interface_language_does_not_override_the_sample() -> None:
    # The bug this module exists to prevent: a Russian scam pasted by
    # someone reading the app in English must be filed as Russian.
    assert detect("СРОЧНО! Карта заблокирована", fallback="en") == "ru"
    print("test_the_interface_language_does_not_override_the_sample PASSED")


def test_mixed_text_prefers_the_cyrillic_signal() -> None:
    # Scams often mix a Latin brand or URL into Cyrillic text.
    assert detect("Ваш Kaspi Gold бонус: http://kaspi-bonus.xyz") == "ru"
    assert detect("Сіздің Kaspi бонусыңыз дайын") == "kk"
    print("test_mixed_text_prefers_the_cyrillic_signal PASSED")


def test_text_without_letters_keeps_the_callers_belief() -> None:
    # A bare URL or a string of digits says nothing about language, so
    # inventing one would be worse than deferring.
    assert detect("http://example.com/12345", fallback="kk") == "kk"
    assert detect("1234567890", fallback="ru") == "ru"
    print("test_text_without_letters_keeps_the_callers_belief PASSED")


if __name__ == "__main__":
    test_kazakh_is_distinguished_from_russian()
    test_russian_is_detected()
    test_english_is_detected()
    test_the_interface_language_does_not_override_the_sample()
    test_mixed_text_prefers_the_cyrillic_signal()
    test_text_without_letters_keeps_the_callers_belief()
    print("ALL LANGUAGE TESTS PASSED")
