"""Strip personal identifiers from text before it is ever stored.

Used on the corpus contribution path. Consent is necessary but not
sufficient: someone agreeing to share a scam message has agreed to help
us detect scams, not to hand over their phone number, and a database of
consented content is still a database worth stealing. So we keep as
little as the research actually needs.

The governing distinction is simple:

    redact what identifies the PERSON — their email, phone, card,
    bank account, the one-time code they were sent

    keep what identifies the ATTACK — the URLs, the brand being
    impersonated, the wording, the urgency, the structure

Applying that faithfully means URLs survive intact even though they
contain digits, because a scam's infrastructure is the single most
valuable thing in a sample. Everything else that looks like an
identifier goes.

Redaction is deliberately aggressive. A false redaction costs a little
research value; a missed one puts a real person's card number in our
database.
"""

import re

# Placeholders left behind, so a reader of the corpus can see that
# something was removed and what kind of thing it was.
EMAIL_TOKEN = "[email]"
PHONE_TOKEN = "[phone]"
CARD_TOKEN = "[card]"
IBAN_TOKEN = "[iban]"
NUMBER_TOKEN = "[number]"

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]{2,}")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

# 13-19 digits, optionally grouped by spaces or dashes. Confirmed with
# a Luhn check before redacting, so ordinary long numbers survive.
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Phone numbers: an optional +, then 9-15 digits with the usual
# separators. Kazakh and Russian numbers are covered by the length.
_PHONE = re.compile(r"\+?\d[\d\s\-()]{7,17}\d")

# Anything else numeric and long enough to identify something: account
# numbers, reference numbers, and the one-time codes themselves.
_LONG_NUMBER = re.compile(r"\b\d{5,}\b")

# Internal marker used while URLs are held aside. Control characters
# cannot appear in the patterns above, so a message cannot forge one.
_SLOT = "\x00{}\x00"


def _luhn(digits: str) -> bool:
    """Whether a digit string passes the card checksum.

    Without this, any 16-digit reference number would be redacted as a
    card. With it, redaction stays accurate enough to trust.
    """
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _redact_cards(text: str) -> str:
    """Replace only digit runs that really look like card numbers."""

    def replace(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn(digits):
            return CARD_TOKEN
        return match.group()

    return _CARD.sub(replace, text)


def redact(text: str) -> str:
    """Return the text with personal identifiers removed.

    URLs are held aside first and restored last, so a scam's links —
    the most useful part of a sample — are never damaged by the
    numeric rules.
    """
    urls: list[str] = []

    def hold(match: re.Match) -> str:
        urls.append(match.group())
        return _SLOT.format(len(urls) - 1)

    protected = _URL.sub(hold, text)

    protected = _EMAIL.sub(EMAIL_TOKEN, protected)
    protected = _IBAN.sub(IBAN_TOKEN, protected)
    protected = _redact_cards(protected)
    protected = _PHONE.sub(PHONE_TOKEN, protected)
    protected = _LONG_NUMBER.sub(NUMBER_TOKEN, protected)

    for index, url in enumerate(urls):
        protected = protected.replace(_SLOT.format(index), url)
    return protected


def contains_identifier(text: str) -> bool:
    """Whether anything identifying survived redaction.

    A safety net rather than a duplicate check: it runs after redaction
    on the contribution path, and a positive result means the sample is
    dropped instead of stored. Losing a sample is cheap; storing
    someone's card number is not.
    """
    without_urls = _URL.sub("", text)
    return bool(
        _EMAIL.search(without_urls)
        or _IBAN.search(without_urls)
        or _LONG_NUMBER.search(without_urls)
        or _CARD.search(without_urls)
    )
