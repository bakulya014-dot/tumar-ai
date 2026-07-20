"""Deterministic message scanner.

Runs before (and independently of) the AI: fast, free, and predictable
pattern checks for urgency pressure, OTP requests, financial bait,
credential-theft wording, psychological manipulation, and suspicious
URLs. Patterns cover English, Russian, and Kazakh.

The scanner returns matched evidence (verbatim phrases, URLs) plus
short reason codes; the UI translates codes into the user's language.
This module knows nothing about Streamlit or Gemini.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# --- Keyword patterns (lowercase substrings; stems cover word endings) ---

_URGENCY_PATTERNS = (
    # English
    "urgent", "immediately", "act now", "right away", "final warning",
    "last chance", "limited time", "expires today", "within 30 minutes",
    "within 24 hours", "will be suspended", "will be blocked",
    "has been blocked", "frozen",
    # Russian
    "срочно", "немедленно", "прямо сейчас", "последнее предупреждение",
    "последний шанс", "заблокирован", "заморожен", "в течение 30 минут",
    "в течение 24 часов", "успейте",
    # Kazakh
    "шұғыл", "дереу", "соңғы ескерту", "бұғаттал", "мұздатыл",
    "30 минут ішінде", "24 сағат ішінде",
)

_OTP_PATTERNS = (
    # English
    "otp", "one-time password", "one-time code", "verification code",
    "sms code", "security code", "confirmation code", "code we sent",
    "enter the code",
    # Russian
    "код из смс", "код из sms", "смс-код", "sms-код", "код подтверждения",
    "одноразовый код", "назовите код", "сообщите код", "введите код",
    # Kazakh
    "растау коды", "бір реттік код", "sms кодын", "смс кодын",
    "кодты енгізіңіз", "кодты айтыңыз",
)

_CREDENTIAL_PATTERNS = (
    "password", "login", "verify your identity", "confirm your identity",
    "verify your account",
    "пароль", "логин", "учетн", "учётн", "подтвердите личность",
    "подтвердите аккаунт",
    "құпиясөз", "тіркелгі", "жеке басыңызды раста",
)

_FINANCIAL_PATTERNS = (
    "card number", "cvv", "cvc", "pin code", "wire transfer",
    "transfer money", "send money", "gift card", "crypto", "bitcoin",
    "you won", "prize", "lottery", "inheritance",
    "номер карты", "переведите", "перевод", "пин-код", "выигр", "приз",
    "наследств", "криптовалют", "подароч",
    "карта нөмір", "ақша аудар", "ұтыс", "жүлде",
)

_MANIPULATION_PATTERNS = (
    "keep this secret", "don't tell anyone", "do not tell anyone",
    "congratulations", "you have been selected", "trust me",
    "никому не говорите", "не говорите никому", "это секрет",
    "поздравляем", "вы выбраны", "доверьтесь",
    "ешкімге айтпаңыз", "құттықтаймыз", "сіз таңдалдыңыз",
)

# --- URL analysis data ---

_URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "clck.ru", "vk.cc", "tiny.cc", "rb.gy",
}

_SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "icu", "club", "work", "click", "link",
    "online", "site", "rest", "fit", "tk", "ml", "ga", "cf", "gq", "buzz",
}

_TRUST_BAIT_WORDS = {
    "secure", "verify", "login", "account", "support", "update",
    "confirm", "bank", "wallet",
}

# Brands commonly imitated in scams targeting our users, mapped to
# their real registered domains.
_BRAND_DOMAINS = {
    "kaspi": "kaspi.kz",
    "halyk": "halykbank.kz",
    "jusan": "jusan.kz",
    "egov": "egov.kz",
    "google": "google.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "telegram": "telegram.org",
    "netflix": "netflix.com",
    "olx": "olx.kz",
}

# Distinct urgency matches -> urgency score.
_URGENCY_SCORES = {0: 0, 1: 35, 2: 60, 3: 85}


@dataclass(frozen=True)
class SuspiciousURL:
    """One URL plus short reason codes explaining the suspicion."""

    url: str
    reasons: list[str]


@dataclass(frozen=True)
class HeuristicReport:
    """Everything the deterministic scanner found in one message."""

    urgency_score: int  # 0-100
    urgency_matches: list[str]
    otp_requested: bool
    otp_matches: list[str]
    credential_indicators: list[str]
    financial_indicators: list[str]
    manipulation_indicators: list[str]
    suspicious_urls: list[SuspiciousURL]


def scan_message(message: str) -> HeuristicReport:
    """Run every deterministic check against one message."""
    lowered = message.lower()

    urgency_matches = _find_matches(lowered, _URGENCY_PATTERNS)
    otp_matches = _find_matches(lowered, _OTP_PATTERNS)

    return HeuristicReport(
        urgency_score=_URGENCY_SCORES.get(len(urgency_matches), 100),
        urgency_matches=urgency_matches,
        otp_requested=bool(otp_matches),
        otp_matches=otp_matches,
        credential_indicators=_find_matches(lowered, _CREDENTIAL_PATTERNS),
        financial_indicators=_find_matches(lowered, _FINANCIAL_PATTERNS),
        manipulation_indicators=_find_matches(lowered, _MANIPULATION_PATTERNS),
        suspicious_urls=_scan_urls(message),
    )


def _find_matches(lowered_text: str, patterns: tuple[str, ...]) -> list[str]:
    """Return the patterns present in the text (order preserved)."""
    return [pattern for pattern in patterns if pattern in lowered_text]


def _scan_urls(message: str) -> list[SuspiciousURL]:
    """Extract URLs and keep only those with at least one red flag."""
    findings: list[SuspiciousURL] = []
    seen: set[str] = set()
    for raw_url in _URL_REGEX.findall(message):
        url = raw_url.rstrip(".,;:!?")
        if url in seen:
            continue
        seen.add(url)
        reasons = _url_reasons(url)
        if reasons:
            findings.append(SuspiciousURL(url=url, reasons=reasons))
    return findings


def _url_reasons(url: str) -> list[str]:
    """Return reason codes describing why this URL looks suspicious."""
    normalized = url if "://" in url else f"http://{url}"
    parsed = urlparse(normalized.lower())
    host = parsed.hostname or ""
    if not host:
        return []

    reasons: list[str] = []
    labels = host.split(".")
    registered = ".".join(labels[-2:]) if len(labels) >= 2 else host
    second_level = labels[-2] if len(labels) >= 2 else host

    if host in _SHORTENERS:
        # A shortener hides the destination; that is the whole story.
        return ["shortener"]
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        reasons.append("ip_address")
    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("punycode")
    if labels[-1] in _SUSPICIOUS_TLDS:
        reasons.append("suspicious_tld")
    if parsed.scheme == "http" and not url.lower().startswith("www."):
        reasons.append("no_https")
    if host.count("-") >= 2:
        reasons.append("many_hyphens")

    for brand, official in _BRAND_DOMAINS.items():
        is_official = host == official or host.endswith("." + official)
        if is_official:
            continue
        if f"{official}." in host:
            reasons.append("misleading_subdomain")
            break
        if brand in host:
            reasons.append("brand_lookalike")
            break
        if second_level != brand and _is_one_edit_away(second_level, brand):
            reasons.append("misspelled_domain")
            break

    if any(word in host for word in _TRUST_BAIT_WORDS):
        reasons.append("trust_bait")

    return reasons


def _is_one_edit_away(candidate: str, target: str) -> bool:
    """True when the strings differ by one edit (typosquat check)."""
    if abs(len(candidate) - len(target)) > 1:
        return False
    if len(candidate) == len(target):
        return sum(a != b for a, b in zip(candidate, target)) == 1
    shorter, longer = sorted((candidate, target), key=len)
    for index in range(len(longer)):
        if shorter == longer[:index] + longer[index + 1:]:
            return True
    return False
