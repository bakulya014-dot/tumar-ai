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

# --- One-time codes, by DIRECTION ---
#
# The single most expensive mistake this scanner made was treating
# every mention of a code as a danger sign. Legitimate services send
# codes constantly, so "verification code" on its own flagged half the
# honest messages people receive. What matters is not the word but who
# is being asked to do what:
#
#   disclosure — reveal the code to a person or a reply. No legitimate
#                service ever asks for this. Strong scam signal.
#   entry      — type the code into the screen you are already on.
#                Normal two-factor setup does exactly this. Ambiguous.
#   delivery   — here is your code. Ordinary, and usually paired with
#                a warning not to share it. Not a scam signal at all.

_OTP_DISCLOSURE_PATTERNS = (
    # English
    "reply with the code", "reply with your code", "send us the code",
    "send me the code", "tell us the code", "tell me the code",
    "share the code", "give us the code", "confirm the code we sent",
    "read the code", "dictate the code", "forward the code",
    # Russian
    "назовите код", "сообщите код", "продиктуйте код", "скажите код",
    "отправьте код", "пришлите код", "передайте код", "код оператору",
    # Kazakh. Stems, not whole words: the accusative appears as both
    # "кодты" and "кодын", and the verb carries a person ending
    # ("айтыңыз", "айт"). Matching the stem covers the family.
    "кодты айт", "кодын айт", "кодты жібер", "кодын жібер",
    "кодты хабарла", "кодын хабарла",
    "кодты операторға", "кодын операторға",
)

_OTP_ENTRY_PATTERNS = (
    "enter the code", "enter this code", "input the code", "type the code",
    "введите код", "вводите код",
    "кодты енгіз", "кодын енгіз",
)

_OTP_DELIVERY_PATTERNS = (
    # English
    "otp", "one-time password", "one-time code", "verification code",
    "sms code", "security code", "confirmation code", "code we sent",
    "your code is",
    # Russian
    "код из смс", "код из sms", "смс-код", "sms-код", "код подтверждения",
    "одноразовый код", "ваш код",
    # Kazakh
    "растау коды", "бір реттік код", "sms кодын", "смс кодын",
    "сіздің кодыңыз",
)

# Word-order-independent detection of "hand the code over". Kazakh and
# Russian inflect both the noun and the verb and place them freely, so
# fixed phrases miss constructions that a human reads instantly.
_CODE_WORDS = ("код", "code", "otp", "one-time password", "passcode")
_DISCLOSURE_VERBS = (
    "айт", "жібер", "хабарла", "оператор",
    "назов", "сообщ", "продикт", "скаж", "отправ", "пришл", "переда",
    "reply", "tell", "share", "forward", "dictate", "give us",
)
# English requests to hand the code to the sender ("send me the code",
# "text me your OTP"). English word order is fixed, so these count only
# when they come shortly BEFORE the code word — "send me the meeting
# notes and the code review link" is not a request for a code.
# Deliberately not a bare "send": "we will send you a code" is what
# every real service writes, and is delivery, not disclosure.
_EN_REQUEST_VERBS = (
    "send me", "send us", "send it to", "send it back", "send back",
    "text me", "text us", "give me", "read me", "read out",
)
_EN_REQUEST_WINDOW = 30

# English compounds where "code" is not a one-time code. A request to
# "send me the source code" or a note about the dress code is ordinary
# conversation, not an attempt to take over an account.
_NON_OTP_CODE_BEFORE = (
    "source ", "dress ", "zip ", "postal ", "post ", "promo ", "discount ",
    "coupon ", "qr ", "bar", "country ", "area ", "error ", "status ",
    "color ", "colour ", "morse ", "cheat ", "secret santa ",
)
_NON_OTP_CODE_AFTER = (" review", " of conduct", "base", " snippet", " editor")
# How far apart the code word and the verb may sit and still be read
# as one instruction.
_DISCLOSURE_WINDOW = 45

# Security advice ABOUT codes — a bank telling you it will never ask
# for one. Lexically these look alarming and are the opposite: they are
# the message a real institution sends.
_NEVER_ASK_PATTERNS = (
    "we will never ask", "never share this code", "do not share this code",
    "never share your", "we never call", "do not share it",
    "do not share your", "don't share your", "dont share your",
    "никогда не просим", "никогда не спрашиваем", "никому не сообщайте",
    "не сообщайте его", "никому не говорите код",
    "ешқашан сұрамайды", "ешқашан сұрамаймыз", "оны ешкімге айтпаңыз",
    "ешкімге айтпаңыз код",
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
# every domain the brand legitimately uses. A brand with one entry was
# the cause of a whole class of false alarms: login.microsoftonline.com
# is Microsoft, and calling it an impostor teaches users to ignore us.
_BRAND_DOMAINS = {
    "kaspi": ("kaspi.kz",),
    "halyk": ("halykbank.kz", "halyk.kz"),
    "jusan": ("jusan.kz",),
    "egov": ("egov.kz",),
    "google": ("google.com", "google.kz", "youtube.com", "gmail.com"),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com"),
    "paypal": ("paypal.com",),
    "amazon": ("amazon.com",),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "telegram": ("telegram.org", "t.me"),
    "netflix": ("netflix.com",),
    "olx": ("olx.kz",),
}

# Domains we recognize as genuine. Lexical heuristics are not applied
# to these at all: a real bank's domain contains "bank", a real support
# site contains "support", and judging them by word-spotting produces
# exactly the false alarms that erode trust in a security tool.
_OFFICIAL_DOMAINS = frozenset(
    domain for domains in _BRAND_DOMAINS.values() for domain in domains
) | frozenset(
    {
        "post.kz",
        "github.com",
        "wikipedia.org",
        "gov.kz",
        "salyk.kz",
        "kaspi.kz",
    }
)

# Signals strong enough to justify suspicion on their own, as opposed
# to ones that only matter in company. Splitting these stopped the
# scanner from flagging every hyphenated domain on the internet.
_STRONG_URL_SIGNALS = frozenset(
    {
        "shortener",
        "ip_address",
        "punycode",
        "homoglyph",
        "misleading_subdomain",
        "brand_lookalike",
        "misspelled_domain",
    }
)

# Hyphens are ordinary in real domain names; three or more is where it
# starts to look like a phrase pretending to be a hostname.
_HYPHEN_LIMIT = 3

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
    otp_signal: str  # "none" | "delivery" | "entry" | "disclosure"
    otp_matches: list[str]
    security_advice: bool  # message warns the reader, e.g. "we never ask"
    credential_indicators: list[str]
    financial_indicators: list[str]
    manipulation_indicators: list[str]
    suspicious_urls: list[SuspiciousURL]

    @property
    def otp_requested(self) -> bool:
        """True only when someone is asking for the code itself.

        Kept as a property because "was a code requested" is still the
        question the UI wants to ask; what changed is that receiving a
        code no longer counts as being asked for one.
        """
        return self.otp_signal == "disclosure"

    @property
    def strong_signals(self) -> list[str]:
        """Findings that alone justify suspicion."""
        found: list[str] = []
        if self.otp_signal == "disclosure":
            found.append("otp_disclosure")
        if self.credential_indicators:
            found.append("credential")
        for finding in self.suspicious_urls:
            if any(is_strong_url_signal(code) for code in finding.reasons):
                found.append("url")
                break
        return found

    @property
    def weak_signals(self) -> list[str]:
        """Findings that mean little on their own but add up."""
        found: list[str] = []
        if self.urgency_matches:
            found.append("urgency")
        if self.financial_indicators:
            found.append("financial")
        if self.manipulation_indicators:
            found.append("manipulation")
        if self.otp_signal == "entry":
            found.append("otp_entry")
        return found


def scan_message(message: str) -> HeuristicReport:
    """Run every deterministic check against one message."""
    lowered = message.lower()

    urgency_matches = _find_matches(lowered, _URGENCY_PATTERNS)
    otp_signal, otp_matches = _classify_otp(lowered)

    return HeuristicReport(
        urgency_score=_URGENCY_SCORES.get(len(urgency_matches), 100),
        urgency_matches=urgency_matches,
        otp_signal=otp_signal,
        otp_matches=otp_matches,
        security_advice=bool(_find_matches(lowered, _NEVER_ASK_PATTERNS)),
        credential_indicators=_find_matches(lowered, _CREDENTIAL_PATTERNS),
        financial_indicators=_find_matches(lowered, _FINANCIAL_PATTERNS),
        manipulation_indicators=_find_matches(lowered, _MANIPULATION_PATTERNS),
        suspicious_urls=_scan_urls(message),
    )


def _classify_otp(lowered: str) -> tuple[str, list[str]]:
    """Decide what a message is doing with a one-time code.

    Strongest intent wins: a message that both delivers a code and asks
    you to pass it on is asking you to pass it on — unless it is
    telling you NOT to pass it on, which is the opposite and is what
    every real bank writes.
    """
    delivery = _find_matches(lowered, _OTP_DELIVERY_PATTERNS)

    # "Never share your code with anyone" contains both a code and a
    # verb about sharing it. Reading that as a request would flag the
    # single most trustworthy message a bank sends.
    if _find_matches(lowered, _NEVER_ASK_PATTERNS):
        return ("delivery", delivery) if delivery else ("none", [])

    disclosure = _find_matches(lowered, _OTP_DISCLOSURE_PATTERNS)
    if disclosure:
        return "disclosure", disclosure

    # Fixed phrases cannot cover Kazakh and Russian, where the word for
    # "code" and the verb asking for it are inflected and can sit
    # several words apart. Proximity catches the construction instead
    # of the phrasing.
    nearby = _code_near_disclosure_verb(lowered)
    if nearby:
        return "disclosure", nearby

    entry = _find_matches(lowered, _OTP_ENTRY_PATTERNS)
    if entry:
        return "entry", entry
    if delivery:
        return "delivery", delivery
    return "none", []


def _code_near_disclosure_verb(lowered: str) -> list[str]:
    """Find "code … hand it over" wording regardless of word order."""
    matches: list[str] = []
    for code_word in _CODE_WORDS:
        start = lowered.find(code_word)
        while start != -1:
            window = lowered[
                max(0, start - _DISCLOSURE_WINDOW) : start + _DISCLOSURE_WINDOW
            ]
            if code_word == "code" and (
                lowered[:start].endswith(_NON_OTP_CODE_BEFORE)
                or lowered[start + 4 :].startswith(_NON_OTP_CODE_AFTER)
            ):
                start = lowered.find(code_word, start + 1)
                continue
            before = lowered[max(0, start - _EN_REQUEST_WINDOW) : start]
            for verb in _DISCLOSURE_VERBS:
                if verb in window:
                    matches.append(f"{code_word}…{verb}")
                    break
            else:
                for verb in _EN_REQUEST_VERBS:
                    if verb in before:
                        matches.append(f"{verb}…{code_word}")
                        break
            start = lowered.find(code_word, start + 1)
    return matches


def _find_matches(lowered_text: str, patterns: tuple[str, ...]) -> list[str]:
    """Return the patterns present in the text (order preserved)."""
    return [pattern for pattern in patterns if pattern in lowered_text]


def _scan_urls(message: str) -> list[SuspiciousURL]:
    """Extract URLs and keep only those worth reporting.

    Weighted rather than "any finding at all": a plain http link with
    a hyphen in it used to be reported as a suspicious URL and handed
    to the AI as evidence of fraud, which is how ordinary newsletters
    started looking dangerous.
    """
    findings: list[SuspiciousURL] = []
    seen: set[str] = set()
    for raw_url in _URL_REGEX.findall(message):
        url = raw_url.rstrip(".,;:!?")
        if url in seen:
            continue
        seen.add(url)
        if is_suspicious_url(url):
            findings.append(SuspiciousURL(url=url, reasons=url_reasons(url)))
    return findings


def url_reasons(url: str) -> list[str]:
    """Return reason codes describing why this URL looks suspicious.

    Public API: the scam analyzer uses it for links found inside
    messages, and the URL scanner uses it when the URL itself is the
    subject. One set of checks, one place to improve them.
    """
    normalized = url if "://" in url else f"http://{url}"
    try:
        parsed = urlparse(normalized.lower())
        host = parsed.hostname or ""
    except ValueError:
        # Malformed (e.g. "http://[::1" — an unbalanced IPv6 bracket).
        # Not a URL we can judge, and never a reason to fail the whole
        # message analysis around it.
        return []
    if not host:
        return []

    reasons: list[str] = []
    labels = host.split(".")
    second_level = labels[-2] if len(labels) >= 2 else host

    if host in _SHORTENERS:
        # A shortener hides the destination; that is the whole story.
        return ["shortener"]

    # A hostname mixing alphabets is an impersonation technique, not a
    # typo: "kаspi.kz" with one Cyrillic letter renders identically to
    # the real domain. Checked before anything else, because on a
    # look-alike domain every other check reads as if it were genuine.
    if _mixes_scripts(host):
        reasons.append("homoglyph")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        reasons.append("ip_address")
    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("punycode")
    if parsed.scheme == "http" and not url.lower().startswith("www."):
        reasons.append("no_https")

    if is_official_domain(host):
        # Recognized as genuine: report only what is objectively true
        # of the connection, and skip every lexical guess. Real banks
        # have "bank" in their name.
        return reasons

    if labels[-1] in _SUSPICIOUS_TLDS:
        reasons.append("suspicious_tld")
    if host.count("-") >= _HYPHEN_LIMIT:
        reasons.append("many_hyphens")

    for brand, officials in _BRAND_DOMAINS.items():
        if any(f"{official}." in host for official in officials):
            reasons.append("misleading_subdomain")
            break
        if brand in host:
            reasons.append("brand_lookalike")
            break
        if second_level != brand and _is_near_miss(second_level, brand):
            reasons.append("misspelled_domain")
            break

    if any(word in host for word in _TRUST_BAIT_WORDS):
        reasons.append("trust_bait")

    return reasons


def is_official_domain(host: str) -> bool:
    """True when this host belongs to a domain we recognize as genuine."""
    return any(
        host == official or host.endswith("." + official)
        for official in _OFFICIAL_DOMAINS
    )


def is_strong_url_signal(code: str) -> bool:
    """True when this finding justifies suspicion on its own."""
    return code in _STRONG_URL_SIGNALS


def is_suspicious_url(url: str) -> bool:
    """Whether the findings add up to something worth flagging.

    One strong signal is enough. Weak signals only count together: a
    site being on http, or having a few hyphens, is not evidence of
    anything by itself, and treating it as such is how a scanner ends
    up crying wolf at half the web.
    """
    reasons = url_reasons(url)
    if any(is_strong_url_signal(code) for code in reasons):
        return True
    return len(reasons) >= 2


def _mixes_scripts(host: str) -> bool:
    """True when a hostname combines Latin and Cyrillic letters.

    Legitimate domains are written in one alphabet. Mixing them is how
    a look-alike is built, and it is invisible to the reader.
    """
    letters = [char for char in host if char.isalpha()]
    has_latin = any("a" <= char <= "z" for char in letters)
    has_cyrillic = any("Ѐ" <= char <= "ӿ" for char in letters)
    return has_latin and has_cyrillic


def _is_near_miss(candidate: str, target: str) -> bool:
    """True when the strings differ by one edit or one swap.

    Substitutions, insertions and deletions were already caught; the
    missing case was transposition — "kapsi" for "kaspi" — which is
    the single most common way a domain is misread, because the eye
    corrects it automatically.
    """
    if _is_one_edit_away(candidate, target):
        return True
    if len(candidate) != len(target):
        return False
    differences = [
        index for index, (a, b) in enumerate(zip(candidate, target)) if a != b
    ]
    if len(differences) != 2:
        return False
    first, second = differences
    return (
        second == first + 1
        and candidate[first] == target[second]
        and candidate[second] == target[first]
    )


def _is_one_edit_away(candidate: str, target: str) -> bool:
    """True when the strings differ by one insertion, deletion or swap."""
    if abs(len(candidate) - len(target)) > 1:
        return False
    if len(candidate) == len(target):
        return sum(a != b for a, b in zip(candidate, target)) == 1
    shorter, longer = sorted((candidate, target), key=len)
    for index in range(len(longer)):
        if shorter == longer[:index] + longer[index + 1:]:
            return True
    return False
