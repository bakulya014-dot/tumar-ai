"""Password health check — breach lookup without revealing the password.

Two independent layers, neither of which sends the password anywhere:

1. Breach lookup via k-anonymity. We take the SHA-1 hash of the
   password and send only its FIRST FIVE characters to Have I Been
   Pwned's range API. The service answers with every hash suffix that
   shares that prefix — typically 500-1000 of them — and the match is
   made here, locally. The breach database therefore learns that
   somebody checked a password starting with those five hex digits,
   and nothing else. It cannot know which password was checked, and
   the password itself never leaves this process.

2. Deterministic strength assessment, entirely offline: length,
   character variety, repeats, sequential runs, and a short list of
   passwords so common that any strength score would be misleading.

The password is never logged, never sent to the AI engine, never
written to disk, and never placed inside the returned TrustReport —
`subject_preview` is a fixed row of dots, so neither the password nor
even its length can leak through session history or a future API
response.

This module knows nothing about Streamlit.
"""

import hashlib
import re

import requests

from services.common import ServiceError
from services.trust_report import Evidence, Metric, TrustReport

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT_S = 15

# Hash characters sent to the breach database. Five is the k-anonymity
# contract HIBP defines: short enough that the prefix is shared by
# hundreds of unrelated hashes, long enough to keep responses small.
PREFIX_LENGTH = 5

# Ask HIBP to pad responses with fake entries. Without padding, the
# size of the response can hint at how many hashes share the prefix.
_PADDING_HEADER = {"Add-Padding": "true"}

# What the report shows instead of the password. Fixed width on
# purpose: a dot per character would leak the length.
_PREVIEW = "•" * 10

# Strength scoring. Deliberately simple and explainable — a score a
# user cannot understand is a score they cannot act on.
_LENGTH_CAP = 16  # characters beyond this add no further points
_POINTS_PER_CHARACTER = 4  # 16 chars -> 64 points
_VARIETY_BONUS = 9  # per character class beyond the first -> up to 27

_STRONG_ENOUGH = 50  # below this, an unbreached password still warns
_COMFORTABLE_LENGTH = 12
_MINIMUM_LENGTH = 8

# Penalties, applied after the base score.
_PENALTY_SEQUENCE = 15
_PENALTY_REPEAT = 10
_PENALTY_SINGLE_CLASS = 10
_COMMON_PASSWORD_CEILING = 10  # a known password is weak regardless

_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "йцукенгшщзхъ",
    "фывапролджэ",
    "ячсмитьбю",
)
_RUN_LENGTH = 4  # how many consecutive characters count as a sequence

# Not a security control — the breach lookup does that job. This list
# only stops the strength score from flattering passwords that are
# guessed first in every attack.
_COMMON_PASSWORDS = frozenset(
    {
        "123456", "password", "12345678", "qwerty", "123456789", "12345",
        "1234", "111111", "1234567", "dragon", "123123", "baseball",
        "abc123", "football", "monkey", "letmein", "shadow", "master",
        "666666", "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
        "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
        "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
        "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
        "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
        "starwars", "klaster", "112233", "george", "computer", "michelle",
        "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111",
        "131313", "freedom", "777777", "pass", "maggie", "159753",
        "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda",
        "summer", "love", "ashley", "nicole", "chelsea", "biteme",
        "matthew", "access", "yankees", "987654321", "dallas", "austin",
        "thunder", "taylor", "matrix", "qwerty123", "admin", "welcome",
        "login", "passw0rd", "password1", "password123", "qwe123",
    }
)


class PasswordCheckError(ServiceError):
    """Check failed. `code` selects a localized message in the UI."""


class Strength:
    """Offline assessment of one password's construction.

    `codes` are short reason codes the UI translates; they never
    contain any part of the password itself.
    """

    def __init__(self, score: int, codes: list[str]):
        self.score = score
        self.codes = codes


def hash_parts(password: str) -> tuple[str, str]:
    """Split the SHA-1 hash into the part we send and the part we keep.

    Only the prefix is ever transmitted. SHA-1 is not a secure choice
    for storing passwords, but that is not what happens here: HIBP's
    corpus is indexed by SHA-1, so this is the lookup key required to
    query it, and the hash never leaves this process in full.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:PREFIX_LENGTH], digest[PREFIX_LENGTH:]


def count_matches(body: str, suffix: str) -> int:
    """Find our suffix in a HIBP range response.

    The response is one "SUFFIX:COUNT" per line. Malformed lines are
    skipped rather than raising: a single bad row must not turn a
    successful lookup into an error the user has to interpret.
    """
    wanted = suffix.upper()
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() != wanted:
            continue
        try:
            return int(count)
        except ValueError:
            return 0
    return 0


def assess_strength(password: str) -> Strength:
    """Judge how hard this password is to guess, without the internet."""
    codes: list[str] = []
    length = len(password)

    if password.lower() in _COMMON_PASSWORDS:
        return Strength(min(_COMMON_PASSWORD_CEILING, length), ["pw_common"])

    # Unicode-aware by design: our users write Kazakh and Russian, and
    # a Cyrillic or Kazakh-specific letter must count as a letter.
    classes = sum(
        (
            any(char.isalpha() and char.islower() for char in password),
            any(char.isalpha() and char.isupper() for char in password),
            any(char.isdigit() for char in password),
            any(
                not char.isalnum() and not char.isspace() for char in password
            ),
        )
    )
    score = min(length, _LENGTH_CAP) * _POINTS_PER_CHARACTER
    score += max(classes - 1, 0) * _VARIETY_BONUS

    if length < _MINIMUM_LENGTH:
        codes.append("pw_too_short")
    elif length < _COMFORTABLE_LENGTH:
        codes.append("pw_short")

    if classes <= 1:
        codes.append("pw_single_class")
        if length < _COMFORTABLE_LENGTH:
            score -= _PENALTY_SINGLE_CLASS

    if _has_repeat(password):
        codes.append("pw_repeated")
        score -= _PENALTY_REPEAT

    if _has_sequence(password):
        codes.append("pw_sequential")
        score -= _PENALTY_SEQUENCE

    return Strength(max(0, min(100, score)), codes)


def _has_repeat(password: str) -> bool:
    """True when the same character runs three or more times."""
    return bool(re.search(r"(.)\1{2,}", password))


def _has_sequence(password: str) -> bool:
    """True when the password contains a keyboard or alphabet run."""
    lowered = password.lower()
    for row in _SEQUENCES:
        for start in range(len(row) - _RUN_LENGTH + 1):
            run = row[start : start + _RUN_LENGTH]
            if run in lowered or run[::-1] in lowered:
                return True
    return False


def build_report(strength: Strength, breach_count: int) -> TrustReport:
    """Turn both layers into the platform's unified report.

    A password found in breach data is treated as compromised no
    matter how strong it looks: attackers try known passwords first,
    so construction stops mattering once it is on their list.
    """
    evidence = [
        Evidence(kind="heuristic", code=code) for code in strength.codes
    ]
    if breach_count:
        evidence.append(
            Evidence(kind="external", code="pw_breached", detail=f"{breach_count:,}")
        )

    if breach_count:
        verdict = "danger"
        trust_score = 5 if breach_count > 10 else 20
        explanation_key = "password.explanation_breached"
        actions = [
            "password.rec_change_now",
            "password.rec_unique",
            "password.rec_manager",
            "password.rec_mfa",
        ]
        confidence = 95  # an exact hash match is not a judgement call
    elif strength.score < _STRONG_ENOUGH:
        verdict = "caution"
        trust_score = 45
        explanation_key = "password.explanation_weak"
        actions = ["password.rec_lengthen", "password.rec_manager", "password.rec_mfa"]
        confidence = 80
    else:
        verdict = "safe"
        # Never 100: "not in the breaches we know about" is the most
        # any check of this kind can honestly claim.
        trust_score = 85
        explanation_key = "password.explanation_clean"
        actions = ["password.rec_keep_unique", "password.rec_mfa"]
        confidence = 80

    return TrustReport(
        source="password_checker",
        subject_type="password",
        subject_preview=_PREVIEW,
        verdict=verdict,
        trust_score=trust_score,
        confidence=confidence,
        metrics=[
            Metric(
                label_key="password.metric_strength",
                value=strength.score,
                higher_is_worse=False,
            )
        ],
        evidence=evidence,
        explanation_key=explanation_key,
        recommended_action_keys=actions,
    )


def check_password(password: str) -> TrustReport:
    """Check one password and return a validated TrustReport.

    Raises:
        PasswordCheckError: With a short error code on any failure.
    """
    if not password:
        raise PasswordCheckError("empty_password")

    prefix, suffix = hash_parts(password)
    return build_report(assess_strength(password), _fetch_count(prefix, suffix))


def _fetch_count(prefix: str, suffix: str) -> int:
    """Query the breach corpus with the hash prefix only.

    Provider-specific — the only function to rewrite if the breach
    corpus ever changes.
    """
    try:
        response = requests.get(
            API_URL.format(prefix=prefix),
            headers=_PADDING_HEADER,
            timeout=REQUEST_TIMEOUT_S,
        )
    except requests.exceptions.Timeout as exc:
        raise PasswordCheckError("timeout") from exc
    except requests.exceptions.RequestException as exc:
        raise PasswordCheckError("unreachable") from exc

    if response.status_code == 429:
        raise PasswordCheckError("rate_limited")
    if response.status_code != 200:
        raise PasswordCheckError("unavailable")
    return count_matches(response.text, suffix)
