"""Email breach lookup service.

Checks whether an email address appears in publicly known data
breaches using the free XposedOrNot API. This module is UI-independent
and can move into a FastAPI backend unchanged.

Provider isolation: everything XposedOrNot-specific lives inside
_fetch_breach_names(). Swapping to another provider (e.g.
HaveIBeenPwned) means rewriting only that function — the public
interface (check_email -> EmailBreachResult) stays the same.

Language independence: recommendations are returned as short keys
(e.g. "rec_enable_mfa"); the UI translates them. Errors carry codes
for the same reason.

Privacy: nothing is stored or logged. The email is sent to the breach
database for the lookup and exists only in memory.
"""

import random
import re
from dataclasses import dataclass

import requests

from services.common import ServiceError

API_URL = "https://api.xposedornot.com/v1/check-email/{email}"
REQUEST_TIMEOUT_S = 15

# Cheap format check only — real validation is the mail server's job.
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Coaching tips for clean emails, grouped by topic. One tip is drawn
# from each group per check, so users get varied but always-useful
# advice instead of the same three lines every time.
_CLEAN_TIP_GROUPS: tuple[tuple[str, ...], ...] = (
    ("rec_unique_passwords", "rec_password_manager"),
    ("rec_enable_mfa", "rec_authenticator_app"),
    ("rec_recognize_phishing", "rec_check_sender"),
    (
        "rec_software_updates",
        "rec_browser_safety",
        "rec_wifi_caution",
        "rec_recovery_settings",
        "rec_account_monitoring",
        "rec_periodic_check",
    ),
)

# For a breached email the advice is not varied — these four steps are
# exactly what must happen, every time.
_BREACHED_RECOMMENDATIONS = (
    "rec_change_passwords",
    "rec_no_reuse",
    "rec_enable_mfa",
    "rec_watch_phishing",
)


class BreachCheckError(ServiceError):
    """Breach lookup failed. `code` selects a localized message."""


@dataclass(frozen=True)
class EmailBreachResult:
    """Outcome of one breach lookup. Exists only in memory."""

    email: str
    breached: bool
    breach_count: int
    breaches: list[str]
    risk_level: str  # "none" | "medium" | "high"
    recommendations: list[str]  # translation keys, resolved by the UI


def is_valid_email(email: str) -> bool:
    """Return True when the text looks like an email address."""
    return bool(_EMAIL_PATTERN.match(email))


def check_email(email: str) -> EmailBreachResult:
    """Look up an email address in known public data breaches.

    Args:
        email: The address to check; surrounding spaces are ignored.

    Raises:
        BreachCheckError: With a short error code on any failure.
    """
    normalized = email.strip().lower()
    if not is_valid_email(normalized):
        raise BreachCheckError("invalid_email")
    return _build_result(normalized, _fetch_breach_names(normalized))


def _fetch_breach_names(email: str) -> list[str]:
    """Query XposedOrNot and return the list of breach names.

    Provider-specific — this is the only function to rewrite when
    changing breach-data providers.
    """
    try:
        response = requests.get(
            API_URL.format(email=email), timeout=REQUEST_TIMEOUT_S
        )
    except requests.exceptions.Timeout as exc:
        raise BreachCheckError("timeout") from exc
    except requests.exceptions.RequestException as exc:
        raise BreachCheckError("unreachable") from exc

    # XposedOrNot answers 404 for "not found in any known breach".
    if response.status_code == 404:
        return []
    if response.status_code == 429:
        raise BreachCheckError("rate_limited")
    if response.status_code != 200:
        raise BreachCheckError("unavailable")

    # Breached: {"breaches": [["Name1", "Name2", ...]]}
    # Clean:    {"Error": "Not found", "email": null}  (with HTTP 200)
    try:
        payload = response.json()
        if payload.get("Error") == "Not found":
            return []
        raw = payload["breaches"]
        names = raw[0] if raw and isinstance(raw[0], list) else raw
        return [str(name) for name in names]
    except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
        raise BreachCheckError("malformed") from exc


def _clean_recommendations() -> list[str]:
    """Pick one tip per topic group, in shuffled order.

    Every tip is genuinely useful; the variation is in WHICH useful
    tips the user sees, so repeat visits feel like ongoing coaching.
    """
    picks = [random.choice(group) for group in _CLEAN_TIP_GROUPS]
    random.shuffle(picks)
    return picks


def _build_result(email: str, breaches: list[str]) -> EmailBreachResult:
    """Turn a raw breach-name list into a user-facing result."""
    count = len(breaches)
    if count == 0:
        risk_level = "none"
        recommendations = _clean_recommendations()
    else:
        risk_level = "high" if count >= 3 else "medium"
        recommendations = list(_BREACHED_RECOMMENDATIONS)
    return EmailBreachResult(
        email=email,
        breached=count > 0,
        breach_count=count,
        breaches=breaches,
        risk_level=risk_level,
        recommendations=recommendations,
    )
