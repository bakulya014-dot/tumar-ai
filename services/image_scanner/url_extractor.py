"""Find URLs in OCR text and QR payloads, and judge each address.

Judgement is delegated to the platform's existing deterministic URL
checks (services/heuristics.url_reasons): shorteners, homoglyphs,
punycode, raw IP addresses, look-alike and misspelled brand domains.
This module only adds what an image needs on top:

- OCR-tolerant extraction (engines insert spaces around dots and
  mistake "l" for "1"; the obvious cases are repaired, the rest are
  reported as-is rather than guessed at).
- An internal-address check (loopback, private, link-local, .local)
  so a QR code pointing at a router or an intranet host is flagged.
  Nothing here, or anywhere in the scanner, ever fetches a URL: the
  check is a defence for the *user*, not a server-side request guard,
  because no request is ever made.
- Honest labelling: every finding here is local heuristic analysis.
  `reputation` is always "heuristic" until a reputation feed exists.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from services.heuristics import is_strong_url_signal, url_reasons
from services.url_scanner import UrlScanError, normalize_url

# Same shape as the message scanner's URL regex, plus bare domains with
# a known-ish TLD so "kaspi-bonus.site" in a screenshot is caught even
# when the scheme was cropped off.
_SCHEMED = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
_BARE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:kz|ru|com|net|org|info|site|online|shop|store|xyz|top|"
    r"club|live|app|io|me|cc|link|click|icu|buzz|cfd|рф|ly|gl|to|co|gg|do|is|be|tv|"
    r"ws|su|by|ua|uz|kg|tj|tm|de|uk|eu|asia|pro|vip|biz|tech|digital|website|space|"
    r"fun|bond|cyou|sbs|monster|rest|lol|mobi|page|dev|one)\b(?:/[^\s<>\"')\]]*)?",
    re.IGNORECASE,
)
# OCR often renders "kaspi. kz" or "kaspi ,kz"; collapse those first.
_OCR_DOT_SPACING = re.compile(r"(?<=[a-z0-9])\s*[.,]\s+(?=(?:kz|ru|com|net|org|info|site|online)\b)", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)»”'\""

_INTERNAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet")
_INTERNAL_NAMES = {"localhost", "router", "gateway", "admin"}

MAX_URLS = 25


@dataclass(frozen=True)
class UrlFinding:
    url: str
    origin: str  # "ocr" | "qr"
    reasons: tuple[str, ...] = ()
    internal: bool = False
    reputation: str = "heuristic"  # "heuristic" until an external feed exists
    invalid: bool = False

    @property
    def strong(self) -> bool:
        return self.internal or any(is_strong_url_signal(code) for code in self.reasons)

    @property
    def suspicious(self) -> bool:
        return self.internal or bool(self.reasons)


@dataclass(frozen=True)
class UrlResult:
    status: str  # "success" | "none"
    findings: tuple[UrlFinding, ...] = field(default=())


def extract_urls(text: str) -> list[str]:
    """Candidate URLs from OCR text, de-duplicated, in reading order."""
    repaired = _OCR_DOT_SPACING.sub(".", text)
    seen: list[str] = []
    for pattern in (_SCHEMED, _BARE):
        for match in pattern.finditer(repaired):
            candidate = match.group(0).rstrip(_TRAILING_PUNCT)
            if candidate and candidate.lower() not in (s.lower() for s in seen):
                seen.append(candidate)
    # Bare matches that are inside a schemed match are duplicates.
    schemed_lower = [s.lower() for s in seen if "://" in s or s.lower().startswith("www.")]
    return [
        s for s in seen
        if "://" in s or s.lower().startswith("www.")
        or not any(s.lower() in full for full in schemed_lower)
    ][:MAX_URLS]


def is_internal_host(host: str) -> bool:
    """True for addresses that live on a private network, not the web."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    if host in _INTERNAL_NAMES or host.endswith(_INTERNAL_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_reserved or address.is_multicast or address.is_unspecified
    )


def judge(url: str, origin: str) -> UrlFinding:
    """Run the platform's URL heuristics over one address."""
    try:
        normalized = normalize_url(url)
    except UrlScanError:
        return UrlFinding(url=url[:200], origin=origin, invalid=True)
    host = urlsplit(normalized).hostname or ""
    return UrlFinding(
        url=normalized,
        origin=origin,
        reasons=tuple(url_reasons(normalized)),
        internal=is_internal_host(host),
    )


def analyze_urls(
    ocr_text: str, qr_payloads: list[str], vision_urls: list[str] | None = None
) -> UrlResult:
    """Judge every link found in the text, the QR codes and (when a
    vision model ran) what it transcribed from the address bar."""
    findings: list[UrlFinding] = []
    seen: set[str] = set()
    for origin, candidates in (
        ("qr", qr_payloads),
        ("ocr", extract_urls(ocr_text)),
        ("vision", list(vision_urls or [])),
    ):
        for candidate in candidates:
            finding = judge(candidate, origin)
            key = finding.url.lower()
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    if not findings:
        return UrlResult(status="none")
    return UrlResult(status="success", findings=tuple(findings[:MAX_URLS]))
