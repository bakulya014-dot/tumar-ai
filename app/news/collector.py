"""Live cybersecurity intelligence and feed collector for Tumar.AI.

Collects recent threat alerts, vulnerabilities, and security news from
curated industry feeds without requiring UI dependencies.
"""

from dataclasses import dataclass
import html
import logging
import re
from typing import Sequence
import urllib.request

import feedparser

logger = logging.getLogger(__name__)

# Curated high-reputation cybersecurity RSS feeds
DEFAULT_FEEDS = (
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
)

REQUEST_TIMEOUT_S = 10
_TAG_RE = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class NewsArticle:
    """Represents a collected cybersecurity news item."""

    title: str
    link: str
    summary: str
    published: str
    source: str


# Fallback intelligence pool when feeds are unreachable (e.g. offline/network timeout)
FALLBACK_ARTICLES: tuple[NewsArticle, ...] = (
    NewsArticle(
        title="Zero-Day Vulnerability Patched in Major Web Browsers",
        link="https://cve.mitre.org",
        summary="Security teams advise immediate patching after proof-of-concept exploits were detected in the wild affecting V8 engine rendering.",
        published="Recent",
        source="Tumar Intel",
    ),
    NewsArticle(
        title="Widespread Phishing Campaign Targets University & Corporate Portals",
        link="https://www.cisa.gov",
        summary="Threat actors are leveraging reverse-proxy toolkits to bypass multi-factor authentication (MFA) on student and enterprise Single Sign-On (SSO) gateways.",
        published="Recent",
        source="Tumar Intel",
    ),
    NewsArticle(
        title="Malicious Packages Discovered in Public Open-Source Registries",
        link="https://nvd.nist.gov",
        summary="Typosquatting packages imitating popular developer libraries were identified harboring credential exfiltration scripts.",
        published="Recent",
        source="Tumar Intel",
    ),
)


def _strip_html(raw_html: str) -> str:
    """Remove HTML markup and decode entities to clean plaintext."""
    if not raw_html:
        return ""
    clean = _TAG_RE.sub(" ", raw_html)
    text = " ".join(html.unescape(clean).split())
    # Fix spacing before common punctuation introduced by tag removal
    return re.sub(r"\s+([,.:;!?])", r"\1", text)


def fetch_cybersecurity_news(
    max_items: int = 6,
    feeds: Sequence[tuple[str, str]] = DEFAULT_FEEDS,
) -> list[NewsArticle]:
    """Scan live RSS feeds for cybersecurity news and alerts.

    Args:
        max_items: Maximum number of articles to return.
        feeds: List of (source_name, feed_url) pairs.

    Returns:
        List of cleaned, deduplicated NewsArticle instances.
    """
    collected: list[NewsArticle] = []
    seen_titles: set[str] = set()

    for source_name, feed_url in feeds:
        try:
            req = urllib.request.Request(
                feed_url,
                headers={"User-Agent": "TumarAI-CyberDefenseBot/1.0 (+https://tumar.ai)"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as response:
                content = response.read()

            parsed = feedparser.parse(content)
            for entry in parsed.entries[:max_items]:
                title = _strip_html(entry.get("title", "")).strip()
                if not title or title.lower() in seen_titles:
                    continue
                seen_titles.add(title.lower())

                raw_summary = entry.get("summary", "") or entry.get("description", "")
                clean_summary = _strip_html(raw_summary).strip()
                link = entry.get("link", "").strip()
                published = entry.get("published", "") or entry.get("updated", "") or "Recent"

                collected.append(
                    NewsArticle(
                        title=title,
                        link=link,
                        summary=clean_summary[:300],
                        published=published[:25],
                        source=source_name,
                    )
                )
                if len(collected) >= max_items:
                    break
        except Exception as exc:
            logger.warning("Feed fetch failed for %s (%s): %s", source_name, feed_url, exc)

        if len(collected) >= max_items:
            break

    # If live feeds yielded no results (e.g. offline/network blocked), use fallback intelligence
    if not collected:
        collected = list(FALLBACK_ARTICLES[:max_items])

    return collected
