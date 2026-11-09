"""End-to-end cybersecurity news intelligence pipeline.

Designed to run in background worker threads (e.g. via asyncio.to_thread)
to prevent blocking the Telegram bot's async event loop.
"""

import logging
import os

from app.news.collector import fetch_cybersecurity_news
from app.news.summarizer import summarize_news

logger = logging.getLogger(__name__)


def run_news_pipeline(limit: int = 3, api_key: str | None = None) -> str:
    """Execute the end-to-end cybersecurity news intelligence pipeline.

    1. Scans curated live RSS/Atom threat feeds.
    2. Filters and synthesizes critical advisories using Gemini AI (or fallback).
    3. Returns a clean, HTML-formatted digest ready for Telegram delivery.

    Args:
        limit: Number of top stories/threats to highlight.
        api_key: Optional Gemini API key (falls back to GEMINI_API_KEY env).

    Returns:
        Telegram HTML-compatible text digest.
    """
    logger.info("Executing Tumar.AI news pipeline (limit=%d)...", limit)
    try:
        articles = fetch_cybersecurity_news(max_items=8)
        resolved_key = api_key or os.getenv("GEMINI_API_KEY")
        digest = summarize_news(articles=articles, api_key=resolved_key, limit=limit)
        return digest
    except Exception as exc:
        logger.exception("Failed to run news pipeline: %s", exc)
        return (
            "⚠️ <b>News Service Notice:</b> Unable to fetch intelligence feeds at the moment. "
            "Please try again shortly."
        )
