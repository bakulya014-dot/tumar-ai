"""Cybersecurity news intelligence filtering and summarization using Gemini AI.

Transforms raw feeds into high-impact, actionable threat digests formatted
for Telegram HTML messaging without any UI dependencies.
"""

import html
import logging
import os
from typing import Sequence

from google import genai
from google.genai import errors as genai_errors

from app.news.collector import NewsArticle

logger = logging.getLogger(__name__)

# Candidate models in order of preference
GEMINI_MODELS = (
    "gemini-2.5-flash",
    "gemini-3.5-flash",
    "gemini-2.5-flash-lite",
)

SYSTEM_PROMPT = """You are Tumar.AI, an elite cybersecurity intelligence and threat monitoring engine.
Your task is to review the provided cybersecurity news items, select the most critical threat alerts or developments, and generate a concise, high-impact executive digest for Telegram users (students, engineers, security analysts).

Format your output STRICTLY using Telegram-supported HTML tags (<b>, <i>, <a>, <code>):
- Start with a clear header: 🛡️ <b>TUMAR.AI CYBER THREAT DIGEST</b>
- For each selected item (up to 3 items):
  • <b>[Threat/Advisory Title]</b> (Source: <i>[Source Name]</i>)
    <b>Impact:</b> [1-2 sentences on the vulnerability, exploit, or risk]
    <b>Actionable Defense:</b> [1 clear mitigation or defensive hygiene step]
    <a href="[URL]">Read Advisory</a>
- Conclude with a short defensive tip or OpSec reminder.

Do not use Markdown (no **, #, or ```). Keep explanations sharp and actionable."""


def _format_rule_based(articles: Sequence[NewsArticle], limit: int = 3) -> str:
    """Deterministic fallback digest when AI client is unconfigured or unavailable."""
    lines: list[str] = [
        "🛡️ <b>TUMAR.AI CYBER THREAT DIGEST</b>",
        "<i>Direct Live Feed Dispatch</i>\n",
    ]
    for idx, art in enumerate(articles[:limit], 1):
        safe_title = html.escape(art.title)
        safe_source = html.escape(art.source)
        safe_summary = html.escape(art.summary)
        link_line = f' <a href="{html.escape(art.link)}">Read More</a>' if art.link else ""
        lines.append(
            f"<b>{idx}. {safe_title}</b>\n"
            f"📡 <i>Source: {safe_source}</i>\n"
            f"• {safe_summary}{link_line}\n"
        )
    lines.append("💡 <i>Defensive Tip: Keep endpoints patched and verify multi-factor prompts.</i>")
    return "\n".join(lines)


def summarize_news(
    articles: Sequence[NewsArticle],
    api_key: str | None = None,
    limit: int = 3,
) -> str:
    """Summarize and prioritize cybersecurity articles with Gemini AI.

    Args:
        articles: Sequence of collected NewsArticle items.
        api_key: Gemini API key (defaults to GEMINI_API_KEY environment variable).
        limit: Maximum number of articles to highlight.

    Returns:
        Telegram HTML-formatted cyber intelligence digest.
    """
    if not articles:
        return "⚠️ <i>No recent cybersecurity updates found at this time.</i>"

    resolved_key = (api_key or os.getenv("GEMINI_API_KEY", "")).strip()
    if not resolved_key:
        logger.info("GEMINI_API_KEY not configured; using deterministic digest.")
        return _format_rule_based(articles, limit=limit)

    articles_text = "\n\n".join(
        f"Item {i+1}:\n"
        f"Title: {a.title}\n"
        f"Source: {a.source}\n"
        f"Link: {a.link}\n"
        f"Summary: {a.summary}"
        for i, a in enumerate(articles[:6])
    )

    prompt = (
        f"Analyze these {len(articles[:6])} cybersecurity news items and synthesize the top {limit} "
        f"threats into a high-impact Telegram digest:\n\n{articles_text}"
    )

    try:
        client = genai.Client(api_key=resolved_key)
        for model in GEMINI_MODELS:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=genai.types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        temperature=0.2,
                    ),
                )
                if response and response.text:
                    return response.text.strip()
            except genai_errors.APIError as api_err:
                logger.warning("Gemini model %s failed: %s", model, api_err)
                continue
    except Exception as exc:
        logger.warning("AI summarization encountered error: %s; falling back to direct feed.", exc)

    return _format_rule_based(articles, limit=limit)
