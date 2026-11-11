"""Telegram bot command handlers for Tumar.AI cybersecurity defense hub.

Provides interactive commands:
- /start, /help: Onboarding and interactive capability dashboard.
- /news: Live cybersecurity threat intelligence feed summarized with AI.
- /check <email/user>: Breach and credential exposure lookup.
- /scan <url/domain/IP>: Threat reputation and malicious indicator scan.
- /audit <text/snippet>: Contextual security risk evaluation and scoring.
- /tip: Student-focused OpSec and endpoint hardening tips.
"""

import asyncio
import html
import ipaddress
import logging
import os
import random

from aiogram import F, Router
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
import requests

from app.news.pipeline import run_news_pipeline
from i18n import language_from_locale, translate
from services.breach_checker import is_valid_email
from services.common import ServiceError
from services import telemetry
from services.quota import default_quota
from services.trust_engine import AnalysisContext, TrustEngine, TrustSubject, UrlAnalyzer
from telegram_bot.report_format import format_report

logger = logging.getLogger(__name__)

commands_router = Router(name="commands_router")

# One engine for every channel: the bot reaches the same analyzers, the
# same scoring and the same evidence as the web app and the REST API, so
# a message cannot get one verdict here and another on the website —
# online or offline. When the AI provider fails, the engine itself
# returns the shared rules-only report (services/offline_report.py),
# exactly as the website shows it.
_ENGINE = TrustEngine()
# The engine's own link test, so "/scan" decides link-or-text exactly as
# the web app's Quick Check does.
_LINK_DETECTOR = UrlAnalyzer()


def _ai_key() -> str:
    return os.getenv("GEMINI_API_KEY", "").strip()


def _engine_report(
    content: str, kind: str, language: str, title: str, user_id: int | None = None
) -> str:
    """Analyze through the shared Trust Engine and format for Telegram.

    A provider failure comes back as the engine's labelled offline
    report: the reply then says so, and the user's check is refunded
    because it never reached the paid service. Raises ServiceError only
    for problems an offline check cannot fix (invalid input, breach
    database down).
    """
    report = _ENGINE.analyze(
        TrustSubject(content=content, declared_kind=kind, language=language),
        AnalysisContext(api_key=_ai_key(), offline_fallback=True, channel="telegram"),
    )
    text = format_report(report, title, language)
    if report.analysis_metadata.get("mode") == "offline":
        logger.info("Offline report for kind=%s (reason=%s)", kind, report.analysis_metadata.get("offline_reason"))
        refund_check(user_id, kind)
        note = html.escape(translate("trust.offline.bot_note", language))
        text = f"⚠️ <i>{note}</i>\n\n{text}"
    return text


def refund_check(user_id: int | None, kind: str) -> None:
    """Give back a check that did not reach the paid service."""
    if user_id is not None:
        default_quota().refund(f"tg:{user_id}", "bot", kind)


def _user_id(message: Message) -> int | None:
    return message.from_user.id if message.from_user else None


def message_language(message: Message) -> str:
    """The user's Telegram language, if Tumar.AI speaks it (kk/ru/en)."""
    user = message.from_user
    return language_from_locale(user.language_code if user else None)


async def quota_allows(message: Message, kind: str) -> bool:
    """Count one paid check for this Telegram user; explain when over the limit."""
    user = message.from_user
    if user is None:
        return True
    telemetry.begin_request()  # one id for this check, from quota to model call
    decision = default_quota().consume(f"tg:{user.id}", "bot", kind)
    if decision.allowed:
        return True
    text = translate("quota.exceeded_bot", message_language(message), limit=decision.limit)
    await message.answer(f"⏳ {html.escape(text)}", parse_mode=ParseMode.HTML)
    return False


# ----------------- Onboarding & Dashboards -----------------

def get_onboarding_keyboard(language: str = "en") -> InlineKeyboardMarkup:
    """Build interactive dashboard inline buttons."""

    def button(name: str, callback: str) -> InlineKeyboardButton:
        return InlineKeyboardButton(text=translate(f"bot.button.{name}", language), callback_data=callback)

    return InlineKeyboardMarkup(
        inline_keyboard=[
            [button("news", "act_news"), button("tip", "act_tip")],
            [button("check", "act_check_help"), button("scan", "act_scan_help")],
            [button("audit", "act_audit_help")],
        ]
    )




@commands_router.message(CommandStart())
@commands_router.message(Command("help"))
async def cmd_start_and_help(message: Message) -> None:
    """Send interactive onboarding dashboard."""
    language = message_language(message)
    await message.answer(
        text=translate("bot.onboarding", language),
        parse_mode=ParseMode.HTML,
        reply_markup=get_onboarding_keyboard(language),
        disable_web_page_preview=True,
    )


# ----------------- /news Handler -----------------

@commands_router.message(Command("news"))
async def cmd_news(message: Message, language: str | None = None) -> None:
    """Deliver fresh live cybersecurity news filtered by AI."""
    language = language or message_language(message)
    status = await message.answer(translate("bot.news.progress", language), parse_mode=ParseMode.HTML)

    try:
        digest = await asyncio.to_thread(run_news_pipeline, limit=3)
        await status.edit_text(
            text=digest,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception as exc:
        logger.exception("Failed delivering /news: %s", exc)
        await status.edit_text(translate("bot.news.error", language), parse_mode=ParseMode.HTML)


# ----------------- /check Handler -----------------

def _query_breach_analytics(email: str) -> dict:
    """Fetch extended breach analytics from XposedOrNot if available."""
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={email.strip().lower()}"
    try:
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        logger.debug("Extended breach-analytics fetch failed: %s", exc)
    return {}


def _extract_exposed_fields(analytics: dict) -> list[str]:
    """Extract human-readable exposed fields (passwords, phone numbers, etc.)."""
    fields: set[str] = set()
    try:
        xposed_data = analytics.get("BreachMetrics", {}).get("xposed_data", [])
        for category in xposed_data:
            for child in category.get("children", []):
                for item in child.get("children", []):
                    name = item.get("name", "")
                    if name.startswith("data_"):
                        fields.add(name.replace("data_", ""))
    except Exception:
        pass
    return sorted(fields)


def _perform_breach_check(target: str, language: str = "en", user_id: int | None = None) -> str:
    """Core breach intelligence lookup logic.

    Email addresses go through the shared Trust Engine (the same breach
    report as the web app). The extra "exposed fields" line comes from
    XposedOrNot's analytics endpoint, which the engine does not use yet.
    """
    clean_target = target.strip().lower()

    if is_valid_email(clean_target):
        try:
            text = _engine_report(clean_target, "email", language, translate("bot.title.breach", language), user_id)
        except ServiceError as err:
            refund_check(user_id, "email")
            logger.warning("Email check failed: %s", err.code)
            return translate("bot.check.unavailable", language)
        exposed_fields = _extract_exposed_fields(_query_breach_analytics(clean_target))
        if exposed_fields:
            fields = html.escape(", ".join(exposed_fields[:6]))
            text += "\n\n" + translate("bot.check.exposed_fields", language, fields=fields)
        return text

    # If target is a username (no domain provided)
    clean_username = clean_target.lstrip("@")
    masked_user = f"{clean_username[:2]}***" if len(clean_username) > 2 else clean_username

    try:
        resp = requests.get(f"https://api.xposedornot.com/v1/check-email/{clean_username}", timeout=10)
        has_hits = False
        breach_count = 0
        if resp.status_code == 200:
            payload = resp.json()
            if payload.get("Error") != "Not found":
                raw = payload.get("breaches", [])
                names = raw[0] if raw and isinstance(raw[0], list) else raw
                breach_count = len(names)
                has_hits = breach_count > 0
    except Exception:
        has_hits = False
        breach_count = 0

    if has_hits:
        return translate(
            "bot.check.username_exposed", language, user=html.escape(masked_user), count=breach_count
        )
    return translate("bot.check.username_clear", language, user=html.escape(masked_user))


@commands_router.message(Command("check"))
async def cmd_check(message: Message) -> None:
    """Query breach and exposure status for an email or username."""
    parts = message.text.split(maxsplit=1)
    target = parts[1].strip() if len(parts) > 1 else ""

    if not target and message.reply_to_message:
        target = (message.reply_to_message.text or message.reply_to_message.caption or "").strip()

    language = message_language(message)
    if not target:
        await message.answer(translate("bot.check.usage", language), parse_mode=ParseMode.HTML)
        return

    if not await quota_allows(message, "email"):
        return

    status = await message.answer(translate("bot.check.progress", language), parse_mode=ParseMode.HTML)

    try:
        report = await asyncio.to_thread(_perform_breach_check, target, language, _user_id(message))
        await status.edit_text(report, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.exception("Breach check encountered failure: %s", exc)
        await status.edit_text(translate("bot.check.unavailable", language), parse_mode=ParseMode.HTML)


# ----------------- /scan Handler -----------------

def _perform_scan(target: str, language: str = "en", user_id: int | None = None) -> str:
    """Analyze a URL, domain, or IP address for threats and reputation."""
    candidate = target.strip()

    # 1. Check if target is an IP address
    try:
        ip = ipaddress.ip_address(candidate)
        target_html = html.escape(candidate)
        if ip.is_private or ip.is_loopback:
            return translate("bot.scan.private_ip", language, target=target_html)
        # Public IP direct address
        return translate("bot.scan.public_ip", language, target=target_html)
    except ValueError:
        pass  # Not an IP address, proceed to domain/URL evaluation

    # 2. Not a link at all — a pasted message or sentence. The legacy bot
    # advertised "/scan text", so people send text here; checking it as
    # a URL would wrongly report "no malicious signals". Run the message
    # check instead, the same analysis /audit gives.
    if not _LINK_DETECTOR.can_handle(TrustSubject(content=candidate)):
        return _perform_audit(candidate, language, user_id)

    # 3. URL or domain: the shared Trust Engine, as on the web. If the AI
    # provider fails, the engine returns the shared offline report.
    try:
        return _engine_report(candidate, "url", language, translate("bot.title.scan", language), user_id)
    except ServiceError as exc:
        logger.info("URL scan failed: %s", exc.code)
        refund_check(user_id, "url")
        return f"⚠️ {html.escape(translate(f'errors.{exc.code}', language))}"


@commands_router.message(Command("scan"))
async def cmd_scan(message: Message) -> None:
    """Evaluate reputations, malicious indicators, or suspicious links."""
    parts = message.text.split(maxsplit=1)
    target = parts[1].strip() if len(parts) > 1 else ""

    if not target and message.reply_to_message:
        target = (message.reply_to_message.text or message.reply_to_message.caption or "").strip()

    language = message_language(message)
    if not target:
        await message.answer(translate("bot.scan.usage", language), parse_mode=ParseMode.HTML)
        return

    if not await quota_allows(message, "url"):
        return

    status = await message.answer(translate("bot.scan.progress", language), parse_mode=ParseMode.HTML)

    try:
        report = await asyncio.to_thread(_perform_scan, target, language, _user_id(message))
        await status.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as exc:
        logger.exception("Scan error: %s", exc)
        await status.edit_text(translate("bot.scan.failed", language), parse_mode=ParseMode.HTML)


# ----------------- /audit Handler -----------------

def _perform_audit(snippet: str, language: str = "en", user_id: int | None = None) -> str:
    """Execute contextual security evaluation on text, messages, or configurations.

    One path for online and offline alike: the shared Trust Engine. If
    the AI provider fails, the engine's rules-only report is shown,
    labelled — the same report the website shows.
    """
    clean_text = snippet.strip()
    try:
        return _engine_report(clean_text, "message", language, translate("bot.title.audit", language), user_id)
    except ServiceError as exc:
        logger.info("Audit failed: %s", exc.code)
        refund_check(user_id, "message")
        return f"⚠️ {html.escape(translate(f'errors.{exc.code}', language))}"


@commands_router.message(Command("audit"))
async def cmd_audit(message: Message) -> None:
    """Run contextual security evaluation on provided text snippet."""
    parts = message.text.split(maxsplit=1)
    snippet = parts[1].strip() if len(parts) > 1 else ""

    if not snippet and message.reply_to_message:
        snippet = (message.reply_to_message.text or message.reply_to_message.caption or "").strip()

    language = message_language(message)
    if not snippet:
        await message.answer(translate("bot.audit.usage", language), parse_mode=ParseMode.HTML)
        return

    if not await quota_allows(message, "message"):
        return

    status = await message.answer(translate("bot.audit.progress", language), parse_mode=ParseMode.HTML)

    try:
        report = await asyncio.to_thread(_perform_audit, snippet, language, _user_id(message))
        await status.edit_text(report, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.exception("Audit error: %s", exc)
        await status.edit_text(translate("bot.audit.failed", language), parse_mode=ParseMode.HTML)


# ----------------- /tip Handler -----------------

# Keys of the curated tips under bot.tips.* in i18n/*.json.
TIP_KEYS = (
    "wifi", "passwords", "twofa", "terminals", "secrets", "phishing", "telegram", "encryption",
)


def opsec_tips(language: str = "en") -> tuple[tuple[str, str], ...]:
    """(title, advice) for every curated tip, in `language`."""
    return tuple(
        (translate(f"bot.tips.{key}.title", language), translate(f"bot.tips.{key}.text", language))
        for key in TIP_KEYS
    )


@commands_router.message(Command("tip"))
async def cmd_tip(message: Message, language: str | None = None) -> None:
    """Deliver a curated, student-focused operational security (OpSec) tip."""
    language = language or message_language(message)
    title, advice = random.choice(opsec_tips(language))
    text = (
        f"{translate('bot.tip.header', language)}\n\n"
        f"{title}\n"
        f"{advice}\n\n"
        f"{translate('bot.tip.footer', language)}"
    )
    await message.answer(text, parse_mode=ParseMode.HTML)


# ----------------- Callback Handlers -----------------

@commands_router.callback_query(F.data.startswith("act_"))
async def handle_dashboard_actions(callback: CallbackQuery) -> None:
    """Handle interactive dashboard inline buttons."""
    await callback.answer()
    data = callback.data or ""
    # callback.message was sent by the bot, so its sender's locale is the
    # bot's: take the language from the user who pressed the button.
    language = language_from_locale(callback.from_user.language_code if callback.from_user else None)

    if data == "act_news":
        if callback.message:
            await cmd_news(callback.message, language)
    elif data == "act_tip":
        if callback.message:
            await cmd_tip(callback.message, language)
    elif data in ("act_check_help", "act_scan_help", "act_audit_help"):
        if callback.message:
            topic = data.removeprefix("act_").removesuffix("_help")
            await callback.message.answer(translate(f"bot.help.{topic}", language), parse_mode=ParseMode.HTML)
