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

def get_onboarding_keyboard() -> InlineKeyboardMarkup:
    """Build interactive dashboard inline buttons."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="📰 Live Threat News", callback_data="act_news"),
                InlineKeyboardButton(text="💡 OpSec Tip", callback_data="act_tip"),
            ],
            [
                InlineKeyboardButton(text="🔍 Check Account", callback_data="act_check_help"),
                InlineKeyboardButton(text="🌐 Scan Target", callback_data="act_scan_help"),
            ],
            [
                InlineKeyboardButton(text="🧠 Deep AI Audit", callback_data="act_audit_help"),
            ],
        ]
    )


ONBOARDING_TEXT = (
    "🛡️ <b>Tumar.AI Cyber Defense Hub</b>\n\n"
    "Welcome! Tumar.AI is an AI-augmented cybersecurity defense and intelligence engine "
    "designed to protect students, developers, and digital citizens from modern cyber threats.\n\n"
    "<b>Available Commands:</b>\n"
    "• <code>/check &lt;email/user&gt;</code> — Data breach & exposed credential lookup\n"
    "• <code>/scan &lt;url/domain/IP&gt;</code> — Rapid threat scanner & malicious link evaluator\n"
    "• <code>/audit &lt;text/snippet&gt;</code> — Deep contextual scam & phishing risk audit\n"
    "• <b>Send a screenshot</b> — Reads its text, QR codes and links and rates the risk "
    "(in groups: reply to it with <code>/screenshot</code>)\n"
    "• <code>/news</code> — Real-time AI synthesized cyber threat intel digest\n"
    "• <code>/tip</code> — Curated student OpSec & endpoint hardening advice\n"
    "• <code>/help</code> — Open this interactive capabilities guide\n\n"
    "<i>Tap any button below to get started or run a test:</i>"
)


@commands_router.message(CommandStart())
@commands_router.message(Command("help"))
async def cmd_start_and_help(message: Message) -> None:
    """Send interactive onboarding dashboard."""
    await message.answer(
        text=ONBOARDING_TEXT,
        parse_mode=ParseMode.HTML,
        reply_markup=get_onboarding_keyboard(),
        disable_web_page_preview=True,
    )


# ----------------- /news Handler -----------------

@commands_router.message(Command("news"))
async def cmd_news(message: Message) -> None:
    """Deliver fresh live cybersecurity news filtered by AI."""
    status = await message.answer(
        "📡 <i>Scanning live cybersecurity threat feeds & synthesizing with AI...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        digest = await asyncio.to_thread(run_news_pipeline, limit=3)
        await status.edit_text(
            text=digest,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )
    except Exception as exc:
        logger.exception("Failed delivering /news: %s", exc)
        await status.edit_text(
            "⚠️ <b>Error:</b> Unable to deliver news intelligence at this moment. Please try again later.",
            parse_mode=ParseMode.HTML,
        )


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
            text = _engine_report(clean_target, "email", language, "TUMAR BREACH INTELLIGENCE REPORT", user_id)
        except ServiceError as err:
            refund_check(user_id, "email")
            logger.warning("Email check failed: %s", err.code)
            return (
                "⚠️ <b>Lookup Notice:</b> Unable to reach breach registries at this time. "
                "Please try again shortly."
            )
        exposed_fields = _extract_exposed_fields(_query_breach_analytics(clean_target))
        if exposed_fields:
            text += f"\n\n🔓 <b>Exposed data types:</b> <code>{html.escape(', '.join(exposed_fields[:6]))}</code>"
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
        return (
            f"🚨 <b>TUMAR USERNAME EXPOSURE NOTICE</b>\n\n"
            f"🎯 <b>Target Username:</b> <code>{html.escape(masked_user)}</code>\n"
            f"⚠️ <b>Incident Count:</b> <code>{breach_count} breaches</code>\n"
            f"⚡ <b>Risk Level:</b> 🟡 <b>ELEVATED</b>\n\n"
            f"💡 <b>Recommendation:</b> For an exhaustive exposure analysis with detailed fields, "
            f"run <code>/check your_email@domain.com</code>."
        )

    return (
        f"🛡️ <b>TUMAR USERNAME REPUTATION CHECK</b>\n\n"
        f"🎯 <b>Target:</b> <code>{html.escape(masked_user)}</code>\n"
        f"🟢 <b>Exposure Status:</b> <b>NO PUBLIC EXPOSURE FOUND</b>\n"
        f"🔒 <b>Risk Level:</b> <b>Minimal</b>\n\n"
        f"💡 <i>Tip: For comprehensive exposure & breach analysis, please specify your full email address "
        f"(e.g. <code>/check student@university.edu</code>).</i>"
    )


@commands_router.message(Command("check"))
async def cmd_check(message: Message) -> None:
    """Query breach and exposure status for an email or username."""
    parts = message.text.split(maxsplit=1)
    target = parts[1].strip() if len(parts) > 1 else ""

    if not target and message.reply_to_message:
        target = (message.reply_to_message.text or message.reply_to_message.caption or "").strip()

    if not target:
        await message.answer(
            "⚠️ <b>Usage:</b> <code>/check &lt;email or username&gt;</code>\n\n"
            "<i>Examples:</i>\n"
            "• <code>/check student@example.com</code>\n"
            "• <code>/check username</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    if not await quota_allows(message, "email"):
        return

    status = await message.answer(
        "🔍 <i>Querying known breach registries & exposure indexes...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        report = await asyncio.to_thread(
            _perform_breach_check, target, message_language(message), _user_id(message)
        )
        await status.edit_text(report, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.exception("Breach check encountered failure: %s", exc)
        await status.edit_text(
            "⚠️ <b>Lookup Notice:</b> Unable to reach breach registries at this time. "
            "Please try again shortly.",
            parse_mode=ParseMode.HTML,
        )


# ----------------- /scan Handler -----------------

def _perform_scan(target: str, language: str = "en", user_id: int | None = None) -> str:
    """Analyze a URL, domain, or IP address for threats and reputation."""
    candidate = target.strip()

    # 1. Check if target is an IP address
    try:
        ip = ipaddress.ip_address(candidate)
        if ip.is_private or ip.is_loopback:
            return (
                f"🛡️ <b>TUMAR IP THREAT INTELLIGENCE</b>\n\n"
                f"🎯 <b>Target:</b> <code>{html.escape(candidate)}</code>\n"
                f"📌 <b>Classification:</b> <b>Private / Internal RFC1918 Address</b>\n"
                f"✅ <b>Verdict:</b> <b>LOCAL / NON-ROUTABLE</b>\n"
                f"💡 <b>Info:</b> This address is reserved for local network routing and cannot be accessed "
                f"directly from the public internet."
            )
        # Public IP direct address
        return (
            f"⚠️ <b>TUMAR IP THREAT INTELLIGENCE</b>\n\n"
            f"🎯 <b>Target:</b> <code>{html.escape(candidate)}</code>\n"
            f"📌 <b>Classification:</b> <b>Direct Public IP Host</b>\n"
            f"🟡 <b>Verdict:</b> <b>CAUTION (Elevated Alert)</b>\n"
            f"🚩 <b>Indicators:</b>\n"
            f"• Direct IP access bypasses standard DNS reputation layers.\n"
            f"• Attackers frequently host temporary phishing sites on direct IPs to evade domain take-downs.\n\n"
            f"💡 <b>Action:</b> Do not enter passwords, API credentials, or card details on direct IP hosts."
        )
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
        return _engine_report(candidate, "url", language, "TUMAR THREAT INTELLIGENCE SCAN", user_id)
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

    if not target:
        await message.answer(
            "⚠️ <b>Usage:</b> <code>/scan &lt;link, domain, IP or message&gt;</code>\n\n"
            "<i>Examples:</i>\n"
            "• <code>/scan https://suspicious-verify.xyz</code>\n"
            "• <code>/scan 185.220.101.5</code>\n"
            "• <code>/scan portal-login.site</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    if not await quota_allows(message, "url"):
        return

    status = await message.answer(
        "🛡️ <i>Evaluating threat signals, indicators & reputation...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        report = await asyncio.to_thread(
            _perform_scan, target, message_language(message), _user_id(message)
        )
        await status.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as exc:
        logger.exception("Scan error: %s", exc)
        await status.edit_text(
            "⚠️ <b>Scan Notice:</b> Analysis failed for the provided target. Please verify format.",
            parse_mode=ParseMode.HTML,
        )


# ----------------- /audit Handler -----------------

def _perform_audit(snippet: str, language: str = "en", user_id: int | None = None) -> str:
    """Execute contextual security evaluation on text, messages, or configurations.

    One path for online and offline alike: the shared Trust Engine. If
    the AI provider fails, the engine's rules-only report is shown,
    labelled — the same report the website shows.
    """
    clean_text = snippet.strip()
    try:
        return _engine_report(clean_text, "message", language, "TUMAR CONTEXTUAL SECURITY AUDIT", user_id)
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

    if not snippet:
        await message.answer(
            "⚠️ <b>Usage:</b> <code>/audit &lt;message or snippet&gt;</code>\n\n"
            "<i>Example:</i>\n"
            "<code>/audit Urgent! Your university portal will be deactivated within 1 hour. "
            "Click here to confirm your credentials.</code>\n\n"
            "<i>(You can also reply to any message with /audit)</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    if not await quota_allows(message, "message"):
        return

    status = await message.answer(
        "🧠 <i>Running contextual security audit & risk evaluation...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        report = await asyncio.to_thread(
            _perform_audit, snippet, message_language(message), _user_id(message)
        )
        await status.edit_text(report, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.exception("Audit error: %s", exc)
        await status.edit_text(
            "⚠️ <b>Audit Notice:</b> Unable to complete analysis at this time. Please try again.",
            parse_mode=ParseMode.HTML,
        )


# ----------------- /tip Handler -----------------

STUDENT_OPSEC_TIPS = (
    (
        "🎓 <b>Campus Wi-Fi Defense</b>",
        "Public university Wi-Fi is shared by thousands of devices. Never access financial accounts "
        "or internal student portals without verified HTTPS and an encrypted DNS (DoH/DoT) or VPN enabled.",
    ),
    (
        "🔐 <b>Master Your Credentials</b>",
        "Never reuse passwords between your university portal, social media, and email. Use an open-source "
        "password manager (like Bitwarden) with a strong, 4-word diceware passphrase.",
    ),
    (
        "🔑 <b>Upgrade Beyond SMS 2FA</b>",
        "SMS verification codes can be intercepted via SIM-swapping and SS7 attacks. Switch your Google, "
        "Telegram, and GitHub accounts to hardware security keys (FIDO2) or authenticator apps (Aegis/Yubico).",
    ),
    (
        "💻 <b>Public Terminal Hygiene</b>",
        "When using library or computer lab workstations, always browse in Incognito/Private mode, never save "
        "credentials, and explicitly click 'Sign Out' before leaving your seat.",
    ),
    (
        "⚡ <b>Avoid Committing Secrets</b>",
        "Student developers: never commit <code>.env</code> files, API tokens, or database passwords to public "
        "GitHub repositories. Use <code>.gitignore</code> and automated secret scanners like <code>git-secrets</code>.",
    ),
    (
        "🎣 <b>Spotting University Phishing</b>",
        "Beware of emails claiming 'Emergency Financial Aid Refund' or 'Urgent Course Tuition Payment'. "
        "Always check sender headers and never log in via emailed links.",
    ),
    (
        "📱 <b>Telegram Account Hardening</b>",
        "In Telegram Settings → Privacy and Security: Enable Two-Step Verification (Cloud Password) and "
        "restrict 'Who can find me by phone number' to 'My Contacts'.",
    ),
    (
        "🔒 <b>Full Disk Encryption</b>",
        "Enable BitLocker (Windows) or FileVault (macOS). If your laptop is lost or stolen on campus, "
        "attackers cannot pull raw files from the hard drive without your encryption key.",
    ),
)


@commands_router.message(Command("tip"))
async def cmd_tip(message: Message) -> None:
    """Deliver a curated, student-focused operational security (OpSec) tip."""
    title, advice = random.choice(STUDENT_OPSEC_TIPS)
    text = (
        f"💡 <b>TUMAR OPSEC & HARDENING TIP</b>\n\n"
        f"{title}\n"
        f"{advice}\n\n"
        f"🛡️ <i>Stay safe • Tumar 24/7 Shield</i>"
    )
    await message.answer(text, parse_mode=ParseMode.HTML)


# ----------------- Callback Handlers -----------------

@commands_router.callback_query(F.data.startswith("act_"))
async def handle_dashboard_actions(callback: CallbackQuery) -> None:
    """Handle interactive dashboard inline buttons."""
    await callback.answer()
    data = callback.data or ""

    if data == "act_news":
        if callback.message:
            await cmd_news(callback.message)
    elif data == "act_tip":
        if callback.message:
            await cmd_tip(callback.message)
    elif data == "act_check_help":
        await callback.message.answer(
            "🔍 <b>Check Breach & Exposure</b>\n\n"
            "Send: <code>/check student@university.edu</code>\n"
            "Queries global data breach registries for incident counts, exposed passwords, and risk levels.",
            parse_mode=ParseMode.HTML,
        )
    elif data == "act_scan_help":
        await callback.message.answer(
            "🌐 <b>Threat & Reputation Scanner</b>\n\n"
            "Send: <code>/scan https://suspicious-link.com</code>\n"
            "Evaluates URLs, domains, and IP addresses for malicious indicators and deceptive markers.",
            parse_mode=ParseMode.HTML,
        )
    elif data == "act_audit_help":
        await callback.message.answer(
            "🧠 <b>Contextual AI Security Audit</b>\n\n"
            "Send: <code>/audit &lt;text here&gt;</code>\n"
            "Runs a deep security evaluation on messages, emails, or snippets to detect social engineering, "
            "credential harvesting, and calculate risk scores (0–100).",
            parse_mode=ParseMode.HTML,
        )
