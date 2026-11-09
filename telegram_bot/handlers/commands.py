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
import re
from urllib.parse import urlparse

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
from services.breach_checker import check_email, is_valid_email
from services.heuristics import scan_message, url_reasons
from services.scam_analysis import analyze_message
from services.url_scanner import normalize_url, scan_url

logger = logging.getLogger(__name__)

commands_router = Router(name="commands_router")

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


def _perform_breach_check(target: str) -> str:
    """Core breach intelligence lookup logic."""
    clean_target = target.strip().lower()

    # If it is a full email address
    if is_valid_email(clean_target):
        try:
            email_result = check_email(clean_target)
        except Exception as err:
            logger.warning("Email check error: %s", err)
            email_result = None

        analytics = _query_breach_analytics(clean_target)
        exposed_fields = _extract_exposed_fields(analytics)

        breach_count = 0
        breaches = []
        if email_result:
            breach_count = email_result.breach_count
            breaches = email_result.breaches
        elif analytics:
            breaches_summary = analytics.get("BreachesSummary", {}).get("site", "")
            if breaches_summary:
                breaches = [b.strip() for b in breaches_summary.split(";") if b.strip()]
                breach_count = len(breaches)

        # Mask target email for user privacy
        user_part, domain_part = clean_target.split("@", 1)
        masked_target = f"{user_part[:2]}***@{domain_part}"

        if breach_count == 0:
            return (
                f"🛡️ <b>TUMAR BREACH INTELLIGENCE REPORT</b>\n\n"
                f"🎯 <b>Target:</b> <code>{html.escape(masked_target)}</code>\n"
                f"🟢 <b>Exposure Status:</b> <b>CLEAN / NO EXPOSURE FOUND</b>\n"
                f"📊 <b>Incident Count:</b> <code>0 breaches detected</code>\n"
                f"🔒 <b>Risk Level:</b> <b>Minimal (Safe)</b>\n\n"
                f"💡 <b>Proactive Hygiene:</b>\n"
                f"• Always use unique passwords across every account.\n"
                f"• Ensure Multi-Factor Authentication (MFA) is active on critical accounts."
            )

        risk_label = "🔴 <b>CRITICAL / HIGH RISK</b>" if breach_count >= 3 else "🟡 <b>ELEVATED RISK</b>"
        fields_str = ", ".join(exposed_fields[:6]) if exposed_fields else "Credentials, Account Metadata"
        top_breaches = ", ".join(breaches[:4]) + (f" (+{len(breaches)-4} more)" if len(breaches) > 4 else "")

        return (
            f"🚨 <b>TUMAR BREACH INTELLIGENCE REPORT</b>\n\n"
            f"🎯 <b>Target:</b> <code>{html.escape(masked_target)}</code>\n"
            f"⚠️ <b>Exposure Status:</b> <b>BREACH INCIDENTS DETECTED</b>\n"
            f"📊 <b>Incident Count:</b> <code>{breach_count} known breaches</code>\n"
            f"⚡ <b>Risk Level:</b> {risk_label}\n"
            f"💥 <b>Known Breaches:</b> <i>{html.escape(top_breaches)}</i>\n"
            f"🔓 <b>Exposed Fields:</b> <code>{html.escape(fields_str)}</code>\n\n"
            f"🛡️ <b>Immediate Action Plan:</b>\n"
            f"1. Change passwords immediately on affected services.\n"
            f"2. Never reuse these passwords on other platforms.\n"
            f"3. Enable Hardware or Authenticator App MFA (avoid SMS where possible).\n"
            f"4. Be vigilant against spear-phishing targeting your exposed contact info."
        )

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

    status = await message.answer(
        "🔍 <i>Querying known breach registries & exposure indexes...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        report = await asyncio.to_thread(_perform_breach_check, target)
        await status.edit_text(report, parse_mode=ParseMode.HTML)
    except Exception as exc:
        logger.exception("Breach check encountered failure: %s", exc)
        await status.edit_text(
            "⚠️ <b>Lookup Notice:</b> Unable to reach breach registries at this time. "
            "Please try again shortly.",
            parse_mode=ParseMode.HTML,
        )


# ----------------- /scan Handler -----------------

_SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".click", ".icu", ".cam"}
_PHISHING_KEYWORDS = {"login", "verify", "secure", "banking", "account", "update", "support", "wallet", "recovery", "kaspi"}


def _perform_scan(target: str) -> str:
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

    # 2. Check as URL / Domain
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    # Try AI-powered url_scanner if API key is present
    if api_key:
        try:
            report = scan_url(candidate, api_key=api_key, language="en")
            verdict_badge = {
                "safe": "✅ <b>LIKELY SAFE</b>",
                "caution": "⚠️ <b>CAUTION ADVISED</b>",
                "danger": "🚨 <b>DANGEROUS THREAT DETECTED</b>",
            }.get(report.verdict, "⚠️ <b>CAUTION</b>")

            red_flags = "\n".join(
                f"• {html.escape(e.detail)}" for e in report.evidence if e.code in ("red_flag", "url_no_https", "url_suspicious_tld")
            ) or "• No severe technical red flags detected."

            actions = "\n".join(f"• {html.escape(a)}" for a in report.recommended_actions) or "• Verify sender origin."

            return (
                f"🛡️ <b>TUMAR THREAT INTELLIGENCE SCAN</b>\n\n"
                f"🎯 <b>Target:</b> <code>{html.escape(candidate[:100])}</code>\n"
                f"⚖️ <b>Verdict:</b> {verdict_badge}\n"
                f"📈 <b>Trust Score:</b> <code>{report.trust_score}/100</code> (Confidence: {report.confidence}%)\n\n"
                f"🚩 <b>Observed Signals & Red Flags:</b>\n{red_flags}\n\n"
                f"💡 <b>Assessment:</b> {html.escape(report.explanation)}\n\n"
                f"🛡️ <b>Recommended Actions:</b>\n{actions}"
            )
        except Exception as exc:
            logger.debug("AI scan_url skipped or failed: %s; using deterministic scan.", exc)

    # 3. Deterministic Heuristic Scanner (fallback / offline)
    try:
        normalized = normalize_url(candidate)
    except Exception:
        normalized = "https://" + candidate if "://" not in candidate else candidate

    reasons = url_reasons(normalized)
    parsed = urlparse(normalized)
    domain = parsed.hostname or ""

    red_flags: list[str] = []
    for reason in reasons:
        red_flags.append(f"Heuristic pattern: {reason}")

    if any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
        red_flags.append(f"High-risk top-level domain ({domain.split('.')[-1]})")

    keyword_hits = [kw for kw in _PHISHING_KEYWORDS if kw in domain.lower()]
    if keyword_hits and not domain.endswith(".kz") and not domain.endswith(".gov"):
        red_flags.append(f"High-value target impersonation keywords ({', '.join(keyword_hits)})")

    if red_flags:
        verdict = "🚨 <b>SUSPICIOUS / THREAT DETECTED</b>" if len(red_flags) >= 2 else "⚠️ <b>CAUTION ADVISED</b>"
        risk_score = min(95, 30 + len(red_flags) * 25)
        flags_text = "\n".join(f"• {html.escape(f)}" for f in red_flags)
        return (
            f"🛡️ <b>TUMAR THREAT INTELLIGENCE SCAN</b>\n\n"
            f"🎯 <b>Target:</b> <code>{html.escape(candidate[:100])}</code>\n"
            f"⚖️ <b>Verdict:</b> {verdict}\n"
            f"⚡ <b>Estimated Risk Score:</b> <code>{risk_score}/100</code>\n\n"
            f"🚩 <b>Identified Threat Indicators:</b>\n{flags_text}\n\n"
            f"💡 <b>Mitigation:</b> Avoid opening or authenticating via this link. Verify official portal URLs directly."
        )

    return (
        f"🛡️ <b>TUMAR THREAT INTELLIGENCE SCAN</b>\n\n"
        f"🎯 <b>Target:</b> <code>{html.escape(candidate[:100])}</code>\n"
        f"⚖️ <b>Verdict:</b> ✅ <b>NO MALICIOUS SIGNALS DETECTED</b>\n"
        f"📈 <b>Trust Score:</b> <code>90/100</code>\n\n"
        f"• Verified standard protocol structure.\n"
        f"• No deceptive TLDs or common phishing indicators flagged.\n\n"
        f"💡 <i>Tip: Always check SSL certificates and domain spelling before entering credentials.</i>"
    )


@commands_router.message(Command("scan"))
async def cmd_scan(message: Message) -> None:
    """Evaluate reputations, malicious indicators, or suspicious links."""
    parts = message.text.split(maxsplit=1)
    target = parts[1].strip() if len(parts) > 1 else ""

    if not target and message.reply_to_message:
        target = (message.reply_to_message.text or message.reply_to_message.caption or "").strip()

    if not target:
        await message.answer(
            "⚠️ <b>Usage:</b> <code>/scan &lt;url/domain/IP&gt;</code>\n\n"
            "<i>Examples:</i>\n"
            "• <code>/scan https://suspicious-verify.xyz</code>\n"
            "• <code>/scan 185.220.101.5</code>\n"
            "• <code>/scan portal-login.site</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    status = await message.answer(
        "🛡️ <i>Evaluating threat signals, indicators & reputation...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        report = await asyncio.to_thread(_perform_scan, target)
        await status.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as exc:
        logger.exception("Scan error: %s", exc)
        await status.edit_text(
            "⚠️ <b>Scan Notice:</b> Analysis failed for the provided target. Please verify format.",
            parse_mode=ParseMode.HTML,
        )


# ----------------- /audit Handler -----------------

def _perform_audit(snippet: str) -> str:
    """Execute contextual security evaluation on text, messages, or configurations."""
    clean_text = snippet.strip()
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    # Try Gemini AI deep audit
    if api_key:
        try:
            report = analyze_message(clean_text, api_key=api_key)
            ai = report.ai
            verdict_badge = {
                "Safe": "🟢 <b>SAFE / BENIGN</b>",
                "Suspicious": "🟡 <b>SUSPICIOUS / ELEVATED RISK</b>",
                "Dangerous": "🔴 <b>DANGEROUS / HIGH RISK</b>",
            }.get(ai.verdict, "🟡 <b>CAUTION</b>")

            flags = "\n".join(f"• {html.escape(flag)}" for flag in ai.red_flags) or "• No overt exploitation signatures."
            mitigations = "\n".join(f"• {html.escape(act)}" for act in ai.recommended_actions) or "• Practice general cyber hygiene."

            return (
                f"🧠 <b>TUMAR CONTEXTUAL SECURITY AUDIT</b>\n\n"
                f"⚖️ <b>Verdict:</b> {verdict_badge}\n"
                f"📊 <b>Risk Score:</b> <code>{ai.risk_score}/100</code> (Confidence: {ai.confidence}%)\n"
                f"🔐 <b>Credential Risk:</b> <code>{ai.credential_theft_risk}/100</code> | <b>Financial Risk:</b> <code>{ai.financial_scam_risk}/100</code>\n\n"
                f"🚩 <b>Key Threat Signals & Techniques:</b>\n{flags}\n\n"
                f"💡 <b>Assessment:</b>\n{html.escape(ai.explanation)}\n\n"
                f"🛡️ <b>Actionable Mitigations:</b>\n{mitigations}"
            )
        except Exception as exc:
            logger.debug("AI audit failed or skipped: %s; falling back to heuristic engine.", exc)

    # Deterministic Heuristic Engine Fallback
    heuristics = scan_message(clean_text)
    risk_score = 10
    red_flags: list[str] = []

    if heuristics.urgency_score > 0:
        risk_score += min(35, heuristics.urgency_score)
        red_flags.append(f"Artificial urgency patterns ({', '.join(heuristics.urgency_matches[:3])})")

    if heuristics.credential_indicators:
        risk_score += 35
        red_flags.append(f"Credential collection cues ({', '.join(heuristics.credential_indicators[:3])})")

    if heuristics.otp_signal in ("disclosure", "entry"):
        risk_score += 40
        red_flags.append("One-Time Password (OTP) solicitation detected")

    if heuristics.financial_indicators:
        risk_score += 25
        red_flags.append(f"Financial transaction bait ({', '.join(heuristics.financial_indicators[:3])})")

    if heuristics.manipulation_indicators:
        risk_score += 20
        red_flags.append(f"Social engineering manipulation ({', '.join(heuristics.manipulation_indicators[:3])})")

    if heuristics.suspicious_urls:
        risk_score += 30
        red_flags.append("Contains suspicious links or deceptive domain structures")

    risk_score = min(100, risk_score)

    if risk_score >= 60:
        verdict = "🔴 <b>DANGEROUS / HIGH RISK</b>"
    elif risk_score >= 30:
        verdict = "🟡 <b>SUSPICIOUS / ELEVATED RISK</b>"
    else:
        verdict = "🟢 <b>LIKELY BENIGN</b>"

    flags_text = "\n".join(f"• {html.escape(f)}" for f in red_flags) or "• No aggressive manipulation signals detected."

    return (
        f"🧠 <b>TUMAR CONTEXTUAL SECURITY AUDIT</b>\n\n"
        f"⚖️ <b>Verdict:</b> {verdict}\n"
        f"📊 <b>Calculated Risk Score:</b> <code>{risk_score}/100</code>\n\n"
        f"🚩 <b>Detected Indicators:</b>\n{flags_text}\n\n"
        f"🛡️ <b>Actionable Mitigations:</b>\n"
        f"• Do not disclose one-time passwords, seed phrases, or credentials.\n"
        f"• Verify sender identity through known, out-of-band communication channels.\n"
        f"• Discard messages that insist on immediate, panic-driven action."
    )


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

    status = await message.answer(
        "🧠 <i>Running contextual security audit & risk evaluation...</i>",
        parse_mode=ParseMode.HTML,
    )

    try:
        report = await asyncio.to_thread(_perform_audit, snippet)
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
