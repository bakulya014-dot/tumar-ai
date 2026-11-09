"""Screenshot scanning for the Telegram bot.

Runs the same Visual Threat Intelligence pipeline as the web app's
Screenshot Scanner (services.image_scanner): validation and
re-encoding, OCR in Kazakh/Russian/English, QR decoding, link checks,
scam-intent categories and the documented risk score.

When it runs:
- in a private chat, for any photo or image file the user sends;
- in any chat, for a photo whose caption starts with /screenshot, or
  for /screenshot sent as a reply to a photo.
Groups are opt-in so the bot never inspects every picture people post.

Nothing is stored: the image is held in memory for one scan only.
Links are shown defanged and are never opened.
"""

import asyncio
import html
import io
import logging
import os

from aiogram import Bot, F, Router
from aiogram.enums import ChatType, ParseMode
from aiogram.filters import Command
from aiogram.types import Message

from services.image_scanner import ImageScanResult, ImageValidationError, scan_image
from services.image_scanner.validator import max_bytes

logger = logging.getLogger(__name__)

screenshot_router = Router(name="screenshot_router")

# OCR is CPU-bound; two at a time keeps a small host responsive.
_SCAN_SLOTS = asyncio.Semaphore(2)

_LEVEL_BADGES = {
    "low": "🟢 <b>LOW RISK</b>",
    "moderate": "🟡 <b>MODERATE RISK</b>",
    "high": "🟠 <b>HIGH RISK</b>",
    "critical": "🔴 <b>CRITICAL RISK</b>",
    "inconclusive": "⚪ <b>INCONCLUSIVE</b>",
}

_CATEGORY_LABELS = {
    "phishing": "Phishing",
    "financial_fraud": "Financial fraud",
    "credential_theft": "Credential theft",
    "identity_impersonation": "Impersonation",
    "delivery_scam": "Delivery scam",
    "investment_scam": "Investment scam",
    "social_engineering": "Social engineering",
    "otp_harvesting": "One-time code harvesting",
    "fake_payment_request": "Fake payment request",
    "suspicious_authentication": "Suspicious sign-in request",
}

_LEVEL_ADVICE = {
    "critical": (
        "Do not open the links or scan the QR code.",
        "Never share one-time codes, card details or passwords.",
        "Block the sender and report the message.",
    ),
    "high": (
        "Do not open the links or scan the QR code.",
        "Contact the company or person through a channel you already trust.",
    ),
    "moderate": (
        "Treat it with caution and verify it through an official channel first.",
        "Do not enter codes or passwords from a link in this image.",
    ),
    "low": (
        "No warning signs were found. Stay alert if it asks for money, codes or passwords.",
    ),
    "inconclusive": (
        "Try sending the screenshot as a file (uncompressed) or a sharper capture.",
        "Or paste the text with /audit and any link with /scan.",
    ),
}

_OCR_NOTES = {
    "unavailable": "Text reading (OCR) is not installed on this server, so only QR codes were checked.",
    "failed": "Text reading (OCR) failed on this image.",
}


def _validation_message(code: str) -> str:
    limit_mb = max_bytes() // (1024 * 1024)
    return {
        "empty_image": "The file is empty.",
        "image_too_large": f"The image is larger than {limit_mb} MB. Send a smaller screenshot.",
        "unsupported_image": "That format isn't supported. Send a PNG, JPEG or WebP screenshot.",
        "image_dimensions": "The image has too many pixels to scan safely.",
        "image_too_small": "The image is too small to read.",
        "image_corrupted": "The file couldn't be opened as an image.",
    }.get(code, "The image couldn't be checked.")


def defang(url: str) -> str:
    """Make a link unclickable everywhere: hxxp scheme, [.] dots."""
    out = url.strip()
    lowered = out.lower()
    if lowered.startswith("http"):
        out = "hxxp" + out[4:]
    return out.replace(".", "[.]")


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def format_scan_report(result: ImageScanResult) -> str:
    """The bot's reply for one finished scan, as Telegram HTML."""
    level = result.risk.level
    lines = ["🖼️ <b>TUMAR SCREENSHOT SCAN</b>", ""]

    badge = _LEVEL_BADGES.get(level, _LEVEL_BADGES["inconclusive"])
    score = "" if level == "inconclusive" else f" (<code>{result.risk.score}/100</code>)"
    lines.append(f"⚖️ <b>Risk:</b> {badge}{score}")

    categories = [
        _CATEGORY_LABELS[c] for c in result.classification.categories if c in _CATEGORY_LABELS
    ]
    if categories:
        lines.append(f"🏷️ <b>Signals:</b> {html.escape(', '.join(categories))}")
    if result.classification.injection_phrases:
        lines.append("🧩 <b>Hidden instructions aimed at AI tools were found in the image.</b>")

    findings = result.urls.findings
    if findings:
        lines += ["", "🔗 <b>Links found</b> <i>(not opened)</i>:"]
        for finding in findings[:5]:
            source = "QR code" if finding.origin == "qr" else "text"
            if finding.invalid:
                verdict = "malformed link"
            elif finding.suspicious:
                reasons = ", ".join(r.replace("_", " ") for r in finding.reasons[:3])
                verdict = "suspicious" + (f": {reasons}" if reasons else "")
            else:
                verdict = "no warning signs"
            lines.append(
                f"• <code>{html.escape(_shorten(defang(finding.url), 120))}</code> — "
                f"{html.escape(verdict)} <i>(from {source})</i>"
            )
        if len(findings) > 5:
            lines.append(f"• …and {len(findings) - 5} more")

    other_qr = [code for code in result.qr.codes if not code.is_link]
    if other_qr:
        kinds = ", ".join(sorted({code.kind for code in other_qr}))
        lines.append(f"📱 <b>Other QR codes:</b> {len(other_qr)} ({html.escape(kinds)})")

    ai = result.ai
    if ai is not None and ai.explanation:
        lines += ["", "💡 <b>Assessment:</b>", html.escape(_shorten(ai.explanation, 700))]

    if result.text:
        lines += ["", "📝 <b>Text read from the image:</b>", f"<i>{html.escape(_shorten(result.text, 300))}</i>"]
    elif not result.anything_read:
        lines += ["", "I couldn't read any text or QR code in this image."]

    advice = list(ai.recommended_actions[:3]) if ai is not None and ai.recommended_actions else []
    if not advice:
        advice = list(_LEVEL_ADVICE.get(level, _LEVEL_ADVICE["inconclusive"]))
    lines += ["", "🛡️ <b>What to do:</b>"]
    lines += [f"• {html.escape(item)}" for item in advice]

    note = _OCR_NOTES.get(result.ocr.status)
    if note:
        lines += ["", f"<i>{html.escape(note)}</i>"]
    lines += ["", f"<i>Checked in {result.elapsed_ms / 1000:.1f} s. The image was not stored.</i>"]
    return "\n".join(lines)


def run_scan(data: bytes) -> str:
    """Scan image bytes and return the reply text (blocking; run in a thread)."""
    try:
        result = scan_image(data, api_key=os.getenv("GEMINI_API_KEY", "").strip(), language="en")
    except ImageValidationError as exc:
        return f"⚠️ <b>Can't check this image.</b> {html.escape(_validation_message(exc.code))}"
    return format_scan_report(result)


def _image_file(message: Message) -> tuple[str, int | None] | None:
    """The best file to scan in `message`: (file_id, size), or None."""
    if message.photo:
        largest = message.photo[-1]
        return largest.file_id, largest.file_size
    doc = message.document
    if doc and (doc.mime_type or "").startswith("image/"):
        return doc.file_id, doc.file_size
    return None


async def _scan_and_reply(message: Message, source: Message, bot: Bot) -> None:
    found = _image_file(source)
    if found is None:
        await message.answer(
            "⚠️ <b>Usage:</b> send a screenshot, or reply to one with <code>/screenshot</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    file_id, size = found
    if size and size > max_bytes():
        await message.answer(
            f"⚠️ <b>Can't check this image.</b> {html.escape(_validation_message('image_too_large'))}",
            parse_mode=ParseMode.HTML,
        )
        return

    status = await message.answer(
        "🖼️ <i>Reading the screenshot: text, QR codes and links…</i>",
        parse_mode=ParseMode.HTML,
    )
    try:
        buffer = io.BytesIO()
        await bot.download(file_id, destination=buffer)
        async with _SCAN_SLOTS:
            report = await asyncio.to_thread(run_scan, buffer.getvalue())
        await status.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as exc:  # never leave the user with a spinner
        logger.exception("Screenshot scan failed: %s", exc)
        await status.edit_text(
            "⚠️ <b>Scan Notice:</b> Unable to check this image right now. Please try again.",
            parse_mode=ParseMode.HTML,
        )


_IMAGE_DOCUMENT = F.document.mime_type.startswith("image/")


@screenshot_router.message(Command("screenshot"))
async def cmd_screenshot(message: Message, bot: Bot) -> None:
    """/screenshot as a photo caption, or as a reply to a photo (any chat).

    aiogram's Command filter reads captions too, so one handler covers both.
    """
    source = message if _image_file(message) else (message.reply_to_message or message)
    await _scan_and_reply(message, source, bot)


@screenshot_router.message(F.chat.type == ChatType.PRIVATE, F.photo | _IMAGE_DOCUMENT)
async def private_screenshot(message: Message, bot: Bot) -> None:
    """Any photo or image file in a private chat."""
    await _scan_and_reply(message, message, bot)
