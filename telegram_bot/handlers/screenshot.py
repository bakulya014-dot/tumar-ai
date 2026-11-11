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

from i18n import translate

from services.image_scanner import ImageScanResult, ImageValidationError, scan_image
from services.image_scanner.validator import max_bytes
from telegram_bot.handlers.commands import message_language, quota_allows

logger = logging.getLogger(__name__)

screenshot_router = Router(name="screenshot_router")

# OCR is CPU-bound; two at a time keeps a small host responsive.
_SCAN_SLOTS = asyncio.Semaphore(2)

_LEVELS = ("low", "moderate", "high", "critical", "inconclusive")
_CATEGORIES = (
    "phishing", "financial_fraud", "credential_theft", "identity_impersonation", "delivery_scam",
    "investment_scam", "social_engineering", "otp_harvesting", "fake_payment_request",
    "suspicious_authentication",
)
# Advice lines per level, as keys under bot.shot.advice.<level>.<n>.
_ADVICE_COUNT = {"critical": 3, "high": 2, "moderate": 2, "low": 1, "inconclusive": 2}
_VALIDATION_CODES = frozenset({
    "empty_image", "image_too_large", "unsupported_image", "image_dimensions",
    "image_too_small", "image_corrupted",
})


def _level_badge(level: str, language: str) -> str:
    level = level if level in _LEVELS else "inconclusive"
    return translate(f"bot.shot.level.{level}", language)


def _level_advice(level: str, language: str) -> list[str]:
    level = level if level in _ADVICE_COUNT else "inconclusive"
    return [translate(f"bot.shot.advice.{level}.{n}", language) for n in range(1, _ADVICE_COUNT[level] + 1)]


def _url_reason(code: str, language: str) -> str:
    """The website's wording for a link-warning code, or the code itself."""
    key = f"scam.url_reason.{code.removeprefix('url_')}"
    text = translate(key, language)
    return code.replace("_", " ") if text == key else text


def _validation_message(code: str, language: str = "en") -> str:
    if code not in _VALIDATION_CODES:
        return translate("bot.shot.invalid.default", language)
    # Unused placeholders are ignored, so every message can be given the limit.
    return translate(f"bot.shot.invalid.{code}", language, mb=max_bytes() // (1024 * 1024))


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


def format_scan_report(result: ImageScanResult, language: str = "en") -> str:
    """The bot's reply for one finished scan, as Telegram HTML."""
    tr = lambda key, **kw: translate(key, language, **kw)  # noqa: E731
    level = result.risk.level
    lines = [tr("bot.shot.title"), ""]

    score = "" if level == "inconclusive" else f" (<code>{result.risk.score}/100</code>)"
    lines.append(tr("bot.shot.risk", badge=_level_badge(level, language), score=score))

    categories = [
        tr(f"image.category.{c}") for c in result.classification.categories if c in _CATEGORIES
    ]
    if categories:
        lines.append(tr("bot.shot.signals", categories=html.escape(", ".join(categories))))
    if result.classification.injection_phrases:
        lines.append(tr("bot.shot.injection"))

    findings = result.urls.findings
    if findings:
        lines += ["", tr("bot.shot.links_title")]
        for finding in findings[:5]:
            source = tr("bot.shot.source_qr") if finding.origin == "qr" else tr("bot.shot.source_text")
            if finding.invalid:
                verdict = tr("bot.shot.link_malformed")
            elif finding.suspicious:
                reasons = ", ".join(_url_reason(r, language) for r in finding.reasons[:3])
                verdict = tr("bot.shot.link_suspicious_with", reasons=reasons) if reasons else tr("bot.shot.link_suspicious")
            else:
                verdict = tr("bot.shot.link_clean")
            lines.append(
                tr(
                    "bot.shot.link_line",
                    url=html.escape(_shorten(defang(finding.url), 120)),
                    verdict=html.escape(verdict),
                    source=html.escape(source),
                )
            )
        if len(findings) > 5:
            lines.append(tr("bot.shot.more_links", count=len(findings) - 5))

    other_qr = [code for code in result.qr.codes if not code.is_link]
    if other_qr:
        kinds = ", ".join(sorted({code.kind for code in other_qr}))
        lines.append(tr("bot.shot.other_qr", count=len(other_qr), kinds=html.escape(kinds)))

    ai = result.ai
    if ai is not None and ai.explanation:
        lines += ["", tr("bot.shot.assessment"), html.escape(_shorten(ai.explanation, 700))]

    if result.text:
        lines += ["", tr("bot.shot.text_title"), f"<i>{html.escape(_shorten(result.text, 300))}</i>"]
    elif not result.anything_read:
        lines += ["", tr("bot.shot.nothing_read")]

    advice = list(ai.recommended_actions[:3]) if ai is not None and ai.recommended_actions else []
    if not advice:
        advice = _level_advice(level, language)
    lines += ["", tr("bot.shot.what_to_do")]
    lines += [f"• {html.escape(item)}" for item in advice]

    if result.ocr.status in ("unavailable", "failed"):
        lines += ["", f"<i>{html.escape(tr(f'bot.shot.ocr_{result.ocr.status}'))}</i>"]
    lines += ["", tr("bot.shot.checked", seconds=f"{result.elapsed_ms / 1000:.1f}")]
    return "\n".join(lines)


def run_scan(data: bytes, language: str = "en") -> str:
    """Scan image bytes and return the reply text (blocking; run in a thread)."""
    try:
        result = scan_image(data, api_key=os.getenv("GEMINI_API_KEY", "").strip(), language=language)
    except ImageValidationError as exc:
        reason = html.escape(_validation_message(exc.code, language))
        return translate("bot.shot.cant_check", language, reason=reason)
    return format_scan_report(result, language)


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
    language = message_language(message)
    found = _image_file(source)
    if found is None:
        await message.answer(translate("bot.shot.usage", language), parse_mode=ParseMode.HTML)
        return

    if not await quota_allows(message, "image"):
        return

    file_id, size = found
    if size and size > max_bytes():
        reason = html.escape(_validation_message("image_too_large", language))
        await message.answer(translate("bot.shot.cant_check", language, reason=reason), parse_mode=ParseMode.HTML)
        return

    status = await message.answer(translate("bot.shot.progress", language), parse_mode=ParseMode.HTML)
    try:
        buffer = io.BytesIO()
        await bot.download(file_id, destination=buffer)
        async with _SCAN_SLOTS:
            report = await asyncio.to_thread(run_scan, buffer.getvalue(), language)
        await status.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as exc:  # never leave the user with a spinner
        logger.exception("Screenshot scan failed: %s", exc)
        await status.edit_text(translate("bot.shot.failed", language), parse_mode=ParseMode.HTML)


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
