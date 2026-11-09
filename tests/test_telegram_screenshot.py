"""Offline tests for the Telegram bot's screenshot scanning.

No network and no bot token: images are generated in memory, Telegram
objects are built locally, and the bot's download/answer calls are
mocks. The scanner itself runs for real (QR decoding, link checks,
risk scoring); OCR is used only if Tesseract happens to be installed.

    venv\\Scripts\\python.exe tests\\test_telegram_screenshot.py
"""

import asyncio
import io
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cv2
from aiogram.types import Message
from PIL import Image

from telegram_bot.handlers import screenshot
from telegram_bot.handlers.screenshot import (
    _scan_and_reply,
    defang,
    run_scan,
    screenshot_router,
)

_PROVIDER_VARS = (
    "TUMAR_TEXT_PROVIDER", "TUMAR_VISION_PROVIDER", "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "KIMI_API_KEY",
)


def _offline() -> dict[str, str | None]:
    return {name: os.environ.pop(name, None) for name in _PROVIDER_VARS}


def _restore(saved: dict[str, str | None]) -> None:
    for name, value in saved.items():
        if value is not None:
            os.environ[name] = value


def _qr_png(payload: str, size: int = 400) -> bytes:
    code = cv2.QRCodeEncoder.create().encode(payload)
    code = cv2.resize(code, (size, size), interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", code)
    assert ok
    return encoded.tobytes()


def _blank_png() -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (300, 300), "white").save(out, "PNG")
    return out.getvalue()


def _message(chat_type: str = "private", *, photo: bool = True, caption: str | None = None,
             text: str | None = None, document_mime: str | None = None,
             file_size: int = 1000, reply_to: dict | None = None) -> Message:
    data: dict = {
        "message_id": 1,
        "date": datetime.now(timezone.utc),
        "chat": {"id": 42, "type": chat_type},
        "from": {"id": 7, "is_bot": False, "first_name": "Test"},
    }
    if photo:
        data["photo"] = [
            {"file_id": "small", "file_unique_id": "s", "width": 90, "height": 90, "file_size": 100},
            {"file_id": "large", "file_unique_id": "l", "width": 800, "height": 800, "file_size": file_size},
        ]
    if document_mime:
        data["document"] = {"file_id": "doc", "file_unique_id": "d", "mime_type": document_mime,
                            "file_size": file_size}
    if caption is not None:
        data["caption"] = caption
    if text is not None:
        data["text"] = text
    if reply_to is not None:
        data["reply_to_message"] = reply_to
    return Message.model_validate(data)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# --- report -----------------------------------------------------------


def test_malicious_qr_is_flagged_and_link_is_defanged() -> None:
    saved = _offline()
    try:
        report = run_scan(_qr_png("http://kaspi-bonus.site/verify"))
    finally:
        _restore(saved)
    assert "HIGH RISK" in report or "CRITICAL RISK" in report, report
    assert "hxxp://kaspi-bonus[.]site/verify" in report, report
    assert "http://kaspi-bonus.site" not in report, "live link must never be shown"
    assert "from QR code" in report and "Phishing" in report
    assert "not stored" in report
    print("test_malicious_qr_is_flagged_and_link_is_defanged PASSED")


def test_blank_image_is_inconclusive_with_next_steps() -> None:
    saved = _offline()
    try:
        report = run_scan(_blank_png())
    finally:
        _restore(saved)
    assert "INCONCLUSIVE" in report and "/100" not in report, report
    assert "couldn't read any text or QR code" in report
    assert "/audit" in report and "/scan" in report
    print("test_blank_image_is_inconclusive_with_next_steps PASSED")


def test_rejected_uploads_get_a_plain_reason() -> None:
    assert "PNG, JPEG or WebP" in run_scan(b"%PDF-1.7 not an image")
    assert "empty" in run_scan(b"")
    os.environ["TUMAR_IMAGE_MAX_BYTES"] = "100"
    try:
        assert "larger than" in run_scan(_blank_png())
    finally:
        os.environ.pop("TUMAR_IMAGE_MAX_BYTES")
    print("test_rejected_uploads_get_a_plain_reason PASSED")


def test_payloads_are_html_escaped() -> None:
    saved = _offline()
    try:
        report = run_scan(_qr_png("http://evil.example/<b>x</b>"))
    finally:
        _restore(saved)
    assert "<b>x</b>" not in report, report
    print("test_payloads_are_html_escaped PASSED")


def test_reply_fits_one_telegram_message() -> None:
    saved = _offline()
    try:
        report = run_scan(_qr_png("http://kaspi-bonus.site/" + "a" * 1500, size=600))
    finally:
        _restore(saved)
    assert len(report) < 4096, len(report)
    print("test_reply_fits_one_telegram_message PASSED")


def test_defang() -> None:
    assert defang("https://a.b.com/x.html") == "hxxps://a[.]b[.]com/x[.]html"
    assert defang("evil.kz") == "evil[.]kz"
    print("test_defang PASSED")


# --- handler flow -----------------------------------------------------


def test_photo_is_downloaded_scanned_and_answered() -> None:
    saved = _offline()
    payload = _qr_png("http://kaspi-bonus.site/verify")

    async def fake_download(file_id, destination):
        assert file_id == "large", "the largest photo size must be scanned"
        destination.write(payload)
        return destination

    bot = MagicMock()
    bot.download = AsyncMock(side_effect=fake_download)
    status = MagicMock()
    status.edit_text = AsyncMock()
    msg = _message()
    answer = AsyncMock(return_value=status)
    try:
        object.__setattr__(msg, "answer", answer)
        _run(_scan_and_reply(msg, msg, bot))
    finally:
        _restore(saved)
    assert bot.download.await_count == 1
    final = status.edit_text.await_args.args[0]
    assert "hxxp://kaspi-bonus[.]site/verify" in final
    print("test_photo_is_downloaded_scanned_and_answered PASSED")


def test_oversized_file_is_refused_before_download() -> None:
    bot = MagicMock()
    bot.download = AsyncMock()
    msg = _message(file_size=50 * 1024 * 1024)
    answer = AsyncMock()
    object.__setattr__(msg, "answer", answer)
    _run(_scan_and_reply(msg, msg, bot))
    assert bot.download.await_count == 0
    assert "larger than" in answer.await_args.args[0]
    print("test_oversized_file_is_refused_before_download PASSED")


def test_command_without_an_image_explains_usage() -> None:
    bot = MagicMock()
    bot.download = AsyncMock()
    msg = _message("group", photo=False, text="/screenshot")
    answer = AsyncMock()
    object.__setattr__(msg, "answer", answer)
    _run(_scan_and_reply(msg, msg, bot))
    assert bot.download.await_count == 0
    assert "reply to one" in answer.await_args.args[0]
    print("test_command_without_an_image_explains_usage PASSED")


# --- routing ----------------------------------------------------------


def _matches(message: Message) -> list[str]:
    """Names of screenshot handlers whose filters accept `message`."""
    bot = MagicMock()
    bot.me = AsyncMock(return_value=MagicMock(username="tumar_bot"))
    names = []
    for handler in screenshot_router.message.handlers:
        ok, _ = _run(handler.check(message, bot=bot))
        if ok:
            names.append(handler.callback.__name__)
    return names


def test_routing_private_vs_group() -> None:
    assert "private_screenshot" in _matches(_message("private"))
    assert "private_screenshot" in _matches(_message("private", photo=False, document_mime="image/png"))
    assert _matches(_message("private", photo=False, document_mime="application/pdf")) == []
    # Groups: never every picture, only on request.
    assert _matches(_message("group")) == []
    assert _matches(_message("supergroup")) == []
    assert "cmd_screenshot" in _matches(_message("group", caption="/screenshot"))
    reply = _message("group", photo=False, text="/screenshot",
                     reply_to=_message("group").model_dump(by_alias=True, exclude_none=True))
    assert "cmd_screenshot" in _matches(reply)
    print("test_routing_private_vs_group PASSED")


def test_reply_command_scans_the_replied_photo() -> None:
    seen = {}

    async def fake_scan(message, source, bot):
        seen["source"] = source

    original = screenshot._scan_and_reply
    screenshot._scan_and_reply = fake_scan
    try:
        reply = _message("group", photo=False, text="/screenshot",
                         reply_to=_message("group").model_dump(by_alias=True, exclude_none=True))
        _run(screenshot.cmd_screenshot(reply, MagicMock()))
    finally:
        screenshot._scan_and_reply = original
    assert seen["source"].photo, "the replied-to photo must be scanned"
    print("test_reply_command_scans_the_replied_photo PASSED")


if __name__ == "__main__":
    test_malicious_qr_is_flagged_and_link_is_defanged()
    test_blank_image_is_inconclusive_with_next_steps()
    test_rejected_uploads_get_a_plain_reason()
    test_payloads_are_html_escaped()
    test_reply_fits_one_telegram_message()
    test_defang()
    test_photo_is_downloaded_scanned_and_answered()
    test_oversized_file_is_refused_before_download()
    test_command_without_an_image_explains_usage()
    test_routing_private_vs_group()
    test_reply_command_scans_the_replied_photo()
    print("All screenshot bot tests passed.")
