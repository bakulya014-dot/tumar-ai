"""Groups, broadcasts and the daily dispatch — moved from the legacy bot.py (since removed).

Behaviour is unchanged from the legacy bot so that switching the
Procfile to telegram_bot.main loses nothing:

- Groups and channels that add the bot are registered, and removed
  when the bot leaves. The registry is the same SQLite file the legacy
  bot used (telegram_bot/broadcast.db), so existing registrations
  carry over.
- /broadcast <message> sends an alert to every registered chat; only
  the admin (TELEGRAM_ADMIN_ID) may use it.
- send_daily_broadcast() posts one curated safety tip to every
  registered chat; telegram_bot.main schedules it daily at 09:00
  Asia/Almaty. It is labelled as a curated tip, not news: live news
  is /news, which runs the news pipeline on request. The legacy bot's
  hard-coded "news" items (e.g. a "Zero-Day Alert") were not real
  current events and are gone.
- Plain text in a private chat gets a hint about the commands. Groups
  get no reply, so the bot never talks over a conversation.

This router is registered last: its text handler must not take
messages that a command handler should get.
"""

import asyncio
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from aiogram import Bot, F, Router
from aiogram.enums import ChatMemberStatus, ChatType, ParseMode
from aiogram.exceptions import TelegramForbiddenError, TelegramRetryAfter
from aiogram.filters import Command
from aiogram.types import ChatMemberUpdated, Message

from i18n import language_from_locale, translate
from services import telemetry
from telegram_bot.handlers.commands import opsec_tips

logger = logging.getLogger(__name__)

community_router = Router(name="community_router")

# The registry must live on a persistent disk in production: hosts with
# ephemeral storage wipe it on every deploy, and the daily dispatch then
# silently reaches nobody. TUMAR_BROADCAST_DB points it there.
DB_PATH = Path(
    os.getenv("TUMAR_BROADCAST_DB", "").strip()
    or Path(__file__).resolve().parent.parent / "broadcast.db"
)
TIMEZONE = ZoneInfo("Asia/Almaty")


class TargetRegistry:
    """Chats that receive broadcasts (same schema as the legacy bot)."""

    def __init__(self, path: Path | str = DB_PATH):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        with self.conn:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS channels ("
                "chat_id INTEGER PRIMARY KEY, title TEXT, chat_type TEXT)"
            )

    def add(self, chat_id: int, title: str, chat_type: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO channels VALUES (?, ?, ?)",
                (chat_id, title, chat_type),
            )

    def remove(self, chat_id: int) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM channels WHERE chat_id = ?", (chat_id,))

    def get_all(self) -> set[int]:
        return {row[0] for row in self.conn.execute("SELECT chat_id FROM channels")}


_registry: TargetRegistry | None = None


def registry() -> TargetRegistry:
    """The shared registry, opened on first use (not at import)."""
    global _registry
    if _registry is None:
        _registry = TargetRegistry()
    return _registry


def admin_user_id() -> int:
    try:
        return int(os.getenv("TELEGRAM_ADMIN_ID", "0"))
    except ValueError:
        return 0



@dataclass
class Delivery:
    """What happened to one broadcast. Chat ids are not logged."""

    sent: int = 0
    failed: int = 0
    removed: int = 0  # chats that blocked or removed the bot, deregistered


async def _send_one(bot: Bot, chat_id: int, text: str) -> None:
    try:
        await bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)
    except TelegramRetryAfter as exc:  # flood control: wait as told, retry once
        await asyncio.sleep(exc.retry_after)
        await bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)


async def _send_to_all(bot: Bot, text: str, targets: set[int], kind: str = "admin") -> Delivery:
    result = Delivery()
    for chat_id in targets:
        try:
            await _send_one(bot, chat_id, text)
            result.sent += 1
            await asyncio.sleep(0.05)  # stay well under Telegram's flood limits
        except TelegramForbiddenError:
            # Kicked or blocked: it will never succeed, so stop trying.
            registry().remove(chat_id)
            result.removed += 1
        except Exception as exc:  # one chat must not stop the rest
            result.failed += 1
            logger.warning("Broadcast delivery failed: %s", type(exc).__name__)
    logger.info(
        "Broadcast (%s): sent=%d failed=%d removed=%d", kind, result.sent, result.failed, result.removed
    )
    telemetry.emit(
        "broadcast", kind=kind, sent=result.sent, failed=result.failed, removed=result.removed
    )
    return result


def broadcast_language() -> str:
    """Groups have no single user locale; TUMAR_BROADCAST_LANGUAGE picks one."""
    return language_from_locale(os.getenv("TUMAR_BROADCAST_LANGUAGE", "en"))


def daily_tip_text(language: str, day: datetime | None = None) -> str:
    """Today's curated tip. Rotates by date, so no tip repeats on consecutive days."""
    day = day or datetime.now(TIMEZONE)
    tips = opsec_tips(language)
    title, advice = tips[day.toordinal() % len(tips)]
    return (
        f"{translate('bot.daily.header', language)}\n\n"
        f"{title}\n{advice}\n\n"
        f"{translate('bot.daily.footer', language)}"
    )


async def send_daily_broadcast(bot: Bot, targets: set[int] | None = None) -> int:
    """Post today's curated tip to every registered chat. Returns how many got it."""
    targets = registry().get_all() if targets is None else targets
    if not targets:
        logger.info("Daily dispatch: no registered chats")
        return 0
    text = daily_tip_text(broadcast_language())
    return (await _send_to_all(bot, text, targets, kind="daily")).sent


@community_router.message(Command("broadcast"))
async def cmd_broadcast(message: Message, bot: Bot) -> None:
    admin = admin_user_id()
    if not admin or message.from_user is None or message.from_user.id != admin:
        await message.answer("⛔ Admin access only.")
        return

    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("⚠️ <b>Usage:</b> <code>/broadcast message</code>", parse_mode=ParseMode.HTML)
        return

    result = await _send_to_all(bot, f"🚨 <b>TUMAR ALERT:</b>\n\n{parts[1]}", registry().get_all())
    await message.answer(
        f"✅ Dispatched to {result.sent} active channels/groups."
        f" Failed: {result.failed}. Removed (bot blocked or kicked): {result.removed}."
    )


@community_router.my_chat_member()
async def on_group_join_or_leave(event: ChatMemberUpdated) -> None:
    chat = event.chat
    status = event.new_chat_member.status
    if status in (ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR):
        registry().add(chat.id, chat.title or "Group", chat.type)
    elif status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED):
        registry().remove(chat.id)


@community_router.message(F.chat.type == ChatType.PRIVATE, F.text)
async def private_text_hint(message: Message) -> None:
    if (message.text or "").startswith("/"):
        return
    language = language_from_locale(message.from_user.language_code if message.from_user else None)
    await message.answer(translate("bot.private_hint", language), parse_mode=ParseMode.HTML)
