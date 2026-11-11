"""Groups, broadcasts and the daily dispatch — moved from the legacy bot.py (since removed).

Behaviour is unchanged from the legacy bot so that switching the
Procfile to telegram_bot.main loses nothing:

- Groups and channels that add the bot are registered, and removed
  when the bot leaves. The registry is the same SQLite file the legacy
  bot used (telegram_bot/broadcast.db), so existing registrations
  carry over.
- /broadcast <message> sends an alert to every registered chat; only
  the admin (TELEGRAM_ADMIN_ID) may use it.
- send_daily_broadcast() posts one curated update to every registered
  chat; telegram_bot.main schedules it daily at 09:00, server time.
- Plain text in a private chat gets a hint about the commands. Groups
  get no reply, so the bot never talks over a conversation.

This router is registered last: its text handler must not take
messages that a command handler should get.
"""

import asyncio
import logging
import os
import random
import sqlite3
from pathlib import Path

from aiogram import Bot, F, Router
from aiogram.enums import ChatMemberStatus, ChatType, ParseMode
from aiogram.filters import Command
from aiogram.types import ChatMemberUpdated, Message

logger = logging.getLogger(__name__)

community_router = Router(name="community_router")

DB_PATH = Path(__file__).resolve().parent.parent / "broadcast.db"


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


# Curated Tech & Cyber Industry Updates Pool (unchanged from the legacy bot)
TECH_NEWS_FEED = [
    "🌐 <b>Tech & Cyber Morning Digest</b>\n\n• <b>Zero-Day Alert:</b> Critical vulnerabilities patched in major Chromium-based browsers. Update your apps today.\n• <b>Defense Tip:</b> Review third-party OAuth app authorizations in your Google and Telegram accounts.",
    "🚀 <b>Tech Industry Update</b>\n\n• <b>AI Infrastructure:</b> Advancements in local LLM deployments allow smaller edge devices to run inference with reduced latency.\n• <b>Security Note:</b> Never approve unexpected two-factor push prompts on your phone.",
    "🛡️ <b>Tumar Cyber Intelligence Brief</b>\n\n• <b>Supply Chain Security:</b> Malicious packages identified in public repositories. Developers should pin dependency hashes.\n• <b>Best Practice:</b> Enable hardware-backed security keys or authenticators where available.",
]


async def _send_to_all(bot: Bot, text: str, targets: set[int]) -> int:
    sent = 0
    for chat_id in targets:
        try:
            await bot.send_message(chat_id=chat_id, text=text, parse_mode=ParseMode.HTML)
            sent += 1
            await asyncio.sleep(0.05)  # stay well under Telegram's flood limits
        except Exception as exc:  # a chat that blocked the bot must not stop the rest
            logger.info("Broadcast to %s failed: %s", chat_id, exc)
    return sent


async def send_daily_broadcast(bot: Bot, targets: set[int] | None = None) -> int:
    """Post one curated update to every registered chat. Returns how many got it."""
    targets = registry().get_all() if targets is None else targets
    if not targets:
        return 0
    text = (
        "📢 <b>AUTOMATED TUMAR.AI TECH DISPATCH</b>\n\n"
        f"{random.choice(TECH_NEWS_FEED)}\n\n"
        "🛡️ <i>Delivered automatically • Tumar 24/7 Shield</i>"
    )
    return await _send_to_all(bot, text, targets)


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

    sent = await _send_to_all(bot, f"🚨 <b>TUMAR ALERT:</b>\n\n{parts[1]}", registry().get_all())
    await message.answer(f"✅ Dispatched to {sent} active channels/groups.")


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
    await message.answer(
        "Message received. Analyze it using <code>/audit text</code> for messages "
        "or <code>/scan link</code> for links — or just send a screenshot.",
        parse_mode=ParseMode.HTML,
    )
