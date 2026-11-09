import asyncio
import os
import random
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Set

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ChatMemberStatus, ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    ChatMemberUpdated,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from google import genai

# Load environment variables
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_USER_ID = int(os.getenv("TELEGRAM_ADMIN_ID", "0"))
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "").strip()
DB_PATH = Path(__file__).resolve().parent / "broadcast.db"

# Initialize Gemini Client if key exists
ai_client = genai.Client(api_key=GEMINI_KEY) if GEMINI_KEY else None

# Database to store all registered groups
class TargetRegistry:
    def __init__(self, path: Path = DB_PATH):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS channels (
                    chat_id INTEGER PRIMARY KEY,
                    title TEXT,
                    chat_type TEXT
                )
            """)

    def add(self, chat_id: int, title: str, chat_type: str):
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO channels VALUES (?, ?, ?)",
                (chat_id, title, chat_type),
            )

    def remove(self, chat_id: int):
        with self.conn:
            self.conn.execute("DELETE FROM channels WHERE chat_id = ?", (chat_id,))

    def get_all(self) -> Set[int]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT chat_id FROM channels")
        return {row[0] for row in cursor.fetchall()}

registry = TargetRegistry()
dp = Dispatcher()

# Curated Tech & Cyber Industry Updates Pool
TECH_NEWS_FEED = [
    "🌐 <b>Tech & Cyber Morning Digest</b>\n\n• <b>Zero-Day Alert:</b> Critical vulnerabilities patched in major Chromium-based browsers. Update your apps today.\n• <b>Defense Tip:</b> Review third-party OAuth app authorizations in your Google and Telegram accounts.",
    "🚀 <b>Tech Industry Update</b>\n\n• <b>AI Infrastructure:</b> Advancements in local LLM deployments allow smaller edge devices to run inference with reduced latency.\n• <b>Security Note:</b> Never approve unexpected two-factor push prompts on your phone.",
    "🛡️ <b>Tumar Cyber Intelligence Brief</b>\n\n• <b>Supply Chain Security:</b> Malicious packages identified in public repositories. Developers should pin dependency hashes.\n• <b>Best Practice:</b> Enable hardware-backed security keys or authenticators where available.",
]

# Automated Scheduled Task: Dispatches Daily at 09:00
async def send_daily_broadcast(bot: Bot) -> None:
    targets = registry.get_all()
    if not targets:
        return

    update_text = random.choice(TECH_NEWS_FEED)
    full_message = (
        f"📢 <b>AUTOMATED TUMAR.AI TECH DISPATCH</b>\n\n"
        f"{update_text}\n\n"
        f"🛡️ <i>Delivered automatically • Tumar 24/7 Shield</i>"
    )

    for chat_id in targets:
        try:
            await bot.send_message(chat_id=chat_id, text=full_message, parse_mode=ParseMode.HTML)
            await asyncio.sleep(0.05)
        except Exception:
            pass

# ---------------- Handlers ----------------

@dp.message(CommandStart())
async def cmd_start(message: Message) -> None:
    welcome = (
        "🛡️ <b>Welcome to Tumar.AI Defense Hub!</b>\n\n"
        "Commands:\n"
        "• <code>/scan text</code> - Fast security evaluation\n"
        "• <code>/audit text</code> - Deep AI threat analysis\n"
        "• <code>/tip</code> - Daily digital hygiene habit\n"
        "• <code>/broadcast msg</code> - Admin group bulletin"
    )
    await message.answer(welcome, parse_mode=ParseMode.HTML)

@dp.message(Command("audit"))
async def cmd_audit(message: Message) -> None:
    parts = message.text.split(maxsplit=1)
    content = parts[1] if len(parts) > 1 else None

    if not content and message.reply_to_message:
        content = message.reply_to_message.text or message.reply_to_message.caption

    if not content:
        await message.answer("⚠️ <b>Usage:</b> <code>/audit suspicious text here</code>", parse_mode=ParseMode.HTML)
        return

    if not ai_client:
        await message.answer("⚠️ <code>GEMINI_API_KEY</code> not found in .env.", parse_mode=ParseMode.HTML)
        return

    status = await message.answer("🧠 <i>Evaluating threat signals with Gemini AI...</i>", parse_mode=ParseMode.HTML)

    prompt = (
        "You are Tumar.AI, a cybersecurity threat evaluation engine. "
        "Analyze the following user input for scams, phishing, extortion, or threats. "
        "Format the response using simple HTML tags (<b>, <i>, <code>):\n\n"
        f"Text to evaluate:\n\"\"\"{content}\"\"\""
    )

    try:
        response = ai_client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        await status.edit_text(response.text or "Analysis completed.", parse_mode=ParseMode.HTML)
    except Exception as e:
        await status.edit_text(f"⚠️ Analysis error: <code>{e}</code>", parse_mode=ParseMode.HTML)

@dp.message(Command("scan"))
async def cmd_scan(message: Message) -> None:
    parts = message.text.split(maxsplit=1)
    query = parts[1] if len(parts) > 1 else None

    if not query and message.reply_to_message:
        query = message.reply_to_message.text

    if not query:
        await message.answer("⚠️ <b>Usage:</b> <code>/scan link or text</code>", parse_mode=ParseMode.HTML)
        return

    suspicious_terms = ["urgent", "verify", ".top", ".xyz", "password", "blocked", "steal", "bank", "hack"]
    is_threat = any(term in query.lower() for term in suspicious_terms)

    verdict = "🚨 <b>THREAT DETECTED</b>" if is_threat else "✅ <b>LIKELY SAFE</b>"
    await message.answer(
        f"🛡️ <b>Tumar Verdict:</b> {verdict}\n<b>Target:</b> <code>{query[:100]}</code>",
        parse_mode=ParseMode.HTML,
    )

@dp.message(Command("tip"))
async def cmd_tip(message: Message) -> None:
    tips = [
        "💡 <b>Tip:</b> Never share SMS one-time verification codes (OTP) with anyone.",
        "💡 <b>Tip:</b> Check top-level domains carefully; banks rarely operate on <code>.top</code> or <code>.xyz</code>.",
    ]
    await message.answer(random.choice(tips), parse_mode=ParseMode.HTML)

@dp.message(Command("broadcast"))
async def cmd_broadcast(message: Message, bot: Bot) -> None:
    if message.from_user.id != ADMIN_USER_ID:
        await message.answer("⛔ Admin access only.")
        return

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("⚠️ <b>Usage:</b> <code>/broadcast message</code>", parse_mode=ParseMode.HTML)
        return

    targets = registry.get_all()
    sent = 0
    for chat_id in targets:
        try:
            await bot.send_message(
                chat_id=chat_id,
                text=f"🚨 <b>TUMAR ALERT:</b>\n\n{parts[1]}",
                parse_mode=ParseMode.HTML,
            )
            sent += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass

    await message.answer(f"✅ Dispatched to {sent} active channels/groups.")

@dp.my_chat_member()
async def on_group_join_or_leave(event: ChatMemberUpdated) -> None:
    chat = event.chat
    status = event.new_chat_member.status
    if status in (ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR):
        registry.add(chat.id, chat.title or "Group", chat.type)
    elif status in (ChatMemberStatus.LEFT, ChatMemberStatus.KICKED):
        registry.remove(chat.id)

@dp.message(F.text)
async def fallback_text_handler(message: Message) -> None:
    if message.text.startswith("/"):
        return
    await message.answer("Message received. Analyze it using <code>/scan text</code> or <code>/audit text</code>.", parse_mode=ParseMode.HTML)

# ---------------- Runner ----------------

async def main() -> None:
    bot = Bot(token=BOT_TOKEN)

    # Initialize APScheduler for automated time-based posts
    scheduler = AsyncIOScheduler()
    # Runs automatically every day at 09:00 AM
    scheduler.add_job(send_daily_broadcast, "cron", hour=9, minute=0, args=[bot])
    scheduler.start()

    print("🛡️ Tumar.AI Multifunctional Bot online and scheduler active.")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
    