"""Tumar.AI Telegram bot.

A minimal aiogram 3.x bot: it greets users on /start, receives text
messages, and acknowledges them. The scam-analysis service will be
plugged in here in a later step — by design it will reuse the
UI-independent services/ layer of the web app unchanged.

Secrets: the bot token lives in the project-root .env file (which is
gitignored) under BOT_TOKEN, loaded with python-dotenv.
"""

import asyncio
import os
import sys
from pathlib import Path

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import Message
from dotenv import load_dotenv

# Project root = one level above this file; .env lives there.
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

WELCOME_TEXT = (
    "🛡 Welcome to Tumar.AI!\n"
    "\n"
    "Forward me any suspicious message and I'll analyze it."
)
RECEIVED_TEXT = "✅ Message received. Analysis module will be connected next."

# The dispatcher routes incoming Telegram updates to the handlers below.
dispatcher = Dispatcher()


@dispatcher.message(CommandStart())
async def handle_start(message: Message) -> None:
    """Reply to /start with a short welcome and usage hint."""
    await message.answer(WELCOME_TEXT)


@dispatcher.message(F.text)
async def handle_text(message: Message) -> None:
    """Acknowledge any other text message.

    Registered after the /start handler, so commands win first.
    The real scam analysis will replace this acknowledgement later.
    """
    await message.answer(RECEIVED_TEXT)


def load_token() -> str:
    """Read BOT_TOKEN from the project .env file; exit if missing."""
    load_dotenv(ENV_FILE)
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        print(
            "ERROR: BOT_TOKEN is not set.\n"
            f"Open {ENV_FILE} and paste your Telegram bot token after "
            "'BOT_TOKEN=' (get a token from @BotFather in Telegram).",
            file=sys.stderr,
        )
        sys.exit(1)
    return token


async def main() -> None:
    """Start the bot and poll Telegram for updates until Ctrl+C."""
    bot = Bot(token=load_token())
    print("Tumar.AI bot is running — press Ctrl+C to stop.")
    await dispatcher.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot stopped.")


# ----------------------------------------------------------------------
# How to run the bot
# ----------------------------------------------------------------------
# 1. Install the dependencies into the project venv
#    (run from the tumar-ai folder):
#
#        venv\Scripts\python.exe -m pip install aiogram python-dotenv
#
# 2. Create your bot and get a token: open Telegram, message @BotFather,
#    send /newbot, follow its prompts, and copy the token it gives you.
#
# 3. Put the token into the .env file in the project root (gitignored,
#    never committed):
#
#        BOT_TOKEN=1234567890:AA...your-token...
#
# 4. Start the bot (from the tumar-ai folder):
#
#        venv\Scripts\python.exe telegram_bot\bot.py
#
# 5. Open your bot in Telegram and send /start. Stop it with Ctrl+C.
# ----------------------------------------------------------------------
