"""Tumar.AI Telegram bot (router-based entry point).

Run from the project root:
    python -m telegram_bot.main

BOT_TOKEN is read from the environment (or a .env file). It must never
be written into source: a token in a file is one `git add` away from
being public, and anyone holding it controls the bot.
"""

import asyncio
import logging
import os
import sys

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from dotenv import load_dotenv

from telegram_bot.handlers import commands_router, screenshot_router
from telegram_bot.middlewares.anti_spam import AntiSpamMiddleware

load_dotenv(override=False)  # a variable already set in the shell wins
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        stream=sys.stdout,
    )
    if not BOT_TOKEN:
        logging.error("BOT_TOKEN is not set. Export it or add it to .env, then restart.")
        sys.exit(1)

    # Initialize Bot with DefaultBotProperties (Required for aiogram >= 3.7.0)
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    dp = Dispatcher()

    # Register anti-spam on outer scope so blocked floods stop before handler execution
    dp.message.outer_middleware(AntiSpamMiddleware(rate_limit_seconds=1.25))

    # Register routers
    dp.include_router(commands_router)
    dp.include_router(screenshot_router)

    logging.info("Starting Tumar.AI Bot...")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())


    